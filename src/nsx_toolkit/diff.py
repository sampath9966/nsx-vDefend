"""Comparing two configuration snapshots.

Objects are matched by their NSX `path`: stable and unique, unlike
`display_name`, which people rename.

**List comparison is the subtle part**, and getting it wrong produces either
false changes nobody trusts or real changes nobody sees:

  * `source_groups`, `destination_groups`, `services`, `scope`, `profiles`
    compare as SETS. Membership is what matters and NSX may return them in any
    order, so a reordering is not a change.
  * `expression` compares as a SEQUENCE. Group criteria are
    `Condition AND Condition` -- order is meaning, and reordering them changes
    which workloads match.
  * Everything else compares in order. That is the safer default: a false
    "changed" costs a second look, a missed change costs an incident.

Changes are classified `security` or `cosmetic` so a scheduled drift check can
stay quiet about a renamed policy and be loud about a new any-any rule. Only
three fields are cosmetic; anything unrecognised counts as security-relevant,
for the same reason the list default is order-sensitive.
"""

from .api import F_DISPLAY_NAME
from .sinks import make_finding

# Membership matters; order does not.
SET_LIKE_FIELDS = frozenset({
    "source_groups", "destination_groups", "services", "scope", "profiles",
})

# The only fields whose change cannot alter what traffic is permitted.
COSMETIC_FIELDS = frozenset({"display_name", "description", "notes"})

DRIFT_LEVELS = ("security", "cosmetic")

DRIFT_HEADERS = ["status", "impact", "kind", "manager", "object", "field",
                 "before", "after", "changed_by", "changed_at"]


class FieldChange:
    __slots__ = ("field", "before", "after", "kind")

    def __init__(self, field, before, after, kind="changed"):
        self.field = field
        self.before = before
        self.after = after
        self.kind = kind

    @property
    def impact(self):
        """security or cosmetic, decided by the outermost field name."""
        root = self.field.split(".", 1)[0].split("[", 1)[0]
        return "cosmetic" if root in COSMETIC_FIELDS else "security"

    def __repr__(self):
        return "FieldChange({!r}, {!r} -> {!r})".format(
            self.field, self.before, self.after)


class ObjectChange:
    __slots__ = ("status", "path", "kind", "manager", "name", "fields",
                 "provenance")

    def __init__(self, status, path, kind, manager, name, fields=(),
                 provenance=None):
        self.status = status          # added | removed | modified
        self.path = path
        self.kind = kind
        self.manager = manager
        self.name = name
        self.fields = list(fields)
        self.provenance = provenance or {}

    @property
    def impact(self):
        """An added or removed object is always security-relevant: it changes
        what rules exist. A modified one inherits the worst of its fields."""
        if self.status in ("added", "removed"):
            return "security"
        return ("security" if any(f.impact == "security" for f in self.fields)
                else "cosmetic")

    @property
    def changed_by(self):
        return self.provenance.get("_last_modified_user", "")

    @property
    def changed_at(self):
        return self.provenance.get("_last_modified_time", "")


def fmt_diff_value(value):
    """One field value as a single line, for a table cell."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return "; ".join("{}={}".format(k, value[k]) for k in sorted(value))
    return str(value)


def _diff_set(field, before, after):
    """Membership comparison: report what joined and what left."""
    a, b = set(map(str, before)), set(map(str, after))
    if a == b:
        return []
    changes = []
    added, removed = sorted(b - a), sorted(a - b)
    if added:
        changes.append(FieldChange(field, None, added, "added"))
    if removed:
        changes.append(FieldChange(field, removed, None, "removed"))
    return changes


def _diff_sequence(field, before, after):
    """Order-sensitive comparison, recursing into nested objects."""
    changes = []
    for index in range(max(len(before), len(after))):
        item_field = "{}[{}]".format(field, index)
        if index >= len(before):
            changes.append(FieldChange(item_field, None, after[index], "added"))
        elif index >= len(after):
            changes.append(FieldChange(item_field, before[index], None,
                                       "removed"))
        else:
            changes.extend(_diff_value(item_field, None, before[index],
                                       after[index]))
    return changes


def _diff_value(field, key, before, after):
    if isinstance(before, dict) and isinstance(after, dict):
        return diff_objects(before, after, prefix=field)
    if isinstance(before, list) and isinstance(after, list):
        if key in SET_LIKE_FIELDS:
            return _diff_set(field, before, after)
        return _diff_sequence(field, before, after)
    if before != after:
        return [FieldChange(field, before, after, "changed")]
    return []


def diff_objects(before, after, prefix=""):
    """Field-level changes between two objects, recursing into nesting."""
    changes = []
    for key in sorted(set(before) | set(after)):
        field = "{}.{}".format(prefix, key) if prefix else key
        if key not in before:
            changes.append(FieldChange(field, None, after[key], "added"))
        elif key not in after:
            changes.append(FieldChange(field, before[key], None, "removed"))
        else:
            changes.extend(_diff_value(field, key, before[key], after[key]))
    return changes


def diff_snapshots(before, after):
    """Every object that differs between two snapshots.

    Unchanged objects are omitted: the caller gets counts from
    summarise_diff() and does not need a row per identical rule.
    """
    old_objects = before.get("objects") or {}
    new_objects = after.get("objects") or {}
    new_provenance = after.get("provenance") or {}
    old_provenance = before.get("provenance") or {}

    changes = []
    for path in sorted(set(old_objects) | set(new_objects)):
        old = old_objects.get(path)
        new = new_objects.get(path)
        entry = new or old
        name = (entry["body"].get(F_DISPLAY_NAME)
                or entry["body"].get("id") or path)

        if old is None:
            changes.append(ObjectChange(
                "added", path, entry["kind"], entry["manager"], name,
                provenance=new_provenance.get(path)))
        elif new is None:
            changes.append(ObjectChange(
                "removed", path, entry["kind"], entry["manager"], name,
                provenance=old_provenance.get(path)))
        else:
            fields = diff_objects(old["body"], new["body"])
            if fields:
                changes.append(ObjectChange(
                    "modified", path, entry["kind"], entry["manager"], name,
                    fields=fields, provenance=new_provenance.get(path)))

    # Security-relevant first, then by kind and name: the reader should meet
    # the dangerous change before the renamed policy.
    changes.sort(key=lambda c: (c.impact != "security", c.status, c.kind,
                                str(c.name)))
    return changes


def summarise_diff(changes):
    counts = {"added": 0, "removed": 0, "modified": 0,
              "security": 0, "cosmetic": 0}
    for change in changes:
        counts[change.status] = counts.get(change.status, 0) + 1
        counts[change.impact] = counts.get(change.impact, 0) + 1
    return counts


def diff_rows(changes):
    """Export rows: one per changed field, one per added/removed object."""
    rows = []
    for change in changes:
        if not change.fields:
            rows.append([change.status, change.impact, change.kind,
                         change.manager, change.name, "", "", "",
                         change.changed_by, str(change.changed_at)])
            continue
        for field in change.fields:
            rows.append([change.status, field.impact, change.kind,
                         change.manager, change.name, field.field,
                         fmt_diff_value(field.before), fmt_diff_value(field.after),
                         change.changed_by, str(change.changed_at)])
    return rows


def drift_findings(changes):
    """Object changes as machine-readable findings.

    Severity is the impact the diff engine already computed, so a scheduled
    drift check reports a new any-any rule as an error and a rename as a note
    without a second classification anybody could get out of step.
    """
    out = []
    for change in changes:
        fields = ", ".join(sorted({f.field for f in change.fields})) or \
            change.status
        out.append(make_finding(
            "drift_{}".format(change.status), change.impact,
            "{} {} {}".format(change.status, change.kind, change.name),
            where="{}/{}".format(change.manager, change.name),
            detail="{}  changed by {} {}".format(
                fields, change.changed_by or "unknown",
                change.changed_at or "")))
    return out


def at_impact(changes, level):
    """Changes at or above an impact level, for --fail-on-drift."""
    if level == "any":
        return list(changes)
    if level == "security":
        return [c for c in changes if c.impact == "security"]
    return []
