"""Configuration snapshots: capture NSX config as a git-friendly tree.

The whole feature turns on one thing. **NSX objects carry fields that change
without the configuration changing** -- `_revision` bumps on any write,
`_last_modified_time` moves, `realization_id` and `unique_id` are per-object
identifiers, federation adds `origin_site_id`. Snapshot those raw and every
diff is noise, the drift report becomes worthless, and people stop running it.

So capture splits each object in two:

  * a **body** with the volatile fields stripped -- this is what gets compared
  * a **sidecar** keeping `_last_modified_user` and `_last_modified_time`

Those two are stripped from the comparison because they move without the
config moving, but retained for reporting, because *who changed this and when*
is the most useful column a drift report has.

Layout on disk, one JSON file per object, sorted keys, trailing newline, so
`git diff` and `diff -r` work on it directly:

    <name>/manifest.json
    <name>/groups/<manager>/<group-id>.json
    <name>/policies/<manager>/<policy-id>/_policy.json
    <name>/policies/<manager>/<policy-id>/rules/<rule-id>.json
    <name>/tags/<manager>/<vm-external-id>.json     (--with-tags only)
"""

import json
import os
import re

from .api import F_DISPLAY_NAME, F_EXTERNAL_ID, F_ID, F_PATH, ROLE_LM
from .errors import NsxError
from .output import Spinner, parallel_run, say
from .paths import DEFAULT_SNAPSHOT_DIR, local_stamp, utc_now_iso
from .policy import group_inventory, rule_sequence, sweep_rules
from .render import tags_of
from .version import VERSION

MANIFEST = "manifest.json"

# Fields NSX changes on its own. Stripped from the compared body: leaving any
# of them in makes every snapshot differ from the last one.
VOLATILE_FIELDS = frozenset({
    "_revision",
    "_create_time",
    "_create_user",
    "_last_modified_time",
    "_last_modified_user",
    "_system_owned",
    "_protection",
    "realization_id",
    "unique_id",
    "parent_path",
    "relative_path",
    "marked_for_delete",
    "overridden",
    "origin_site_id",
    "owner_id",
    "remote_path",
    "children",
})
# Deliberately NOT stripped: `resource_type`. It looks like metadata, but
# inside a group's `expression` it is the discriminator that tells a Condition
# from an IPAddressExpression. Strip it and two different criteria compare
# equal.

# Kept out of the comparison, but carried alongside it: this is the
# "who changed it" evidence the drift report exists to surface.
PROVENANCE_FIELDS = ("_last_modified_user", "_last_modified_time",
                     "_create_user", "_revision")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _safe(component):
    """A path component safe on every filesystem, from an NSX id."""
    cleaned = _SAFE_NAME.sub("_", str(component or "unknown"))
    return cleaned[:120] or "unknown"


def normalise_object(obj):
    """(body, provenance). Body is what gets compared; provenance is context.

    Recurses, because nested structures carry the same volatile fields.
    """
    provenance = {key: obj.get(key) for key in PROVENANCE_FIELDS
                  if obj.get(key) is not None}
    return _strip(obj), provenance


def _strip(value):
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items()
                if k not in VOLATILE_FIELDS}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


# === CAPTURE ===
def capture_snapshot(sessions, domain, with_tags=False):
    """Read the current configuration into an in-memory snapshot.

    Uses the same deduplicated GM/LM traversal as reverse lookup and rule
    hygiene, so a GM-authored rule realized onto eight Local Managers is
    captured once, under the manager that owns it.
    """
    objects = {}
    provenance = {}
    counts = {"groups": 0, "policies": 0, "rules": 0, "tags": 0}

    def record(kind, manager, path, obj, extra=None):
        body, prov = normalise_object(obj)
        if extra:
            body.update(extra)
        objects[path] = {"kind": kind, "manager": manager, "body": body}
        if prov:
            provenance[path] = prov
        counts[kind] = counts.get(kind, 0) + 1

    with Spinner("Reading groups"):
        groups = group_inventory(sessions, domain)
    for path, (nsx, group) in groups.items():
        record("groups", nsx.name, path, group)

    with Spinner("Reading policies and rules"):
        records = sweep_rules(sessions, domain)

    # Evaluation order lives on the policy rather than in rule filenames, so a
    # reorder shows as one precise change instead of N deletes plus N adds.
    by_policy = {}
    for rec in records:
        key = (rec.nsx.name, rec.policy.get(F_PATH, ""))
        by_policy.setdefault(key, []).append(rec)

    for (manager, policy_path), rules in by_policy.items():
        ordered = sorted(rules, key=rule_sequence)
        policy = ordered[0].policy
        record("policies", manager, policy_path, policy,
               extra={"order": [r.rule_id for r in ordered]})
        for rec in ordered:
            if rec.path:
                record("rules", manager, rec.path, rec.rule)

    if with_tags:
        lms = [s for s in sessions if s.role == ROLE_LM]
        fetched = parallel_run(lms, lambda s: s.all_vms(),
                               label="Reading VM tags")
        for nsx in lms:
            vms = fetched.get(nsx.name)
            if isinstance(vms, Exception):
                continue
            for vm in (vms or []):
                ext = vm.get(F_EXTERNAL_ID)
                if not ext:
                    continue
                path = "vm:{}".format(ext)
                objects[path] = {
                    "kind": "tags", "manager": nsx.name,
                    "body": {"display_name": vm.get(F_DISPLAY_NAME, ""),
                             "external_id": ext,
                             "tags": sorted("{}={}".format(s, t)
                                            for s, t in tags_of(vm))}}
                counts["tags"] += 1

    return {
        "manifest": {
            "taken": utc_now_iso(),
            "tool_version": VERSION,
            "domain": domain,
            "managers": sorted(s.name for s in sessions),
            "with_tags": bool(with_tags),
            "counts": counts,
        },
        "objects": objects,
        "provenance": provenance,
    }


# === STORAGE ===
def _write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _object_file(root, entry, path):
    """Where one object's file lives in the tree."""
    kind = entry["kind"]
    manager = _safe(entry["manager"])
    body = entry["body"]
    if kind == "groups":
        return os.path.join(root, "groups", manager,
                            _safe(body.get(F_ID) or path) + ".json")
    if kind == "policies":
        return os.path.join(root, "policies", manager,
                            _safe(body.get(F_ID) or path), "_policy.json")
    if kind == "rules":
        # .../security-policies/<pid>/rules/<rid>
        parts = path.split("/security-policies/", 1)
        policy_id = parts[1].split("/")[0] if len(parts) > 1 else "unknown"
        return os.path.join(root, "policies", manager, _safe(policy_id),
                            "rules", _safe(body.get(F_ID) or path) + ".json")
    if kind == "tags":
        return os.path.join(root, "tags", manager,
                            _safe(body.get("external_id") or path) + ".json")
    return os.path.join(root, "other", manager, _safe(path) + ".json")


def default_snapshot_name(domain="default"):
    return "{}_{}".format(_safe(domain), local_stamp())


def save_snapshot(snapshot, name=None, root_dir=None):
    """Write the tree. Returns its root directory."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    name = _safe(name or default_snapshot_name(
        snapshot["manifest"].get("domain", "default")))
    root = os.path.join(root_dir, name)

    manifest = dict(snapshot["manifest"])
    manifest["name"] = name
    manifest["paths"] = {}

    for path, entry in snapshot["objects"].items():
        target = _object_file(root, entry, path)
        # Only the config goes in the object file. Provenance rides in the
        # manifest instead: _revision and _last_modified_time move when nothing
        # real changed, and putting them here would make every `git diff` noisy
        # -- the exact failure this whole design exists to avoid.
        _write_json(target, entry["body"])
        record = {"kind": entry["kind"], "manager": entry["manager"],
                  "file": os.path.relpath(target, root).replace(os.sep, "/")}
        prov = snapshot.get("provenance", {}).get(path)
        if prov:
            record["provenance"] = prov
        manifest["paths"][path] = record

    _write_json(os.path.join(root, MANIFEST), manifest)
    return root


def load_snapshot(root):
    """Read a tree back into the same shape capture_snapshot produces."""
    manifest_path = os.path.join(root, MANIFEST)
    if not os.path.isfile(manifest_path):
        raise NsxError(
            "{} is not a snapshot (no {}).".format(root, MANIFEST))
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except ValueError as e:
        raise NsxError("{} is corrupt: {}".format(manifest_path, e)) from e

    objects, provenance = {}, {}
    for path, meta in (manifest.get("paths") or {}).items():
        target = os.path.join(root, meta["file"].replace("/", os.sep))
        if not os.path.isfile(target):
            raise NsxError(
                "snapshot {} is incomplete: {} is missing".format(
                    root, meta["file"]))
        with open(target, encoding="utf-8") as f:
            payload = json.load(f)
        objects[path] = {"kind": meta["kind"], "manager": meta["manager"],
                         "body": payload}
        if meta.get("provenance"):
            provenance[path] = meta["provenance"]
    return {"manifest": manifest, "objects": objects, "provenance": provenance}


def list_snapshots(root_dir=None):
    """Every snapshot under root_dir, newest first."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    if not os.path.isdir(root_dir):
        return []
    found = []
    for name in sorted(os.listdir(root_dir)):
        candidate = os.path.join(root_dir, name)
        manifest_path = os.path.join(candidate, MANIFEST)
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
        except (ValueError, OSError):
            continue
        found.append({"name": name, "root": candidate,
                      "taken": manifest.get("taken", ""),
                      "domain": manifest.get("domain", ""),
                      "counts": manifest.get("counts", {}),
                      "managers": manifest.get("managers", [])})
    found.sort(key=lambda item: item["taken"], reverse=True)
    return found


def resolve_snapshot(name_or_path, root_dir=None):
    """Accept a snapshot name or a directory path. Newest wins for None."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    if name_or_path:
        if os.path.isdir(name_or_path):
            return name_or_path
        candidate = os.path.join(root_dir, _safe(name_or_path))
        if os.path.isdir(candidate):
            return candidate
        raise NsxError("No snapshot named '{}' in {}".format(
            name_or_path, root_dir))
    existing = list_snapshots(root_dir)
    if not existing:
        raise NsxError(
            "No snapshots yet in {}. Take one first: nsxctl snapshot "
            "save".format(root_dir))
    return existing[0]["root"]


def describe_snapshot(snapshot):
    manifest = snapshot["manifest"]
    counts = manifest.get("counts", {})
    say("  Taken    : {}".format(manifest.get("taken", "?")))
    say("  Domain   : {}".format(manifest.get("domain", "?")))
    say("  Managers : {}".format(", ".join(manifest.get("managers", []))))
    say("  Objects  : {}".format(", ".join(
        "{} {}".format(v, k) for k, v in sorted(counts.items()) if v)))
