"""Append-only audit log of every write, with before/after state for undo.

Rotates at a size cap and reads from the tail, so a long-lived log neither
grows without bound nor gets slurped into memory to show the last 20 entries.

**Two entry shapes live in this file, and both must keep working.** Until
authoring existed, every write was a VM tag change, so an entry was
VM-shaped end to end: `vm_display_name`, `vm_external_id`, `tags_before`,
`tags_after`. Authoring writes groups and rules, which have none of those,
and needs `{object_type, object_path, before, after}` instead.

Rather than rename the fields -- which would make every audit log written
before this release unreadable, including for undo -- entries gained the
general fields alongside the specific ones, and `normalise_entry` maps BOTH
shapes onto one. Everything downstream (listing, export, undo) reads the
normalised shape, so nothing has to know which era an entry came from. A tag
entry still carries `tags_before`/`tags_after`, so an old log undoes exactly
as it always did.
"""

import json
import os
import platform

from .output import err
from .paths import AUDIT_KEEP, AUDIT_MAX_BYTES, DEFAULT_AUDIT_FILE, utc_now_iso


def current_user():
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "unknown")


# What an entry describes. Tag entries predate the field and are inferred.
OBJ_VM_TAGS = "vm_tags"
OBJ_GROUP = "group"
OBJ_RULE = "rule"
OBJ_POLICY = "policy"

ENTRY_VERSION = 2


def _tag_pairs(entries):
    return [(t.get("scope", ""), t.get("tag", "")) for t in (entries or [])]


def normalise_entry(entry):
    """One shape for an audit entry, whichever era wrote it.

    Returns a dict with object_type, object_path, object_name, before and
    after always present. For a tag entry `before`/`after` are lists of
    (scope, tag) pairs; for an object entry they are the NSX bodies.
    """
    common = {
        "timestamp": entry.get("timestamp", ""),
        "user": entry.get("user", ""),
        "manager": entry.get("manager", ""),
        "action": entry.get("action", ""),
        "status": entry.get("status", ""),
        "detail": entry.get("detail", ""),
        "raw": entry,
    }
    object_type = entry.get("object_type")
    if object_type in (None, OBJ_VM_TAGS) and "vm_display_name" in entry:
        # Pre-authoring entry, or a tag entry written since: both carry the
        # VM fields, and undo reads them from here.
        common.update({
            "object_type": OBJ_VM_TAGS,
            "object_path": entry.get("object_path")
                           or "vm:{}".format(entry.get("vm_external_id", "")),
            "object_name": entry.get("vm_display_name", "?"),
            "before": _tag_pairs(entry.get("tags_before")),
            "after": _tag_pairs(entry.get("tags_after")),
        })
        return common
    common.update({
        "object_type": object_type or "unknown",
        "object_path": entry.get("object_path", ""),
        "object_name": entry.get("object_name", ""),
        "before": entry.get("before"),
        "after": entry.get("after"),
    })
    return common


def summarise_entry(normalised):
    """A one-line 'what changed' for the listing, per object type."""
    if normalised["object_type"] == OBJ_VM_TAGS:
        before = normalised["before"] or []
        after = normalised["after"] or []
        added = [p for p in after if p not in before]
        removed = [p for p in before if p not in after]
        return added, removed
    return [], []


class AuditLog:
    def __init__(self, path=None, max_bytes=AUDIT_MAX_BYTES, keep=AUDIT_KEEP):
        self.path = path or DEFAULT_AUDIT_FILE
        self.max_bytes = max_bytes
        self.keep = keep
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)

    def _rotate_if_needed(self):
        try:
            if not os.path.isfile(self.path):
                return
            if os.path.getsize(self.path) < self.max_bytes:
                return
            oldest = "{}.{}".format(self.path, self.keep)
            if os.path.exists(oldest):
                os.remove(oldest)
            for i in range(self.keep - 1, 0, -1):
                src = "{}.{}".format(self.path, i)
                if os.path.exists(src):
                    os.replace(src, "{}.{}".format(self.path, i + 1))
            os.replace(self.path, "{}.1".format(self.path))
        except OSError as e:
            err("audit rotation failed: {}".format(e))

    def _append(self, entry):
        self._rotate_if_needed()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            err("audit write failed: {}".format(e))
        return entry

    def _envelope(self, action, manager, status, detail):
        return {
            "timestamp": utc_now_iso(),
            "user": current_user(),
            "host": platform.node(),
            "manager": manager,
            "action": action,
            "status": status,
            "detail": detail,
            "entry_version": ENTRY_VERSION,
        }

    def log(self, action, manager, vm_name, vm_ext_id, tags_before, tags_after,
            status="success", detail=""):
        """A VM tag change.

        Keeps writing `vm_display_name` / `tags_before` / `tags_after`
        verbatim -- an undo path and a log file written by an earlier release
        both read those, and neither should have to care that object entries
        now exist alongside them. The general fields are added, not swapped in.
        """
        entry = self._envelope(action, manager, status, detail)
        entry.update({
            "object_type": OBJ_VM_TAGS,
            "object_path": "vm:{}".format(vm_ext_id or ""),
            "object_name": vm_name,
            "vm_display_name": vm_name,
            "vm_external_id": vm_ext_id,
            "tags_before": [{"scope": s, "tag": t} for s, t in tags_before],
            "tags_after": [{"scope": s, "tag": t} for s, t in tags_after],
        })
        return self._append(entry)

    def log_change(self, action, manager, object_type, object_path,
                   object_name, before_body, after_body, status="success",
                   detail=""):
        """A change to a policy object: a group, a rule or a policy.

        `before_body` is None for a create and `after_body` is None for a
        delete, which is exactly what undo needs to know which direction to
        go without a separate flag to get out of step with reality.
        """
        entry = self._envelope(action, manager, status, detail)
        entry.update({
            "object_type": object_type,
            "object_path": object_path,
            "object_name": object_name,
            "before": before_body,
            "after": after_body,
        })
        return self._append(entry)

    def _tail_lines(self, n):
        """Last n non-empty lines without reading the whole file."""
        if not os.path.isfile(self.path):
            return []
        chunk = 8192
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                data = b""
                while size > 0 and data.count(b"\n") <= n:
                    step = min(chunk, size)
                    size -= step
                    f.seek(size)
                    data = f.read(step) + data
        except OSError:
            return []
        text = data.decode("utf-8", "replace")
        return [ln for ln in text.splitlines() if ln.strip()][-n:]

    def last_n(self, n=20):
        entries = []
        for line in self._tail_lines(n):
            try:
                entries.append(json.loads(line))
            except ValueError:
                pass
        return entries

    def last_n_normalised(self, n=20):
        """The same entries in one shape, whichever era wrote them."""
        return [normalise_entry(e) for e in self.last_n(n)]
