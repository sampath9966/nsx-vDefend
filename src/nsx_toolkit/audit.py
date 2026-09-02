"""Append-only audit log of every write, with before/after state for undo.

Rotates at a size cap and reads from the tail, so a long-lived log neither
grows without bound nor gets slurped into memory to show the last 20 entries.
"""

import json
import os
import platform

from .output import err
from .paths import AUDIT_KEEP, AUDIT_MAX_BYTES, DEFAULT_AUDIT_FILE, utc_now_iso


def current_user():
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "unknown")


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

    def log(self, action, manager, vm_name, vm_ext_id, tags_before, tags_after,
            status="success", detail=""):
        entry = {
            "timestamp": utc_now_iso(),
            "user": current_user(),
            "host": platform.node(),
            "manager": manager,
            "action": action,
            "vm_display_name": vm_name,
            "vm_external_id": vm_ext_id,
            "tags_before": [{"scope": s, "tag": t} for s, t in tags_before],
            "tags_after": [{"scope": s, "tag": t} for s, t in tags_after],
            "status": status,
            "detail": detail,
        }
        self._rotate_if_needed()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            err("audit write failed: {}".format(e))
        return entry

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
