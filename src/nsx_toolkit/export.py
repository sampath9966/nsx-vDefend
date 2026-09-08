"""Result staging and export.

Holds a LIST of named result sets, not one. Running two actions in a single
invocation (--groups --dashboard) used to silently discard the first one's
rows because staging overwrote it.

Console output truncates long listings for readability; exports never do.
"""

import csv
import json
import os
import re

from .output import ask, cC, is_json_mode, ok_msg, say
from .paths import DEFAULT_EXPORT_DIR, local_stamp, utc_now_iso


class ResultSet:
    __slots__ = ("label", "headers", "rows")

    def __init__(self, label, headers, rows):
        self.label = label
        self.headers = headers
        self.rows = rows

    def as_dicts(self):
        return [{self.headers[i]: (row[i] if i < len(row) else "")
                 for i in range(len(self.headers))} for row in self.rows]


class Exporter:
    def __init__(self, export_dir=None):
        self.export_dir = export_dir or DEFAULT_EXPORT_DIR
        self._sets = []
        # Findings are a second channel alongside rows: rows are "here is the
        # data", findings are "here is what is wrong with it". CSV and JSON
        # want the first; JUnit, SARIF, metrics and a webhook want the second.
        self._findings = []

    def stage(self, label, headers, rows):
        """Add a result set. Empty sets are still recorded so --json reports
        'this action ran and found nothing' rather than staying silent."""
        self._sets.append(ResultSet(label, list(headers), list(rows)))

    @property
    def sets(self):
        return list(self._sets)

    def stage_findings(self, label, findings):
        """Record machine-readable findings for this run."""
        for item in findings:
            entry = dict(item)
            entry.setdefault("suite", label)
            self._findings.append(entry)

    @property
    def findings(self):
        return list(self._findings)

    def findings_by_suite(self):
        suites = {}
        for item in self._findings:
            suites.setdefault(item.get("suite", "nsxctl"), []).append(item)
        return suites

    def has_findings(self):
        return bool(self._findings)

    def has_staged(self):
        return any(rs.rows for rs in self._sets)

    def clear(self):
        self._sets = []
        self._findings = []

    def _ensure_dir(self, path):
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)

    def _gen(self, label, ext):
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", label or "export")[:40]
        return os.path.join(self.export_dir,
                            "{}_{}.{}".format(safe, local_stamp(), ext))

    def _target(self, base_path, rs, index, total, ext):
        """One file per result set. With several sets the label is appended so
        nothing is silently overwritten."""
        if not base_path:
            return self._gen(rs.label, ext)
        if total == 1:
            return base_path
        root, dot_ext = os.path.splitext(base_path)
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", rs.label or str(index))[:40]
        return "{}_{}{}".format(root, safe, dot_ext or "." + ext)

    def to_csv(self, path=None):
        written = []
        sets = [rs for rs in self._sets if rs.rows]
        for i, rs in enumerate(sets):
            target = self._target(path, rs, i, len(sets), "csv")
            self._ensure_dir(target)
            with open(target, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(rs.headers)
                w.writerows(rs.rows)
            written.append(target)
        return written

    def to_json(self, path=None):
        written = []
        sets = [rs for rs in self._sets if rs.rows]
        if path and len(sets) > 1:
            # One JSON file can hold every set, so keep them together.
            self._ensure_dir(path)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"exported": utc_now_iso(),
                           "results": [{"label": rs.label,
                                        "count": len(rs.rows),
                                        "records": rs.as_dicts()} for rs in sets]},
                          f, indent=2, ensure_ascii=False)
            return [path]
        for i, rs in enumerate(sets):
            target = self._target(path, rs, i, len(sets), "json")
            self._ensure_dir(target)
            with open(target, "w", encoding="utf-8") as f:
                json.dump({"exported": utc_now_iso(), "label": rs.label,
                           "count": len(rs.rows), "records": rs.as_dicts()},
                          f, indent=2, ensure_ascii=False)
            written.append(target)
        return written

    def json_payload(self):
        return [{"label": rs.label, "count": len(rs.rows),
                 "records": rs.as_dicts()} for rs in self._sets]


def offer_export(exporter):
    """Interactive post-action export prompt. A no-op in JSON mode, where the
    results are emitted in the envelope instead."""
    if is_json_mode() or not exporter.has_staged():
        return
    total = sum(len(rs.rows) for rs in exporter.sets)
    say("\n  {} record(s) available.".format(cC(str(total))))
    c = ask("  Export? [c]sv / [j]son / [n]o: ",
            default="n", allow_back=False).lower()
    if c in ("c", "csv"):
        for p in exporter.to_csv():
            ok_msg("Saved: {}".format(p))
    elif c in ("j", "json"):
        for p in exporter.to_json():
            ok_msg("Saved: {}".format(p))
    exporter.clear()
