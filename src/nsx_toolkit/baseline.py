"""Rule hit-count baselines.

NSX hit counters are cumulative since the last reset -- a manager reboot, a
rule edit, or a manual counter reset all zero them. A single read therefore
cannot tell you a rule saw no traffic in the last thirty days, only that its
counter currently reads zero.

Saving a baseline and comparing later closes that gap: a rule whose counter
did not move between two timestamps genuinely saw no matching traffic in that
window, and that is evidence you can attach to a deletion request.

The trap this module exists to avoid: if the second read is LOWER than the
first, the counter was reset and the window is meaningless. That case is
reported as `counter_reset`, never as unused. Claiming a rule saw no traffic
when the evidence was wiped is how a live firewall rule gets deleted.
"""

import json
import os

from .api import F_HIT_COUNT, F_LAST_UPDATE
from .errors import NsxError
from .paths import DEFAULT_SNAPSHOT_DIR, local_stamp, utc_now_iso
from .version import VERSION

BASELINE_HEADERS = ["status", "manager", "policy", "rule", "hits_then",
                    "hits_now", "delta", "detail"]

# Outcomes, worst-news-first for reporting.
STATUS_ORDER = ("counter_reset", "unused_since_baseline", "active",
                "added", "removed", "unknown")


def default_baseline_path(domain="default"):
    return os.path.join(
        DEFAULT_SNAPSHOT_DIR,
        "hit-baseline_{}_{}.json".format(domain, local_stamp()))


def build_hit_baseline(records, stats, domain="default"):
    """A serialisable snapshot of every rule's counter."""
    rules = {}
    for record in records:
        path = record.path
        if not path:
            continue
        entry = stats.get(path) or {}
        hits = entry.get(F_HIT_COUNT)
        rules[path] = {
            "manager": record.nsx.name,
            "policy": record.policy_name,
            "rule": record.rule_name,
            "hit_count": hits,
            "last_update": entry.get(F_LAST_UPDATE),
        }
    return {"taken": utc_now_iso(), "tool_version": VERSION,
            "domain": domain, "rule_count": len(rules), "rules": rules}


def save_hit_baseline(snapshot, path=None, domain="default"):
    path = path or default_baseline_path(domain)
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


def load_hit_baseline(path):
    if not os.path.isfile(path):
        raise NsxError("Baseline not found: {}".format(path))
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise NsxError("Baseline is not valid JSON ({}): {}".format(
            path, e)) from e
    if not isinstance(data, dict) or "rules" not in data:
        raise NsxError(
            "{} does not look like a hit baseline (no 'rules').".format(path))
    return data


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compare_hit_baselines(before, after):
    """Per-rule comparison of two snapshots.

    Returns a list of dicts with a `status` from STATUS_ORDER. Rules present
    in only one snapshot are reported as added/removed rather than dropped --
    a rule that disappeared between reads is information, not noise.
    """
    old_rules = before.get("rules") or {}
    new_rules = after.get("rules") or {}
    results = []

    for path in sorted(set(old_rules) | set(new_rules)):
        old = old_rules.get(path)
        new = new_rules.get(path)
        meta = new or old or {}
        base = {"path": path,
                "manager": meta.get("manager", ""),
                "policy": meta.get("policy", ""),
                "rule": meta.get("rule", ""),
                "hits_then": None, "hits_now": None, "delta": None}

        if old is None:
            base.update(status="added",
                        hits_now=_as_int(new.get("hit_count")),
                        detail="rule did not exist when the baseline "
                               "was taken")
            results.append(base)
            continue
        if new is None:
            base.update(status="removed",
                        hits_then=_as_int(old.get("hit_count")),
                        detail="rule existed in the baseline but not now")
            results.append(base)
            continue

        then = _as_int(old.get("hit_count"))
        now = _as_int(new.get("hit_count"))
        base["hits_then"], base["hits_now"] = then, now
        if then is None or now is None:
            base.update(status="unknown",
                        detail="hit counters unavailable in one or both reads")
            results.append(base)
            continue

        delta = now - then
        base["delta"] = delta
        if delta < 0:
            base.update(
                status="counter_reset",
                detail="counter went backwards ({} -> {}) -- it was reset, so "
                       "this window proves nothing".format(then, now))
        elif delta == 0:
            base.update(
                status="unused_since_baseline",
                detail="no traffic matched between {} and {}".format(
                    before.get("taken", "?"), after.get("taken", "?")))
        else:
            base.update(status="active",
                        detail="{} hit(s) in the window".format(delta))
        results.append(base)

    results.sort(key=lambda r: (STATUS_ORDER.index(r["status"]),
                                r["policy"], r["rule"]))
    return results


def hit_baseline_rows(results):
    return [[r["status"], r["manager"], r["policy"], r["rule"],
             "" if r["hits_then"] is None else str(r["hits_then"]),
             "" if r["hits_now"] is None else str(r["hits_now"]),
             "" if r["delta"] is None else str(r["delta"]),
             r["detail"]] for r in results]


def hit_baseline_summary(results):
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    return counts
