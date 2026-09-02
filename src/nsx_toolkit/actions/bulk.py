"""Bulk tagging from CSV.

Resolution is index-based. The previous implementation called a per-VM lookup
that fell back to fetching the entire VM inventory, once per CSV row per
manager -- 500 rows across 8 Local Managers meant up to 4,000 full inventory
sweeps. Here every manager's inventory is fetched exactly once, in parallel,
and all rows resolve against that index.

Apply re-reads each VM immediately before writing and refuses the row if its
tags changed since the plan was computed, so a stale plan cannot silently
clobber another operator's concurrent change.
"""

import csv
import os

from ..api import F_DISPLAY_NAME, F_EXTERNAL_ID
from ..errors import NsxError
from ..output import cBG, cBR, cBY, cC, cD, cG, cR, cY, err, hr, parallel_run, say, warn
from ..render import fmt_tags_plain, tags_of

REQUIRED_COLUMNS = {"vm_name", "scope", "tag", "action"}
VALID_ACTIONS = ("add", "remove")


def read_bulk_csv(path):
    """Rows plus any structural problems. Raises only for unusable files."""
    if not os.path.isfile(path):
        raise NsxError("Not found: {}".format(path))
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise NsxError("CSV empty: {}".format(path))
    missing = REQUIRED_COLUMNS - {k for k in rows[0].keys() if k}
    if missing:
        raise NsxError("CSV missing column(s): {}".format(", ".join(sorted(missing))))
    problems = []
    clean = []
    for i, row in enumerate(rows, 2):  # header is line 1
        name = (row.get("vm_name") or "").strip()
        scope = (row.get("scope") or "").strip()
        tag = (row.get("tag") or "").strip()
        action = (row.get("action") or "").strip().lower()
        if not name:
            problems.append("line {}: empty vm_name".format(i))
            continue
        if action not in VALID_ACTIONS:
            problems.append("line {}: action must be add|remove (got {!r})".format(
                i, row.get("action")))
            continue
        if not scope and not tag:
            problems.append("line {}: needs a scope, a tag, or both".format(i))
            continue
        clean.append({"line": i, "vm_name": name, "scope": scope,
                      "tag": tag, "action": action})
    return clean, problems


def build_vm_index(sessions):
    """{lowercase display name: [(nsx, vm), ...]} from one fetch per manager."""
    fetched = parallel_run(sessions, lambda s: s.all_vms(),
                           label="Indexing VM inventories")
    index = {}
    for nsx in sessions:
        vms = fetched.get(nsx.name)
        if isinstance(vms, Exception):
            err("{}: {}".format(nsx.name, vms))
            continue
        for vm in (vms or []):
            key = str(vm.get(F_DISPLAY_NAME, "")).lower()
            if key:
                index.setdefault(key, []).append((nsx, vm))
    return index


def plan_bulk(sessions, rows):
    """Compute per-VM tag changes without touching NSX beyond the index build.

    Returns (plan, unresolved, ambiguous) where plan entries are
    {nsx, vm, before, after, added, removed, ops}.
    """
    index = build_vm_index(sessions)
    by_vm = {}
    for row in rows:
        by_vm.setdefault(row["vm_name"], []).append(row)

    plan, unresolved, ambiguous = [], [], []
    for name, ops in sorted(by_vm.items()):
        candidates = index.get(name.lower(), [])
        if not candidates:
            unresolved.append(name)
            continue
        if len({n.name for n, _ in candidates}) > 1:
            ambiguous.append((name, sorted({n.name for n, _ in candidates})))
            continue
        nsx, vm = candidates[0]
        before = sorted(tags_of(vm))
        after = list(before)
        for op in ops:
            pair = (op["scope"], op["tag"])
            if op["action"] == "add":
                if pair not in after:
                    after.append(pair)
            else:
                after = [p for p in after if p != pair]
        after = sorted(after)
        plan.append({
            "nsx": nsx, "vm": vm, "before": before, "after": after,
            "added": [p for p in after if p not in before],
            "removed": [p for p in before if p not in after],
            "ops": ops,
        })
    return plan, unresolved, ambiguous


def act_bulk_tag(sessions, csv_path, audit, write_enabled, dry_run=True,
                 taxonomy=None, force=False):
    """Returns a result dict; also prints a human-readable plan/outcome."""
    result = {"applied": 0, "skipped": 0, "failed": 0, "unresolved": 0,
              "unchanged": 0}
    try:
        rows, problems = read_bulk_csv(csv_path)
    except NsxError as e:
        err(str(e))
        return result
    for p in problems:
        warn(p)
    if not rows:
        err("No usable rows in {}.".format(csv_path))
        return result

    if taxonomy:
        for row in rows:
            if row["action"] == "add":
                for w in taxonomy.validate_tag(row["scope"], row["tag"]):
                    warn("line {}: {}".format(row["line"], w))

    if not dry_run and not write_enabled:
        say("  {}. Re-run with --enable-writes.".format(cBY("Writes disabled")))
        return result

    plan, unresolved, ambiguous = plan_bulk(sessions, rows)
    label = cBY("DRY RUN") if dry_run else cBG("APPLYING")
    say("\n  {} -- {} op(s) across {} VM(s)".format(label, len(rows), len(plan)))
    hr()

    for name in unresolved:
        say("  {:45s}  {}".format(name, cR("NOT FOUND")))
        result["unresolved"] += 1
    for name, mgrs in ambiguous:
        say("  {:45s}  {} on {}".format(
            name, cBR("AMBIGUOUS"), ", ".join(mgrs)))
        say("      {}".format(cD("resolve with --manager to pick one")))
        result["skipped"] += 1

    for item in plan:
        name = item["vm"].get(F_DISPLAY_NAME, "?")
        if not item["added"] and not item["removed"]:
            say("  {:45s}  {}".format(name, cD("no change")))
            result["unchanged"] += 1
            continue
        change = []
        if item["added"]:
            change.append(cG("+{}".format(len(item["added"]))))
        if item["removed"]:
            change.append(cR("-{}".format(len(item["removed"]))))
        if dry_run:
            say("  {:45s}  [{}]  would: {}".format(
                name, cC(item["nsx"].name), ", ".join(change)))
            for s, t in item["added"]:
                say("      {}".format(cG("+ {}={}".format(s, t))))
            for s, t in item["removed"]:
                say("      {}".format(cR("- {}={}".format(s, t))))
            result["applied"] += 1
            continue
        try:
            _write_row(item, audit, force)
            say("  {:45s}  [{}]  applied: {}".format(
                name, cC(item["nsx"].name), ", ".join(change)))
            result["applied"] += 1
        except NsxError as e:
            say("  {:45s}  {}".format(name, cBR("FAILED")))
            say("      {}".format(cD(str(e)[:160])))
            result["failed"] += 1

    hr()
    say("  Complete: {} {}, {} unchanged, {} not found, {} failed.".format(
        cG(str(result["applied"])), "planned" if dry_run else "applied",
        cY(str(result["unchanged"])), cR(str(result["unresolved"])),
        cR(str(result["failed"]))))
    return result


def _write_row(item, audit, force):
    nsx, vm = item["nsx"], item["vm"]
    fresh = nsx.refresh_vm(vm)
    if fresh is None:
        raise NsxError("VM disappeared from inventory before write.")
    live = sorted(tags_of(fresh))
    if live != item["before"] and not force:
        raise NsxError(
            "tags changed on NSX since the plan was built (now: {}); "
            "re-run, or pass --force to overwrite.".format(fmt_tags_plain(live)))
    nsx.update_vm_tags(fresh, item["after"])
    audit.log("bulk_update_tags", nsx.name, fresh.get(F_DISPLAY_NAME, "?"),
              fresh.get(F_EXTERNAL_ID), item["before"], item["after"])
