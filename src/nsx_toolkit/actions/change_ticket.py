"""Change plan generation from a bulk-tagging CSV.

This used to be a CSV reformatter: it accepted sessions, a domain and an audit
log and used none of them, so the plan attached to a change ticket was never
checked against the NSX it would run on. It now resolves every VM through the
same planner --bulk-tag uses, so the document states current tags, proposed
tags, rows that are already no-ops, and rows whose VM cannot be found.
"""

import os
import platform

from ..api import F_DISPLAY_NAME
from ..errors import NsxError
from ..output import cB, cBC, cBY, cG, cR, err, ok_msg, say
from ..paths import DEFAULT_TICKET_DIR, local_stamp, utc_now_stamp
from ..render import fmt_tags_plain
from .bulk import plan_bulk, read_bulk_csv

TICKET_HEADERS = ["vm_name", "manager", "status", "tags_before", "tags_after",
                  "added", "removed"]


def _rule(char="=", width=70):
    return char * width


def build_plan_lines(csv_path, plan, unresolved, ambiguous, problems, user):
    adds = sum(len(p["added"]) for p in plan)
    removes = sum(len(p["removed"]) for p in plan)
    changing = [p for p in plan if p["added"] or p["removed"]]
    noop = [p for p in plan if not p["added"] and not p["removed"]]

    lines = [_rule(), "  CHANGE PLAN: Tag Migration Batch", _rule(),
             "  Prepared by : {}".format(user),
             "  Date        : {}".format(utc_now_stamp()),
             "  Source      : {}".format(csv_path),
             "  Host        : {}".format(platform.node()), "",
             "  SCOPE", "  " + _rule("-", 40),
             "  VMs changing     : {}".format(len(changing)),
             "  VMs already ok   : {}".format(len(noop)),
             "  VMs not found    : {}".format(len(unresolved)),
             "  VMs ambiguous    : {}".format(len(ambiguous)),
             "  Tags to add      : {}".format(adds),
             "  Tags to remove   : {}".format(removes), ""]

    if problems:
        lines.extend(["  CSV PROBLEMS", "  " + _rule("-", 40)])
        lines.extend("    {}".format(p) for p in problems)
        lines.append("")

    lines.extend(["  CHANGES BY VM  (verified against live NSX)",
                  "  " + _rule("-", 40)])
    for item in sorted(changing, key=lambda p: p["vm"].get(F_DISPLAY_NAME, "")):
        lines.append("  {}   [{}]".format(
            item["vm"].get(F_DISPLAY_NAME, "?"), item["nsx"].name))
        lines.append("    current : {}".format(fmt_tags_plain(item["before"])))
        lines.append("    proposed: {}".format(fmt_tags_plain(item["after"])))
        for s, t in item["added"]:
            lines.append("    + {}={}".format(s, t))
        for s, t in item["removed"]:
            lines.append("    - {}={}".format(s, t))
        lines.append("")

    if noop:
        lines.extend(["  ALREADY IN DESIRED STATE (no action)",
                      "  " + _rule("-", 40)])
        lines.extend("    {}".format(p["vm"].get(F_DISPLAY_NAME, "?")) for p in noop)
        lines.append("")
    if unresolved:
        lines.extend(["  NOT FOUND ON ANY MANAGER (will be skipped)",
                      "  " + _rule("-", 40)])
        lines.extend("    {}".format(n) for n in unresolved)
        lines.append("")
    if ambiguous:
        lines.extend(["  AMBIGUOUS -- same name on several managers",
                      "  " + _rule("-", 40)])
        lines.extend("    {}  ({})".format(n, ", ".join(m)) for n, m in ambiguous)
        lines.append("")

    lines.extend(["  ROLLBACK", "  " + _rule("-", 40),
                  "  Audit-log undo (menu 11) restores per-VM prior state,",
                  "  or apply an inverse CSV with --bulk-tag.", "",
                  "  PRE-CHANGE CHECKLIST", "  " + _rule("-", 40),
                  "  1. --verify   (all managers reachable and authenticated)",
                  "  2. --bulk-tag <file> --dry-run   (preview, no writes)",
                  "  3. Confirm no active maintenance window conflicts",
                  "  4. --bulk-tag <file> --enable-writes --yes", "", _rule()])
    return lines


def act_change_ticket(sessions, csv_path, exporter, out_dir=None):
    try:
        rows, problems = read_bulk_csv(csv_path)
    except NsxError as e:
        err(str(e))
        return None
    plan, unresolved, ambiguous = plan_bulk(sessions, rows)
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    lines = build_plan_lines(csv_path, plan, unresolved, ambiguous, problems, user)

    out_dir = out_dir or DEFAULT_TICKET_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "change_plan_{}.txt".format(local_stamp()))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    for line in lines:
        if line.startswith("=" * 10):
            say(cBC(line))
        elif "CHANGE PLAN" in line:
            say("  {}".format(cB(line.strip())))
        elif line.strip().startswith("+") and "=" in line:
            say(cG(line))
        elif line.strip().startswith("- ") and "=" in line:
            say(cR(line))
        else:
            say(line)

    export_rows = []
    for item in plan:
        changing = bool(item["added"] or item["removed"])
        export_rows.append([
            item["vm"].get(F_DISPLAY_NAME, "?"), item["nsx"].name,
            "change" if changing else "no_change",
            fmt_tags_plain(item["before"]), fmt_tags_plain(item["after"]),
            fmt_tags_plain(item["added"]), fmt_tags_plain(item["removed"])])
    for name in unresolved:
        export_rows.append([name, "", "not_found", "", "", "", ""])
    for name, mgrs in ambiguous:
        export_rows.append([name, ", ".join(mgrs), "ambiguous", "", "", "", ""])
    exporter.stage("change_plan", TICKET_HEADERS, export_rows)

    if unresolved or ambiguous:
        say("  {} {} row(s) could not be resolved -- see the plan.".format(
            cBY("WARNING:"), len(unresolved) + len(ambiguous)))
    ok_msg("Saved: {}".format(out_path))
    return out_path
