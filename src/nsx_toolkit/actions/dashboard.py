"""Taxonomy compliance posture across every Local Manager."""

import datetime

from ..api import F_DISPLAY_NAME, ROLE_LM
from ..output import (
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cG,
    cR,
    err,
    hr,
    parallel_run,
    progress_bar,
    say,
    section,
    table,
)
from ..render import tags_of

DASHBOARD_HEADERS = ["vm_name", "manager", "tag_count", "mandatory_present",
                  "missing", "status"]


def _pct(part, whole):
    return int(100 * part / whole) if whole else 0


def act_dashboard(sessions, exporter, taxonomy):
    lms = [s for s in sessions if s.role == ROLE_LM]
    if not lms:
        say("  No Local Managers connected -- tags are LM-local objects.")
        exporter.stage("dashboard", DASHBOARD_HEADERS, [])
        return
    section("COMPLIANCE DASHBOARD    {}".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
    say("  Taxonomy: {}".format(cC(taxonomy.source)))
    fetched = parallel_run(lms, lambda s: s.all_vms(),
                           label="Fetching VM inventories")
    vms = []
    for name, result in fetched.items():
        if isinstance(result, Exception):
            err("{}: {}".format(name, result))
            continue
        for vm in (result or []):
            vms.append((name, vm))
    total = len(vms)
    if total == 0:
        say("  No VMs found.")
        exporter.stage("dashboard", DASHBOARD_HEADERS, [])
        return

    mandatory = taxonomy.mandatory
    coverage = dict.fromkeys(mandatory, 0)
    untagged = full = partial = 0
    rows = []
    for mgr, vm in vms:
        pairs = tags_of(vm)
        scopes = {s for s, _ in pairs if s}
        present = [s for s in mandatory if s in scopes]
        missing = [s for s in mandatory if s not in scopes]
        if not pairs:
            untagged += 1
            status = "untagged"
        elif len(present) == len(mandatory):
            full += 1
            status = "complete"
        else:
            partial += 1
            status = "partial"
        for s in present:
            coverage[s] += 1
        rows.append([vm.get(F_DISPLAY_NAME, "?"), mgr, str(len(pairs)),
                     str(len(present)), ", ".join(missing) or "none", status])

    say("\n  {} ({} VMs)\n".format(cB("Scope Coverage"), total))
    table(["Scope", "Coverage", "Progress"],
          [[cC(s), "{}/{}".format(coverage[s], total),
            progress_bar(coverage[s], total)] for s in mandatory], indent=4)

    say("\n  {}".format(cB("Summary")))
    hr()
    say("    Total VMs              : {}".format(cB(str(total))))
    say("    Fully tagged ({}/{})     : {} ({}%)".format(
        len(mandatory), len(mandatory), cBG(str(full)), _pct(full, total)))
    say("    Partially tagged       : {} ({}%)".format(
        cBY(str(partial)), _pct(partial, total)))
    say("    Untagged               : {} ({}%)".format(
        cBR(str(untagged)), _pct(untagged, total)))
    say("    Migration progress     : {}".format(progress_bar(full, total)))

    say("\n  {}".format(cB("Per-Manager")))
    mrows = []
    for nsx in lms:
        mine = [vm for mgr, vm in vms if mgr == nsx.name]
        mt = len(mine)
        mf = sum(1 for v in mine
                 if len({s for s, _ in tags_of(v) if s} & set(mandatory))
                 == len(mandatory))
        mu = sum(1 for v in mine if not tags_of(v))
        mrows.append([cC(nsx.name), str(mt), cG(str(mf)), cR(str(mu)),
                      progress_bar(mf, mt)])
    table(["Manager", "VMs", "Complete", "Untagged", "Progress"], mrows, indent=4)
    hr()
    exporter.stage("dashboard", DASHBOARD_HEADERS, rows)
