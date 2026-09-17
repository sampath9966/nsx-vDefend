"""VM-centric views: groups a VM is a member of, and the rules that reference them."""

from ..api import (
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_EXTERNAL_ID,
    F_PATH,
    F_TARGET_DISPLAY_NAME,
    F_TARGET_ID,
    PARAM_VM_EXTERNAL_ID,
    ROLE_GM,
    ROLE_LM,
    group_id_from_path,
    origin_of_path,
    p_group,
    p_vm_group_assoc,
)
from ..errors import NsxError
from ..output import Spinner, cB, cBG, cBR, cC, cD, err, hr, parallel_run, say, section, table
from ..policy import sweep_rules
from ..render import criteria_summary

VM_GROUP_HEADERS = ["vm", "manager", "group_id", "group_name", "origin",
                    "criteria", "rule_count"]


def act_vm_groups(all_sessions, needle, domain, exporter):
    """Groups this VM belongs to (any member type) and how many DFW rules reference them.

    Uses NSX's own virtual-machine-group-associations reverse index, which is
    member-type agnostic -- it works for tag-matched, segment-matched, VIF-matched
    and IP-set groups equally, unlike the /members/virtual-machines sub-resource
    which silently returns nothing for non-VM-typed groups.
    """
    lm_sessions = [s for s in all_sessions if s.role == ROLE_LM]
    gm_sessions = [s for s in all_sessions if s.role == ROLE_GM]

    # VMs are LM-local objects -- find the VM on whichever LM has it.
    found = None
    for nsx in lm_sessions:
        try:
            hits = nsx.find_vms(needle)
            if hits:
                found = (nsx, hits[0])
                break
        except NsxError:
            continue
    if not found:
        say("  No VM matching '{}' on any Local Manager.".format(needle))
        exporter.stage("vm_groups", VM_GROUP_HEADERS, [])
        return

    nsx_lm, vm = found
    vname = vm.get(F_DISPLAY_NAME, "?")
    ext_id = vm.get(F_EXTERNAL_ID)
    section("VM GROUPS")
    say("  VM       : {}".format(cB(vname)))
    say("  Found on : {}".format(cC(nsx_lm.name)))

    if not ext_id:
        say("  {} VM has no external_id -- cannot resolve group associations.".format(
            cBR("[error]")))
        exporter.stage("vm_groups", VM_GROUP_HEADERS, [])
        return

    # --- Group membership via reverse-association index ---
    matched = {}  # group_id -> (path, display_name, origin)
    with Spinner("Association lookup on {}".format(nsx_lm.name)):
        try:
            for a in nsx_lm.get_all(p_vm_group_assoc(nsx_lm.base(domain)),
                                    params={PARAM_VM_EXTERNAL_ID: ext_id}):
                gpath = a.get(F_PATH, "")
                gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
                matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                                origin_of_path(gpath))
        except NsxError as e:
            err("association lookup failed: {}".format(e))

    # Best-effort GM supplement -- catches Global Groups not yet realized here.
    for nsx_gm in gm_sessions:
        try:
            for a in nsx_gm.get_all(p_vm_group_assoc(nsx_gm.base(domain)),
                                    params={PARAM_VM_EXTERNAL_ID: ext_id}):
                gpath = a.get(F_PATH, "")
                gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
                if gid not in matched:
                    matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                                    origin_of_path(gpath))
        except NsxError:
            pass

    if not matched:
        say("  {}".format(cD("Not a member of any group.")))
        exporter.stage("vm_groups", VM_GROUP_HEADERS, [])
        return

    say("  Member of: {} group(s)".format(cC(str(len(matched)))))
    hr()

    # Count how many DFW rules reference each group
    group_paths = {gp for gp, _, _ in matched.values() if gp}
    rule_counts = {}
    for record in sweep_rules(all_sessions, domain):
        for gp in record.group_refs() & group_paths:
            rule_counts[gp] = rule_counts.get(gp, 0) + 1

    # Fetch group expressions for the criteria column — all groups in parallel.
    def _fetch_group(item):
        nsx, gid = item
        return nsx.get(p_group(nsx.base(domain), domain, gid))

    group_work = [(nsx, gid)
                  for gid in matched
                  for nsx in (lm_sessions + gm_sessions)]
    group_results = {}
    fetched_exprs = parallel_run(
        group_work,
        _fetch_group,
        label="Fetching group criteria",
        key=lambda item: (item[0].name, item[1]),
    )
    for (sname, gid), value in fetched_exprs.items():
        if gid not in group_results and not isinstance(value, Exception):
            group_results[gid] = criteria_summary(value.get(F_EXPRESSION))

    rows = []
    display_rows = []
    for gid, (gpath, gname, origin) in sorted(matched.items(),
                                               key=lambda kv: kv[1][1].lower()):
        criteria = group_results.get(gid, "")
        rc = rule_counts.get(gpath, 0)
        origin_lbl = cC("GM") if origin == "GM" else cD("LM")
        rows.append([vname, nsx_lm.name, gid, gname, origin, criteria, str(rc)])
        display_rows.append([origin_lbl, cB(gname), cD(gid),
                             criteria[:48] if criteria else cD("(unknown)"),
                             cBG(str(rc)) if rc else cD("0")])

    table(["Origin", "Group", "Id", "Criteria", "DFW Rules"],
          display_rows, indent=4)
    hr()
    say("  {}  {}".format(
        cD("next:"),
        cC("nsxctl rule search --ip <IP>   # find rules by IP address")))
    exporter.stage("vm_groups", VM_GROUP_HEADERS, rows)
