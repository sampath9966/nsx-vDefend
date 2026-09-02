"""Reverse lookup: VM -> groups -> DFW rules impact analysis."""

from ..api import (
    F_ACTION_FIELD,
    F_DEST_GROUPS,
    F_DISPLAY_NAME,
    F_EXTERNAL_ID,
    F_ID,
    F_PATH,
    F_SCOPE,
    F_SOURCE_GROUPS,
    F_TARGET_DISPLAY_NAME,
    F_TARGET_ID,
    PARAM_VM_EXTERNAL_ID,
    ROLE_GM,
    ROLE_LABEL,
    ROLE_LM,
    group_id_from_path,
    origin_of_path,
    p_sec_policies,
    p_sec_rules,
    p_vm_group_assoc,
)
from ..errors import NsxError
from ..output import Spinner, cB, cBR, cC, cD, cG, cR, err, hr, parallel_run, say, section
from ..render import fmt_tags, tags_of

REVERSE_HEADERS = ["vm", "manager", "manager_role", "group_id", "group_name",
                  "group_origin", "policy", "rule", "rule_origin", "action",
                  "direction"]


def _collect_associations(nsx, domain, ext_id):
    base = nsx.base(domain)
    return nsx.get_all(p_vm_group_assoc(base),
                       params={PARAM_VM_EXTERNAL_ID: ext_id})


def _fetch_rules(nsx, domain, policies):
    """Rules for every policy on one manager, fetched concurrently.

    Serially this was an N+1: one round trip per policy per manager, so eight
    LMs with 200 policies each meant 1,600 sequential requests.
    """
    if not policies:
        return []
    results = parallel_run(
        policies,
        lambda pol: nsx.get_all(p_sec_rules(nsx.base(domain), domain,
                                            pol.get(F_ID, "?"))),
        label="Rules on {}".format(nsx.name),
        key=lambda pol: pol.get(F_ID, "?"))
    out = []
    for pol in policies:
        rules = results.get(pol.get(F_ID, "?"))
        if isinstance(rules, Exception):
            continue
        for rule in (rules or []):
            out.append((pol, rule))
    return out


def act_reverse_lookup(all_sessions, needle, domain, exporter):
    """VM -> groups -> DFW rules impact analysis.

    GROUP MEMBERSHIP: uses NSX's own reverse-association endpoint
    (virtual-machine-group-associations) instead of sweeping every group's
    /members/virtual-machines sub-resource. That sub-resource only returns
    results for groups whose criteria resolves to the VirtualMachine member
    type -- groups matched on VIF, IPAddress, Segment, or SegmentPort criteria
    silently come back empty there even though the VM is an effective member.
    The association endpoint is member-type agnostic: it's the same index NSX's
    own Groups search UI reads, so results match what you see there. Queried on
    the VM's home LM (tags/VMs are LM-local), with a best-effort supplementary
    query on any connected GM.

    DFW RULES: GM-authored security policies are realized read-only on every LM
    registered beneath it, so an LM's own rule listing contains both its native
    rules AND a copy of every GM rule. Scanned across GM + all LMs, that means
    each GM rule would otherwise be reported once per LM (once per site, up to
    8x). Rules are deduped globally by their NSX 'path' -- first-seen wins, GM
    sessions are scanned before LM sessions, so a GM-origin rule is always
    attributed to 'GM' exactly once and never re-listed per LM. Rules with no
    GM session connected (or genuinely LM-native rules) still get counted,
    tagged with the appropriate origin.
    """
    rows = []
    gm_sessions = [s for s in all_sessions if s.role == ROLE_GM]
    lm_sessions = [s for s in all_sessions if s.role == ROLE_LM]

    # Tags/VMs are LM-local objects -- find the VM on whichever LM has it.
    found_vm = None
    for nsx in lm_sessions:
        try:
            hits = nsx.find_vms(needle)
            if hits:
                found_vm = (nsx, hits[0])
                break
        except NsxError:
            continue
    if not found_vm:
        say("  No VM matching '{}' on any Local Manager.".format(needle))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return

    nsx_lm, vm = found_vm
    vname = vm.get(F_DISPLAY_NAME, "?")
    ext_id = vm.get(F_EXTERNAL_ID)
    say("\n  VM      : {}".format(cB(vname)))
    say("  Found on: {}  (Local Manager)".format(cC(nsx_lm.name)))
    say("  tags    : {}".format(fmt_tags(tags_of(vm))))
    if not ext_id:
        say("  {} -- cannot resolve group associations.".format(
            cBR("VM has no external_id")))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return

    # --- Group membership: reverse-association lookup, any member type ---
    section("Group Membership (any member type)")
    matched = {}   # group_id -> (path, display_name, origin)
    with Spinner("Association lookup on {}".format(nsx_lm.name)):
        try:
            assocs = _collect_associations(nsx_lm, domain, ext_id)
        except NsxError as e:
            err("association lookup on {} failed: {}".format(nsx_lm.name, e))
            assocs = []
    for a in assocs:
        gpath = a.get(F_PATH, "")
        gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
        matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                        origin_of_path(gpath))

    # Best-effort supplementary check on any connected GM -- catches the rare
    # case of a Global Group not yet realized onto this specific LM.
    # Non-fatal: GM doesn't hold VM inventory, so this may simply 404.
    for nsx_gm in gm_sessions:
        try:
            g_assocs = _collect_associations(nsx_gm, domain, ext_id)
        except NsxError:
            continue
        for a in g_assocs:
            gpath = a.get(F_PATH, "")
            gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
            if gid in matched:
                continue
            matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                            origin_of_path(gpath))

    if not matched:
        say("  {}".format(cD("Not a member of any group on any manager.")))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return
    for gid, (_gpath, gname, origin) in sorted(matched.items(),
                                              key=lambda kv: kv[1][1].lower()):
        say("    [{}]  {}  {}".format(
            cC("GM") if origin == "GM" else cD("LM"), cB(gname), cD("id=" + gid)))

    group_paths = ({gp for gp, _, _ in matched.values() if gp}
                   | set(matched.keys()))
    group_lookup = {gid: gname for gid, (_, gname, _) in matched.items()}

    # --- DFW rules: GM scanned first, then LM, deduped by rule path ---
    section("DFW Rules Referencing These Groups")
    say("  Scanning {} GM + {} LM ({}) ...".format(
        len(gm_sessions), len(lm_sessions), cD("deduped by rule path")))
    seen_rule_paths, hit_count = set(), 0
    for nsx in gm_sessions + lm_sessions:
        try:
            base = nsx.base(domain)
        except NsxError:
            continue
        with Spinner("Policies on {}".format(nsx.name)):
            try:
                policies = nsx.get_all(p_sec_policies(base, domain))
            except NsxError:
                continue
        for pol, rule in _fetch_rules(nsx, domain, policies):
            pid = pol.get(F_ID, "?")
            rpath = rule.get(F_PATH, "")
            refs = set(rule.get(F_SOURCE_GROUPS, [])
                       + rule.get(F_DEST_GROUPS, [])
                       + rule.get(F_SCOPE, []))
            hits = refs & group_paths
            if not hits:
                continue
            if rpath:
                if rpath in seen_rule_paths:
                    continue   # already reported via GM (or an earlier LM)
                seen_rule_paths.add(rpath)
            hit_count += 1
            dirs = []
            if set(rule.get(F_SOURCE_GROUPS, [])) & group_paths:
                dirs.append("source")
            if set(rule.get(F_DEST_GROUPS, [])) & group_paths:
                dirs.append("dest")
            if set(rule.get(F_SCOPE, [])) & group_paths:
                dirs.append("applied_to")
            act = rule.get(F_ACTION_FIELD, "?")
            colour = cG if act == "ALLOW" else cR
            role_lbl = ROLE_LABEL.get(nsx.role, "?")
            if nsx.role == ROLE_GM:
                rule_origin = "GM"
            else:
                rule_origin = origin_of_path(rpath)
                if rule_origin == "GM" and not gm_sessions:
                    rule_origin = "GM (via LM)"
            say("    [{} / {} / {}]  {} / {}   {}   {}".format(
                cC(nsx.name), cD(role_lbl), cD(rule_origin),
                cB(pol.get(F_DISPLAY_NAME, pid)), rule.get(F_DISPLAY_NAME, "?"),
                colour(act), cC(", ".join(dirs))))
            for gpath in hits:
                gi = group_id_from_path(gpath)
                _, _, gorigin = matched.get(gi, (None, None, "?"))
                rows.append([vname, nsx.name, role_lbl, gi,
                             group_lookup.get(gi, gi), gorigin, pid,
                             rule.get(F_ID, "?"), rule_origin, act,
                             ", ".join(dirs)])
    if hit_count == 0:
        say("  {} reference these groups on any manager.".format(cG("No DFW rules")))
    hr()
    exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
