"""Gateway Firewall (GFW): policy list, rule list, hygiene."""
from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_CATEGORY,
    F_DEST_GROUPS,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_ID,
    F_LOGGED,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SERVICES,
    F_SOURCE_GROUPS,
)
from ..output import cBG, cBR, cD, parallel_run, say, section, table

GW_POLICY_HEADERS = ["manager", "id", "name", "category", "seq", "rules", "applied_to"]
GW_RULE_HEADERS   = ["manager", "policy", "seq", "rule", "action",
                     "source", "destination", "service", "state"]
GW_HYGIENE_HEADERS = ["manager", "policy", "rule", "finding"]


def _shorten_groups(groups):
    if not groups or groups == [ANY]:
        return ANY
    return ", ".join(g.rsplit("/", 1)[-1] for g in groups)


def _shorten_services(services):
    if not services or services == [ANY]:
        return ANY
    return ", ".join(s.rsplit("/", 1)[-1] for s in services)


def act_gw_policy_list(sessions, domain, exporter, contains=None):
    """List gateway policies across all managers."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_gw_policies(domain),
        label="Fetching gateway policies",
    )
    # Collect (session, policy_id) pairs that pass the name filter so we can
    # fetch all rules for all policies in parallel rather than serially.
    pol_map = {}  # (s.name, pid) -> (s, pol)
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for pol in (result or []):
            name = pol.get(F_DISPLAY_NAME, pol.get(F_ID, ""))
            if contains and contains.lower() not in name.lower():
                continue
            pol_map[(s.name, pol.get(F_ID, ""))] = (s, pol)

    rules_fetched = parallel_run(
        list(pol_map.items()),
        lambda item: item[1][0].get_gw_rules(item[0][1], domain),
        label="Fetching gateway rules",
        key=lambda item: item[0],
    )

    rows = []
    for (sname, pid), (s, pol) in pol_map.items():
        rules = rules_fetched.get((sname, pid))
        if isinstance(rules, Exception):
            rules = []
        name = pol.get(F_DISPLAY_NAME, pol.get(F_ID, ""))
        scope_parts = [
            g.rsplit("/", 1)[-1]
            for g in (pol.get(F_SCOPE) or [])
            if g != ANY
        ]
        rows.append([
            s.name,
            pid,
            name,
            pol.get(F_CATEGORY, ""),
            str(pol.get(F_SEQUENCE_NUMBER, "")),
            str(len(rules)),
            ", ".join(scope_parts) or ANY,
        ])
    section("Gateway policies ({})".format(len(rows)))
    if rows:
        table(GW_POLICY_HEADERS, rows)
    else:
        say("  No gateway policies found.")
    exporter.stage("gw_policies", GW_POLICY_HEADERS, rows)


def act_gw_rule_list(sessions, domain, exporter, policy=None,
                     contains=None, action=None, disabled_only=False):
    """List gateway firewall rules across all managers."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_gw_policies(domain),
        label="Fetching gateway policies",
    )
    pol_map = {}  # (s.name, pid) -> (s, pname)
    for s in sessions:
        policies = fetched.get(s.name)
        if isinstance(policies, Exception) or not policies:
            continue
        for pol in policies:
            pname = pol.get(F_DISPLAY_NAME, pol.get(F_ID, ""))
            if policy and policy.lower() not in pname.lower():
                continue
            pol_map[(s.name, pol.get(F_ID, ""))] = (s, pname)

    rules_fetched = parallel_run(
        list(pol_map.items()),
        lambda item: item[1][0].get_gw_rules(item[0][1], domain),
        label="Fetching gateway rules",
        key=lambda item: item[0],
    )

    all_rows = []
    for (sname, pid), (s, pname) in pol_map.items():
        rules = rules_fetched.get((sname, pid))
        if isinstance(rules, Exception) or not rules:
            continue
        for rule in rules:
                rname = rule.get(F_DISPLAY_NAME, rule.get(F_ID, ""))
                if contains and contains.lower() not in rname.lower():
                    continue
                act = rule.get(F_ACTION_FIELD, "")
                if action and action.upper() != act.upper():
                    continue
                disabled = rule.get(F_DISABLED, False)
                if disabled_only and not disabled:
                    continue
                act_display = cBG(act) if act == "ALLOW" else cBR(act)
                state = cBR("DISABLED") if disabled else cD("enabled")
                all_rows.append([
                    s.name,
                    pname,
                    str(rule.get(F_SEQUENCE_NUMBER, "")),
                    rname,
                    act_display,
                    _shorten_groups(rule.get(F_SOURCE_GROUPS) or []),
                    _shorten_groups(rule.get(F_DEST_GROUPS) or []),
                    _shorten_services(rule.get(F_SERVICES) or []),
                    state,
                ])
    section("Gateway rules ({})".format(len(all_rows)))
    if all_rows:
        table(GW_RULE_HEADERS, all_rows)
    else:
        say("  No gateway rules found.")
    plain = [
        r[:4] + [r[4].strip("\x1b[0m").strip()] + r[5:8]
        + [r[8].strip("\x1b[0m").strip()]
        for r in all_rows
    ]
    exporter.stage("gw_rules", GW_RULE_HEADERS, plain)


def act_gw_hygiene(sessions, domain, exporter):
    """Gateway firewall hygiene: any-any-allow, disabled rules, drop-not-logged."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_gw_policies(domain),
        label="Fetching gateway policies",
    )
    pol_map = {}  # (s.name, pid) -> (s, pname)
    for s in sessions:
        policies = fetched.get(s.name)
        if isinstance(policies, Exception) or not policies:
            continue
        for pol in policies:
            pid = pol.get(F_ID, "")
            pol_map[(s.name, pid)] = (s, pol.get(F_DISPLAY_NAME, pid))

    rules_fetched = parallel_run(
        list(pol_map.items()),
        lambda item: item[1][0].get_gw_rules(item[0][1], domain),
        label="Fetching gateway rules",
        key=lambda item: item[0],
    )

    findings = []
    for (sname, pid), (s, pname) in pol_map.items():
        rules = rules_fetched.get((sname, pid))
        if isinstance(rules, Exception) or not rules:
            continue
        for rule in rules:
                rname = rule.get(F_DISPLAY_NAME, rule.get(F_ID, ""))
                act = rule.get(F_ACTION_FIELD, "")
                src = rule.get(F_SOURCE_GROUPS, [])
                dst = rule.get(F_DEST_GROUPS, [])
                disabled = rule.get(F_DISABLED, False)
                logged = rule.get(F_LOGGED, True)
                if disabled:
                    findings.append([s.name, pname, rname, "disabled-rule"])
                if src == [ANY] and dst == [ANY] and act == "ALLOW":
                    findings.append([s.name, pname, rname, "any-any-allow"])
                if act in ("DROP", "REJECT") and not logged:
                    findings.append([s.name, pname, rname, "drop-not-logged"])
    section("Gateway hygiene ({} findings)".format(len(findings)))
    if findings:
        table(GW_HYGIENE_HEADERS, findings)
    else:
        say("  No issues found.")
    exporter.stage("gw_hygiene", GW_HYGIENE_HEADERS, findings)
