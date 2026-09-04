"""Reading rules, policies and services.

The read side of what authoring can already write. Until this existed you
could create, edit, move and delete a rule but not look at one, which made
`nsxctl rule create` an act of faith.

Everything here is a view over machinery that already exists -- `sweep_rules`
for the deduplicated GM/LM rule set, `service_inventory` for service
definitions -- so a rule listed here is exactly the rule hygiene reports on
and trace evaluates, in the same evaluation order.
"""

from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_CATEGORY,
    F_DEST_GROUPS,
    F_DESTINATION_PORTS,
    F_DIRECTION,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_ID,
    F_L4_PROTOCOL,
    F_LOGGED,
    F_PATH,
    F_RULE_ID,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SERVICE_ENTRIES,
    F_SERVICES,
    F_SOURCE_GROUPS,
    RT,
    RT_L4_PORTSET,
    category_rank,
    group_id_from_path,
    origin_of_path,
)
from ..authoring import service_inventory
from ..namecache import (
    KIND_POLICY,
    KIND_RULE,
    KIND_SERVICE,
    update_cache,
)
from ..output import (
    cB,
    cBR,
    cC,
    cD,
    cG,
    cR,
    cY,
    hr,
    more_note,
    say,
    section,
    table,
)
from ..policy import ordered_sessions, policies_for, sweep_rules
from ..trace import evaluation_order
from .author import find_rule

RULE_HEADERS = ["manager", "origin", "category", "policy", "seq", "rule",
                "action", "direction", "source", "destination", "service",
                "applied_to", "state", "rule_id"]
POLICY_HEADERS = ["manager", "origin", "category", "seq", "id", "name",
                  "rules", "applied_to"]
SERVICE_HEADERS = ["id", "name", "protocol", "ports", "kind"]

LIST_CONSOLE_LIMIT = 60


def _short_refs(paths, limit=2):
    """Group paths as short ids, because a full NSX path is 60 characters of
    prefix and 8 of meaning."""
    values = [p for p in (paths or []) if p]
    if not values or values == [ANY]:
        return ANY
    names = [group_id_from_path(p) for p in values]
    if len(names) <= limit:
        return ", ".join(names)
    return "{}, +{}".format(", ".join(names[:limit]), len(names) - limit)


def _state(rule):
    return "disabled" if rule.get(F_DISABLED) else "enabled"


def _rule_action_colour(action):
    return {"ALLOW": cG, "DROP": cR, "REJECT": cR}.get(action, cY)


def rule_row(record):
    rule = record.rule
    return [record.nsx.name, record.origin,
            str(record.policy.get(F_CATEGORY, "")),
            record.policy_name, str(rule.get(F_SEQUENCE_NUMBER, "")),
            record.rule_name, rule.get(F_ACTION_FIELD, "?"),
            rule.get(F_DIRECTION, ""),
            _short_refs(rule.get(F_SOURCE_GROUPS)),
            _short_refs(rule.get(F_DEST_GROUPS)),
            _short_refs(rule.get(F_SERVICES)),
            _short_refs(rule.get(F_SCOPE)),
            _state(rule), str(rule.get(F_RULE_ID, ""))]


def _matches(record, needle, policy_ref, action, disabled_only):
    if needle and needle not in "{} {}".format(
            record.rule_name, record.rule_id).lower():
        return False
    if policy_ref and policy_ref not in "{} {}".format(
            record.policy_name, record.policy_id).lower():
        return False
    if action and str(record.rule.get(F_ACTION_FIELD, "")).upper() != action:
        return False
    if disabled_only and not record.rule.get(F_DISABLED):
        return False
    return True


def remember_names(kind, values, cache_key=None):
    """Refresh part of the completion cache, never fatally.

    A listing that succeeded must not fail because a cache file could not be
    written -- the user asked for a list, not for a cache.
    """
    if not cache_key:
        return
    try:
        update_cache(kind, values, *cache_key)
    except Exception:  # noqa: BLE001 - never break a read over a cache write
        pass


def act_rule_list(sessions, domain, exporter, contains=None, policy_ref=None,
                  action=None, disabled_only=False, cache_key=None):
    """Every DFW rule, in NSX evaluation order.

    Evaluation order rather than fetch order, because the order rules are
    listed in is the order they decide traffic in -- and a listing sorted any
    other way invites exactly the mistake `nsxctl trace` exists to catch.
    """
    section("DFW RULES")
    records = evaluation_order(sweep_rules(sessions, domain))
    needle = (contains or "").lower() or None
    policy_needle = (policy_ref or "").lower() or None
    wanted_action = (action or "").upper() or None
    hits = [r for r in records
            if _matches(r, needle, policy_needle, wanted_action, disabled_only)]

    say("  {} rule(s) across {} manager(s){}".format(
        cC(str(len(hits))), len(sessions),
        "" if len(hits) == len(records)
        else cD("  ({} total before filtering)".format(len(records)))))
    say("  {}".format(cD("listed in NSX evaluation order: category, then "
                         "policy and rule sequence")))
    hr()

    rows = [rule_row(r) for r in hits]
    exporter.stage("rules", RULE_HEADERS, rows)
    # Keep TAB completion warm off work somebody was doing anyway.
    remember_names(KIND_RULE, [r.rule_name for r in records]
                   + [r.rule_id for r in records], cache_key)
    remember_names(KIND_POLICY, [r.policy_name for r in records]
                   + [r.policy_id for r in records], cache_key)
    if not hits:
        say("  {}".format(cD("(nothing matches)")))
        return rows

    current = None
    shown = 0
    for record in hits:
        if shown >= LIST_CONSOLE_LIMIT:
            break
        key = (record.nsx.name, record.policy_id)
        if key != current:
            current = key
            category = record.policy.get(F_CATEGORY)
            say("\n  {}{}   [{}/{}]".format(
                cB(record.policy_name),
                cD("  ({})".format(category)) if category else "",
                cC(record.nsx.name), cD(record.origin)))
        rule = record.rule
        flag = cD("  [disabled]") if rule.get(F_DISABLED) else ""
        say("    {:>5}  {:26s} {:7s} {} -> {}   svc {}   applied {}{}".format(
            str(rule.get(F_SEQUENCE_NUMBER, "")),
            str(record.rule_name)[:26],
            _rule_action_colour(rule.get(F_ACTION_FIELD))(
                str(rule.get(F_ACTION_FIELD, "?"))),
            _short_refs(rule.get(F_SOURCE_GROUPS)),
            _short_refs(rule.get(F_DEST_GROUPS)),
            _short_refs(rule.get(F_SERVICES)),
            _short_refs(rule.get(F_SCOPE)), flag))
        shown += 1
    more_note(LIST_CONSOLE_LIMIT, len(hits))
    hr()
    return rows


def act_rule_show(sessions, domain, exporter, ref, policy_ref=None):
    """One rule in full, with every field spelled out rather than shortened."""
    section("RULE")
    record = find_rule(sessions, domain, ref, policy_ref=policy_ref)
    rule = record.rule
    say("  {}   {}".format(cB(record.rule_name),
                           cD(rule.get(F_ID, ""))))
    say("  policy      : {}  {}".format(
        record.policy_name, cD("({})".format(
            record.policy.get(F_CATEGORY, "?")))))
    say("  manager     : {}  [{}]".format(cC(record.nsx.name), record.origin))
    hr()
    for label, value in (
            ("action", _rule_action_colour(rule.get(F_ACTION_FIELD))(
                str(rule.get(F_ACTION_FIELD, "?")))),
            ("direction", rule.get(F_DIRECTION, "")),
            ("sequence", rule.get(F_SEQUENCE_NUMBER, "")),
            ("state", _state(rule)),
            ("logged", "yes" if rule.get(F_LOGGED) else "no"),
            ("realized id", rule.get(F_RULE_ID, "")),
            ("path", cD(record.path))):
        say("    {:12s}: {}".format(label, value))
    for label, field in (("source", F_SOURCE_GROUPS),
                         ("destination", F_DEST_GROUPS),
                         ("services", F_SERVICES),
                         ("applied to", F_SCOPE)):
        values = [v for v in (rule.get(field) or []) if v] or [ANY]
        say("    {:12s}: {}".format(label, values[0]))
        for extra in values[1:]:
            say("    {:12s}  {}".format("", extra))
    if rule.get("description"):
        say("    {:12s}: {}".format("description", rule["description"]))
    hr()
    say("  {} {}".format(cD("next:"), cC(
        "nsxctl trace VM_A VM_B --port N   # does this rule actually decide "
        "a flow?")))
    rows = [rule_row(record)]
    exporter.stage("rule", RULE_HEADERS, rows)
    return rows


def act_policy_list(sessions, domain, exporter, contains=None,
                    cache_key=None):
    """Security policies, in evaluation order, with their rule counts."""
    section("SECURITY POLICIES")
    records = sweep_rules(sessions, domain)
    counts = {}
    for record in records:
        counts[(record.nsx.name, record.policy_id)] = counts.get(
            (record.nsx.name, record.policy_id), 0) + 1

    gm_sessions, lm_sessions = ordered_sessions(sessions)
    needle = (contains or "").lower()
    seen = set()
    rows = []
    for nsx in gm_sessions + lm_sessions:
        for policy in policies_for(nsx, domain):
            path = policy.get(F_PATH, "")
            if path and path in seen:
                continue
            if path:
                seen.add(path)
            pid = policy.get(F_ID, "?")
            name = policy.get(F_DISPLAY_NAME, pid)
            if needle and needle not in "{} {}".format(name, pid).lower():
                continue
            rows.append([nsx.name, origin_of_path(path),
                         str(policy.get(F_CATEGORY, "")),
                         str(policy.get(F_SEQUENCE_NUMBER, "")),
                         pid, name, str(counts.get((nsx.name, pid), 0)),
                         _short_refs(policy.get(F_SCOPE))])

    rows.sort(key=lambda r: (category_rank(r[2]), r[3], r[5]))
    say("  {} policy(ies) across {} manager(s)".format(
        cC(str(len(rows))), len(sessions)))
    hr()
    table(["Manager", "Origin", "Category", "Seq", "Id", "Name", "Rules",
           "Applied to"],
          [[cC(r[0]), cD(r[1]), r[2], r[3], cB(r[4]), r[5], r[6], r[7]]
           for r in rows[:LIST_CONSOLE_LIMIT]], indent=4)
    more_note(LIST_CONSOLE_LIMIT, len(rows))
    exporter.stage("policies", POLICY_HEADERS, rows)
    remember_names(KIND_POLICY, [r[4] for r in rows] + [r[5] for r in rows],
                   cache_key)
    return rows


def describe_service(service):
    """(protocol, ports, kind) for one service definition.

    `kind` is what the port matcher in trace.py can do with it: an L4 port set
    reduces to a port comparison, anything else does not, and saying so here
    is what makes an undecided trace verdict explicable rather than mystifying.
    """
    entries = service.get(F_SERVICE_ENTRIES) or []
    if not entries:
        return "", "", "empty"
    protocols, ports, kinds = [], [], []
    for entry in entries:
        kind = entry.get(RT, "?")
        kinds.append(str(kind).replace("ServiceEntry", ""))
        if kind != RT_L4_PORTSET:
            continue
        protocols.append(str(entry.get(F_L4_PROTOCOL, "")))
        ports.extend(str(p) for p in (entry.get(F_DESTINATION_PORTS) or []))
    l4 = all(e.get(RT) == RT_L4_PORTSET for e in entries)
    return (",".join(sorted({p for p in protocols if p})),
            ",".join(ports) or ("any" if l4 else ""),
            "L4 port set" if l4 else "/".join(sorted(set(kinds))))


def act_service_list(sessions, domain, exporter, contains=None,
                     cache_key=None):
    """Service definitions, and whether each is one trace can decide."""
    section("SERVICES")
    services = service_inventory(sessions, domain)
    needle = (contains or "").lower()
    rows = []
    for path, service in sorted(services.items()):
        sid = service.get(F_ID, path)
        name = service.get(F_DISPLAY_NAME, sid)
        if needle and needle not in "{} {}".format(name, sid).lower():
            continue
        protocol, ports, kind = describe_service(service)
        rows.append([sid, name, protocol, ports, kind])

    say("  {} service(s)".format(cC(str(len(rows)))))
    hr()
    table(["Id", "Name", "Protocol", "Ports", "Kind"],
          [[cB(r[0]), r[1], r[2], r[3],
            r[4] if r[4] == "L4 port set" else cY(r[4])]
           for r in rows[:LIST_CONSOLE_LIMIT]], indent=4)
    more_note(LIST_CONSOLE_LIMIT, len(rows))
    not_l4 = sum(1 for r in rows if r[4] != "L4 port set")
    if not_l4:
        say("\n  {} {} service(s) are not plain L4 port sets, so "
            "`nsxctl trace`".format(cD("note:"), not_l4))
        say("  {}".format(cD(
            "reports a rule limited to one of them as undecided rather than "
            "guessing.")))
    exporter.stage("services", SERVICE_HEADERS, rows)
    remember_names(KIND_SERVICE, [r[0] for r in rows] + [r[1] for r in rows],
                   cache_key)
    return rows


def act_service_show(sessions, domain, exporter, ref):
    section("SERVICE")
    services = service_inventory(sessions, domain)
    needle = str(ref).strip().lower()
    hits = [s for s in services.values()
            if needle in (str(s.get(F_ID, "")).lower(),
                          str(s.get(F_DISPLAY_NAME, "")).lower())]
    if not hits:
        say("  {} no service called '{}'.".format(cBR("Not found:"), ref))
        exporter.stage("service", SERVICE_HEADERS, [])
        return []
    service = hits[0]
    protocol, ports, kind = describe_service(service)
    say("  {}   {}".format(cB(service.get(F_DISPLAY_NAME, ref)),
                           cD(service.get(F_ID, ""))))
    say("  path        : {}".format(cD(service.get(F_PATH, ""))))
    say("  kind        : {}".format(kind))
    hr()
    for entry in (service.get(F_SERVICE_ENTRIES) or []):
        say("    {}".format(cB(str(entry.get(RT, "?")))))
        for key in sorted(entry):
            if key in (RT, F_ID, F_DISPLAY_NAME, F_PATH) or key.startswith("_"):
                continue
            say("      {:20s} {}".format(key, entry[key]))
    if kind != "L4 port set":
        say("\n  {}".format(cD(
            "Not a plain L4 port set, so `nsxctl trace` cannot decide whether "
            "a rule limited to this service matches a given port.")))
    rows = [[service.get(F_ID, ""), service.get(F_DISPLAY_NAME, ""),
             protocol, ports, kind]]
    exporter.stage("service", SERVICE_HEADERS, rows)
    return rows
