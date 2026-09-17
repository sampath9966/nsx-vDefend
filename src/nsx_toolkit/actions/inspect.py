"""Reading rules, policies and services.

The read side of what authoring can already write. Until this existed you
could create, edit, move and delete a rule but not look at one, which made
`nsxctl rule create` an act of faith.

Everything here is a view over machinery that already exists -- `sweep_rules`
for the deduplicated GM/LM rule set, `service_inventory` for service
definitions -- so a rule listed here is exactly the rule hygiene reports on
and trace evaluates, in the same evaluation order.
"""

import ipaddress

from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_CATEGORY,
    F_DEST_GROUPS,
    F_DESTINATION_PORTS,
    F_DIRECTION,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_ID,
    F_IP_ADDRESSES,
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
    RT_CONDITION,
    RT_CONJUNCTION,
    RT_IPADDRESS,
    RT_L4_PORTSET,
    RT_NESTED,
    RT_PATHEXPR,
    category_rank,
    group_id_from_path,
    origin_of_path,
    p_group,
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
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cG,
    cR,
    cY,
    err,
    hr,
    more_note,
    parallel_run,
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


# ── rule search ──────────────────────────────────────────────────────────────

RULE_SEARCH_HEADERS = ["manager", "origin", "policy", "rule", "action",
                       "direction", "source_match", "dest_match"]

# Match verdicts (higher = more certain)
_MATCH_NONE = 0
_MATCH_POSSIBLE = 1   # tag/condition-based group; can't evaluate statically
_MATCH_ANY = 2        # ANY wildcard — always matches
_MATCH_EXACT = 3      # confirmed via IPAddressExpression


def _net(cidr):
    """Parse CIDR or host IP; return ip_network or None."""
    try:
        return ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None


def _ip_in_entries(query_net, entries):
    """Check whether query_net is covered by any IPAddressExpression in entries."""
    for entry in entries or []:
        if entry.get(RT) != RT_IPADDRESS:
            continue
        for addr in entry.get(F_IP_ADDRESSES) or []:
            candidate = _net(addr)
            if candidate is None:
                continue
            try:
                if query_net.subnet_of(candidate) or candidate.subnet_of(query_net):
                    return True
            except TypeError:
                # mixed v4/v6
                pass
    return False


def _group_match_basis(query_net, expression):
    """Return (_MATCH_EXACT | _MATCH_POSSIBLE | _MATCH_NONE) for a group expression."""
    if not expression:
        return _MATCH_NONE
    # Flatten nested and conjunction types to a single list of leaf entries.
    leaves = []
    queue = list(expression) if isinstance(expression, list) else [expression]
    while queue:
        item = queue.pop()
        if not isinstance(item, dict):
            continue
        rt = item.get(RT, "")
        if rt in (RT_CONJUNCTION, RT_NESTED):
            queue.extend(item.get(F_EXPRESSION) or [])
        else:
            leaves.append(item)

    has_ip = any(e.get(RT) == RT_IPADDRESS for e in leaves)
    has_condition = any(e.get(RT) in (RT_CONDITION, RT_PATHEXPR) for e in leaves)

    if has_ip and _ip_in_entries(query_net, leaves):
        return _MATCH_EXACT
    if has_condition or (has_ip and not _ip_in_entries(query_net, leaves)):
        # Tag/segment-based groups may still match the IP at runtime.
        return _MATCH_POSSIBLE if has_condition else _MATCH_NONE
    return _MATCH_NONE


def _build_group_index(sessions, domain, group_paths):
    """Map group_path -> match basis for as many groups as we can fetch."""
    # Build (nsx, gpath) work items — one per (session, unresolved path).
    # We stop trying a path as soon as any session resolves it, so we avoid
    # duplicate fetches when GM and LM both know the same group.
    work = []
    resolved = set()
    for nsx in sessions:
        for gpath in group_paths:
            gid = group_id_from_path(gpath)
            if gid and gpath not in resolved:
                work.append((nsx, gpath, gid))

    def fetch(item):
        nsx, gpath, gid = item
        return nsx.get(p_group(nsx.base(domain), domain, gid))

    results = parallel_run(
        work,
        fetch,
        label="Fetching groups",
        key=lambda item: (item[0].name, item[1]),
    )

    index = {}
    for (_sname, gpath), value in results.items():
        if not isinstance(value, Exception) and gpath not in index:
            index[gpath] = value.get(F_EXPRESSION)
    return index


def _refs_match(paths, query_net, group_expr_index, certain_only):
    """Best match verdict for a list of group paths."""
    values = [p for p in (paths or []) if p]
    if not values or values == [ANY]:
        return _MATCH_ANY, "ANY"
    best = _MATCH_NONE
    best_label = ""
    for path in values:
        expr = group_expr_index.get(path)
        basis = _group_match_basis(query_net, expr)
        if expr is None and not certain_only:
            basis = max(basis, _MATCH_POSSIBLE)
        if basis > best:
            best = basis
            gid = group_id_from_path(path) or path
            if basis == _MATCH_EXACT:
                best_label = "exact: {}".format(gid)
            elif basis == _MATCH_POSSIBLE:
                best_label = "possible: {}".format(gid)
    return best, best_label


def act_rule_search(sessions, domain, exporter, ip, certain_only=False,
                    policy_ref=None, cache_key=None):
    """Find DFW rules whose source or destination groups could apply to an IP."""
    section("RULE SEARCH")
    query_net = _net(ip)
    if query_net is None:
        err("  Not a valid IP or CIDR: '{}'".format(ip))
        exporter.stage("rule_search", RULE_SEARCH_HEADERS, [])
        return []

    say("  Searching for rules that could apply to {}".format(cB(str(query_net))))
    if certain_only:
        say("  {}".format(cD("(--certain: hiding 'possible' matches)")))
    hr()

    records = evaluation_order(sweep_rules(sessions, domain))
    policy_needle = (policy_ref or "").lower() or None
    if policy_needle:
        records = [r for r in records
                   if policy_needle in "{} {}".format(
                       r.policy_name, r.policy_id).lower()]

    # Collect all unique group paths referenced by any candidate rule.
    all_paths = set()
    for record in records:
        for path in (record.rule.get(F_SOURCE_GROUPS) or []):
            if path and path != ANY:
                all_paths.add(path)
        for path in (record.rule.get(F_DEST_GROUPS) or []):
            if path and path != ANY:
                all_paths.add(path)

    group_expr_index = _build_group_index(sessions, domain, all_paths)

    rows = []
    display_rows = []
    for record in records:
        rule = record.rule
        src_basis, src_label = _refs_match(
            rule.get(F_SOURCE_GROUPS), query_net, group_expr_index, certain_only)
        dst_basis, dst_label = _refs_match(
            rule.get(F_DEST_GROUPS), query_net, group_expr_index, certain_only)

        # A rule matches when either direction hits.
        direction = str(rule.get(F_DIRECTION, "IN_OUT")).upper()
        if direction == "IN":
            # only destination matters for inbound
            effective = dst_basis
        elif direction == "OUT":
            effective = src_basis
        else:
            effective = max(src_basis, dst_basis)

        if effective == _MATCH_NONE:
            continue
        # --certain: hide any rule where either side is merely "possible"
        if certain_only and (src_basis == _MATCH_POSSIBLE
                             or dst_basis == _MATCH_POSSIBLE):
            continue

        action = str(rule.get(F_ACTION_FIELD, "?"))
        rows.append([record.nsx.name, record.origin, record.policy_name,
                     record.rule_name, action, direction,
                     src_label or "-", dst_label or "-"])
        src_colour = (cBG if src_basis == _MATCH_EXACT
                      else (cBY if src_basis == _MATCH_ANY else cD))
        dst_colour = (cBG if dst_basis == _MATCH_EXACT
                      else (cBY if dst_basis == _MATCH_ANY else cD))
        display_rows.append([
            _rule_action_colour(action)(action),
            cB(record.rule_name),
            record.policy_name,
            src_colour(src_label or "-"),
            dst_colour(dst_label or "-"),
            cD(direction),
        ])

    say("  {} rule(s) could apply to {}{}".format(
        cC(str(len(rows))), cB(str(query_net)),
        cD("  (exact + possible)") if not certain_only else ""))
    if not rows:
        say("  {}".format(cD("(no matches)")))
        exporter.stage("rule_search", RULE_SEARCH_HEADERS, [])
        return []

    table(["Action", "Rule", "Policy", "Source match", "Dest match", "Dir"],
          display_rows, indent=4)
    hr()
    say("  {}  {}".format(
        cD("legend:"),
        cD("exact = IP in group's IPAddressExpression  |  "
           "possible = tag/segment-based (check at runtime)")))
    say("  {}  {}".format(
        cD("next:"),
        cC("nsxctl trace VM_A VM_B --port N   # confirm what actually decides")))

    remember_names(KIND_RULE, [r.rule_name for r in records]
                   + [r.rule_id for r in records], cache_key)
    exporter.stage("rule_search", RULE_SEARCH_HEADERS, rows)
    return rows
