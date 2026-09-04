"""DFW rule hygiene: the "is my policy sane" report.

Design rule that shapes everything here: **a report that cries wolf gets
ignored**, which defeats the point of having one. So every finding is either
provable from the data, or explicitly marked soft with the reason stated in
the output. Two places where the obvious implementation would lie:

  * Hit counters are cumulative since the last reset (manager reboot, rule
    edit, manual reset). A single read cannot prove "no traffic in 30 days",
    so the single-read finding says "no hits since counters last reset" and
    is marked soft. `nsxctl rule baseline` is what produces real evidence.

  * `/members/virtual-machines` returns nothing for groups matched on VIF,
    IPAddress, Segment or SegmentPort criteria -- the caveat documented in
    act_reverse_lookup. Counting members there would report live IP-set
    groups as empty, so member counts run only for groups whose criteria is
    VM-resolvable and everything else reports "not measurable", never
    "empty".

Shadow detection is deliberately conservative: no port or CIDR arithmetic, so
it cannot produce a false "this rule is unreachable". Service definitions are
compared as opaque paths.
"""

from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_DIRECTION,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_EXPRESSIONS,
    F_HIT_COUNT,
    F_ID,
    F_LAST_UPDATE,
    F_LOGGED,
    F_MEMBER_TYPE,
    F_RESULTS,
    F_RULE_PATH,
    F_SCOPE,
    F_SERVICES,
    F_STATISTICS,
    RT,
    RT_CONDITION,
    RT_CONJUNCTION,
    RT_EXTERNALID,
    RT_NESTED,
    p_group_members,
    p_policy_stats,
)
from ..output import (
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cY,
    debug,
    hr,
    more_note,
    parallel_run,
    say,
    section,
    table,
)
from ..policy import (
    group_inventory,
    is_wildcard,
    listed_values,
    rule_sequence,
    sweep_rules,
)

HYGIENE_CONSOLE_LIMIT = 40

SEVERITIES = ("critical", "high", "medium", "low")

HYGIENE_HEADERS = ["severity", "check", "confidence", "manager", "origin",
                   "policy", "rule", "action", "detail"]

TERMINAL_ACTIONS = ("ALLOW", "DROP", "REJECT")
DENY_ACTIONS = ("DROP", "REJECT")


class Finding:
    __slots__ = ("check", "severity", "confidence", "record", "detail")

    def __init__(self, check, severity, record, detail, confidence="provable"):
        self.check = check
        self.severity = severity
        self.record = record
        self.detail = detail
        self.confidence = confidence

    def row(self):
        rule = self.record.rule
        return [self.severity, self.check, self.confidence,
                self.record.nsx.name, self.record.origin,
                self.record.policy_name, self.record.rule_name,
                rule.get(F_ACTION_FIELD, "?"), self.detail]


# === RULE SHAPE HELPERS ===
def match_key(rule):
    """What makes two rules equivalent, without expanding services.

    Service definitions are compared as opaque paths on purpose: expanding
    them into port ranges is where a shadow analysis starts producing false
    "unreachable" claims.
    """
    return (
        tuple(sorted(listed_values(rule, "source_groups"))),
        tuple(sorted(listed_values(rule, "destination_groups"))),
        tuple(sorted(listed_values(rule, F_SERVICES))),
        tuple(sorted(listed_values(rule, F_SCOPE))),
        rule.get(F_ACTION_FIELD, ""),
        rule.get(F_DIRECTION, ""),
    )


def matches_everything(rule):
    """True when this rule matches all traffic in its policy."""
    return (is_wildcard(listed_values(rule, "source_groups"))
            and is_wildcard(listed_values(rule, "destination_groups"))
            and is_wildcard(listed_values(rule, F_SERVICES))
            and is_wildcard(listed_values(rule, F_SCOPE))
            and rule.get(F_ACTION_FIELD) in TERMINAL_ACTIONS
            and not rule.get(F_DISABLED))


def vm_resolvable(group):
    """Whether a group's criteria can be measured through the VM member API.

    Conservative by design: anything we cannot positively identify as
    VM-resolvable is reported as not measurable rather than guessed at.
    """
    expression = group.get(F_EXPRESSION) or []
    if not expression:
        return False
    for item in expression:
        kind = item.get(RT)
        if kind == RT_CONJUNCTION:
            continue
        if kind == RT_EXTERNALID:
            continue
        if kind == RT_CONDITION:
            if item.get(F_MEMBER_TYPE) == "VirtualMachine":
                continue
            return False
        if kind == RT_NESTED:
            if vm_resolvable({F_EXPRESSION: item.get(F_EXPRESSIONS, [])}):
                continue
            return False
        return False
    return True


# === STATISTICS ===
def _parse_stats(payload):
    """{rule_path: counters} from NSX's results[].statistics[] shape.

    Tolerates a flat results[] too: statistics is the part of the contract
    that varies most between versions, so the parser is permissive and the
    caller degrades rather than failing.
    """
    out = {}
    for result in (payload.get(F_RESULTS) or []):
        entries = result.get(F_STATISTICS)
        if entries is None:
            entries = [result] if result.get(F_RULE_PATH) else []
        for entry in entries:
            path = entry.get(F_RULE_PATH)
            if path:
                out[path] = entry
    return out


def fetch_hit_counts(records, domain):
    """({rule_path: counters}, supported).

    One call per policy, not per rule -- the per-rule endpoint would
    reintroduce the N+1 that the concurrent policy fetch removed. When the
    endpoint is absent the hit checks report unknown and every other check
    still runs.
    """
    targets = {}
    for record in records:
        targets[(record.nsx.name, record.policy_id)] = (record.nsx,
                                                        record.policy_id)
    if not targets:
        return {}, True

    def fetch(item):
        nsx, pid = item
        return nsx.get(p_policy_stats(nsx.base(domain), domain, pid))

    results = parallel_run(list(targets.values()), fetch,
                           label="Rule statistics",
                           key=lambda item: (item[0].name, item[1]))
    stats, failures = {}, 0
    for value in results.values():
        if isinstance(value, Exception):
            failures += 1
            debug("statistics unavailable: {}".format(value))
            continue
        stats.update(_parse_stats(value))
    supported = failures < len(targets)
    return stats, supported


def group_member_counts(groups, domain):
    """{group path: count or None} -- None means not measurable, not empty."""
    measurable = {path: (nsx, group) for path, (nsx, group) in groups.items()
                  if vm_resolvable(group)}
    counts = dict.fromkeys(groups)
    if not measurable:
        return counts

    def fetch(item):
        path, (nsx, group) = item
        members = nsx.get_all(p_group_members(nsx.base(domain), domain,
                                              group.get(F_ID, "?")))
        return len(members)

    results = parallel_run(list(measurable.items()), fetch,
                           label="Group members",
                           key=lambda item: item[0])
    for path, value in results.items():
        counts[path] = None if isinstance(value, Exception) else value
    return counts


# === CONTEXT ===
class HygieneContext:
    def __init__(self, records, groups, stats, stats_supported, member_counts):
        self.records = records
        self.groups = groups
        self.stats = stats
        self.stats_supported = stats_supported
        self.member_counts = member_counts
        self._by_policy = {}
        for record in records:
            key = (record.nsx.name, record.policy_id)
            self._by_policy.setdefault(key, []).append(record)
        for key in self._by_policy:
            self._by_policy[key].sort(key=rule_sequence)

    def earlier_siblings(self, record):
        """Rules ahead of this one in the same policy, in evaluation order."""
        key = (record.nsx.name, record.policy_id)
        siblings = self._by_policy.get(key, [])
        out = []
        for other in siblings:
            if other is record:
                break
            out.append(other)
        return out

    def hits_for(self, record):
        entry = self.stats.get(record.path)
        if entry is None:
            return None
        try:
            return int(entry.get(F_HIT_COUNT))
        except (TypeError, ValueError):
            return None


# === CHECKS ===
def check_any_any(record, ctx):
    rule = record.rule
    if not (is_wildcard(listed_values(rule, "source_groups"))
            and is_wildcard(listed_values(rule, "destination_groups"))):
        return []
    if rule.get(F_DISABLED):
        return []
    action = rule.get(F_ACTION_FIELD, "?")
    if action == "ALLOW":
        return [Finding("any_any_allow", "critical", record,
                        "source and destination are both ANY with ALLOW -- "
                        "permits all traffic in scope")]
    return [Finding("any_any_other", "high", record,
                    "source and destination are both ANY (action {})".format(
                        action))]


def check_broad_applied_to(record, ctx):
    rule = record.rule
    if rule.get(F_DISABLED):
        return []
    if is_wildcard(listed_values(rule, F_SCOPE)):
        return [Finding("broad_applied_to", "high", record,
                        "applied-to is ANY -- enforced on every workload, "
                        "not a scoped set")]
    return []


def check_group_references(record, ctx):
    findings = []
    for ref in sorted(record.group_refs()):
        if ref == ANY:
            continue
        entry = ctx.groups.get(ref)
        if entry is None:
            findings.append(Finding(
                "missing_group", "critical", record,
                "references a group that does not exist: {}".format(ref)))
            continue
        _, group = entry
        name = group.get(F_DISPLAY_NAME, ref)
        if not (group.get(F_EXPRESSION) or []):
            findings.append(Finding(
                "no_criteria_group", "medium", record,
                "group '{}' has no membership criteria -- the rule is "
                "inert".format(name)))
            continue
        count = ctx.member_counts.get(ref)
        if count == 0:
            findings.append(Finding(
                "empty_group", "low", record,
                "group '{}' currently resolves to 0 VM members".format(name),
                confidence="soft"))
    return findings


def check_disabled(record, ctx):
    if record.rule.get(F_DISABLED):
        return [Finding("disabled_rule", "low", record,
                        "disabled -- dead configuration carried in the "
                        "policy")]
    return []


def check_deny_not_logged(record, ctx):
    rule = record.rule
    if rule.get(F_DISABLED):
        return []
    if rule.get(F_ACTION_FIELD) in DENY_ACTIONS and not rule.get(F_LOGGED):
        return [Finding("drop_not_logged", "medium", record,
                        "{} with logging off -- drops leave no forensic "
                        "trail".format(rule.get(F_ACTION_FIELD)))]
    return []


def check_duplicate(record, ctx):
    key = match_key(record.rule)
    for other in ctx.earlier_siblings(record):
        if match_key(other.rule) == key:
            return [Finding("duplicate_rule", "medium", record,
                            "identical match criteria to earlier rule "
                            "'{}' in the same policy".format(other.rule_name))]
    return []


def check_shadowed(record, ctx):
    """Only flags what is provable without port or CIDR arithmetic."""
    if record.rule.get(F_DISABLED):
        return []
    for other in ctx.earlier_siblings(record):
        if matches_everything(other.rule):
            return [Finding(
                "shadowed_by_any_any", "high", record,
                "unreachable: earlier rule '{}' in this policy matches all "
                "traffic with {}".format(
                    other.rule_name, other.rule.get(F_ACTION_FIELD)))]
    return []


def check_unused(record, ctx):
    if not ctx.stats_supported or record.rule.get(F_DISABLED):
        return []
    hits = ctx.hits_for(record)
    if hits is None or hits > 0:
        return []
    entry = ctx.stats.get(record.path) or {}
    stamp = entry.get(F_LAST_UPDATE)
    when = " (counters last updated {})".format(stamp) if stamp else ""
    return [Finding(
        "unused_rule", "medium", record,
        "no hits since counters were last reset{} -- NOT proof the rule is "
        "unused; use `nsxctl rule baseline` for that".format(when),
        confidence="soft")]


CHECKS = (
    check_any_any,
    check_broad_applied_to,
    check_group_references,
    check_disabled,
    check_deny_not_logged,
    check_duplicate,
    check_shadowed,
    check_unused,
)


def evaluate(ctx):
    findings = []
    for record in ctx.records:
        for check in CHECKS:
            findings.extend(check(record, ctx) or [])
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check,
                                 f.record.policy_name, f.record.rule_name))
    return findings


def build_context(sessions, domain, with_members=True):
    records = sweep_rules(sessions, domain)
    groups = group_inventory(sessions, domain)
    stats, supported = fetch_hit_counts(records, domain)
    referenced = {ref for record in records for ref in record.group_refs()
                  if ref != ANY and ref in groups}
    member_counts = {}
    if with_members and referenced:
        member_counts = group_member_counts(
            {path: groups[path] for path in referenced}, domain)
    return HygieneContext(records, groups, stats, supported, member_counts)


# === ACTION ===
def act_hygiene(sessions, domain, exporter, with_members=True):
    """Returns (findings, worst_severity_or_None)."""
    section("DFW RULE HYGIENE")
    ctx = build_context(sessions, domain, with_members=with_members)
    say("  {} rule(s) across {} manager(s), {} group(s) referenced".format(
        cC(str(len(ctx.records))), len(sessions), len(ctx.groups)))
    if not ctx.stats_supported:
        say("  {} hit counters unavailable on this NSX -- unused-rule checks "
            "skipped.".format(cBY("note:")))
    not_measurable = sum(1 for v in ctx.member_counts.values() if v is None)
    if not_measurable:
        say("  {} {} referenced group(s) are not VM-resolvable, so their "
            "member counts are {} -- never reported as empty.".format(
                cD("note:"), not_measurable, cD("not measurable")))
    hr()

    findings = evaluate(ctx)
    rows = [f.row() for f in findings]
    exporter.stage("rule_hygiene", HYGIENE_HEADERS, rows)

    if not findings:
        say("  {} no hygiene problems found.".format(cBG("Clean:")))
        return findings, None

    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    say("  {}".format(cB("Summary")))
    table(["Severity", "Findings"],
          [[_colour(sev)(sev), str(counts[sev])]
           for sev in SEVERITIES if sev in counts], indent=4)

    for severity in SEVERITIES:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        say("\n  {} ({})".format(_colour(severity)(severity.upper()),
                                 len(group)))
        hr()
        for finding in group[:HYGIENE_CONSOLE_LIMIT]:
            soft = "  {}".format(cD("[soft]")) if finding.confidence == "soft" \
                else ""
            say("    {} / {}   {}{}".format(
                cB(finding.record.policy_name), finding.record.rule_name,
                cD(finding.check), soft))
            say("      {}".format(finding.detail))
        more_note(HYGIENE_CONSOLE_LIMIT, len(group))

    hr()
    worst = next(s for s in SEVERITIES if s in counts)
    say("  {} finding(s); worst severity {}.".format(
        cC(str(len(findings))), _colour(worst)(worst)))
    return findings, worst


def _colour(severity):
    return {"critical": cBR, "high": cBY, "medium": cY, "low": cD}.get(
        severity, cD)


def worst_severity(findings):
    present = {f.severity for f in findings}
    for severity in SEVERITIES:
        if severity in present:
            return severity
    return None


def at_or_above(findings, threshold):
    """Findings at or above a severity, for --fail-on."""
    if threshold not in SEVERITIES:
        return []
    limit = SEVERITIES.index(threshold)
    return [f for f in findings if SEVERITIES.index(f.severity) <= limit]
