"""Shared security-policy and rule traversal.

The GM/LM sweep with path-based deduplication used to live inside
`act_reverse_lookup`. Rule hygiene needs exactly the same traversal, so it is
extracted here rather than duplicated -- two copies of this logic would drift,
and the dedup is the subtle part.

Why the dedup exists: GM-authored security policies are realized read-only on
every Local Manager registered beneath the Global Manager, so an LM's own rule
listing contains both its native rules AND a copy of every GM rule. Scanned
across GM + all LMs, each GM rule would otherwise be reported once per site.
Rules are deduped globally by their NSX 'path', first-seen wins, and GM
sessions are always scanned before LM sessions -- so a GM-origin rule is
attributed to the GM exactly once and never re-listed per LM.
"""

from .api import (
    ANY,
    F_DEST_GROUPS,
    F_DISPLAY_NAME,
    F_ID,
    F_PATH,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SOURCE_GROUPS,
    ROLE_GM,
    ROLE_LM,
    origin_of_path,
    p_groups,
    p_sec_policies,
    p_sec_rules,
)
from .errors import NsxError
from .output import Spinner, parallel_run


class RuleRecord:
    """One DFW rule, with the manager and policy it was read from."""

    __slots__ = ("nsx", "policy", "rule", "origin")

    def __init__(self, nsx, policy, rule, origin):
        self.nsx = nsx
        self.policy = policy
        self.rule = rule
        self.origin = origin

    @property
    def policy_id(self):
        return self.policy.get(F_ID, "?")

    @property
    def policy_name(self):
        return self.policy.get(F_DISPLAY_NAME, self.policy_id)

    @property
    def rule_id(self):
        return self.rule.get(F_ID, "?")

    @property
    def rule_name(self):
        return self.rule.get(F_DISPLAY_NAME, self.rule_id)

    @property
    def path(self):
        return self.rule.get(F_PATH, "")

    def group_refs(self):
        """Every group path this rule mentions, in any position."""
        return set(self.rule.get(F_SOURCE_GROUPS, [])
                   + self.rule.get(F_DEST_GROUPS, [])
                   + self.rule.get(F_SCOPE, []))

    def directions_for(self, group_paths):
        """Which positions of the rule reference the given groups."""
        dirs = []
        if set(self.rule.get(F_SOURCE_GROUPS, [])) & group_paths:
            dirs.append("source")
        if set(self.rule.get(F_DEST_GROUPS, [])) & group_paths:
            dirs.append("dest")
        if set(self.rule.get(F_SCOPE, [])) & group_paths:
            dirs.append("applied_to")
        return dirs


def fetch_rules_for(nsx, domain, policies):
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


def policies_for(nsx, domain):
    """Security policies on one manager, or [] when it cannot be reached."""
    try:
        base = nsx.base(domain)
    except NsxError:
        return []
    with Spinner("Policies on {}".format(nsx.name)):
        try:
            return nsx.get_all(p_sec_policies(base, domain))
        except NsxError:
            return []


def listed_values(rule, field):
    """A rule's list-valued field with empties dropped."""
    return [v for v in (rule.get(field) or []) if v]


def is_wildcard(values):
    """NSX writes the wildcard as ["ANY"]; an empty list means the same.

    Shared rather than duplicated: rule hygiene and trace evaluation both turn
    on this exact question, and two copies would eventually disagree about
    what "matches everything" means.
    """
    return not values or list(values) == [ANY]


def rule_sequence(record):
    """A rule's evaluation position, as an int. NSX omits or stringifies it on
    some versions, so this never raises."""
    try:
        return int(record.rule.get(F_SEQUENCE_NUMBER) or 0)
    except (TypeError, ValueError):
        return 0


def ordered_sessions(sessions):
    """Global Managers first. The dedup below depends on this order."""
    gm = [s for s in sessions if s.role == ROLE_GM]
    lm = [s for s in sessions if s.role == ROLE_LM]
    return gm, lm


def sweep_rules(sessions, domain):
    """Every DFW rule across every manager, deduplicated by rule path.

    A rule with no path is never deduplicated -- we cannot prove two such
    rules are the same object, and silently dropping one would under-report.
    """
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    seen_paths = set()
    records = []
    for nsx in gm_sessions + lm_sessions:
        policies = policies_for(nsx, domain)
        for policy, rule in fetch_rules_for(nsx, domain, policies):
            path = rule.get(F_PATH, "")
            if path:
                if path in seen_paths:
                    continue
                seen_paths.add(path)
            if nsx.role == ROLE_GM:
                origin = "GM"
            else:
                origin = origin_of_path(path)
                if origin == "GM" and not gm_sessions:
                    origin = "GM (via LM)"
            records.append(RuleRecord(nsx, policy, rule, origin))
    return records


def group_inventory(sessions, domain):
    """{group path: (nsx, group)} across every manager, GM first.

    Used to tell "this rule references a group that does not exist" apart from
    "this rule references a group that exists but is empty" -- two findings
    with very different meanings.
    """
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    by_path = {}
    for nsx in gm_sessions + lm_sessions:
        try:
            base = nsx.base(domain)
            groups = nsx.get_all(p_groups(base, domain))
        except NsxError:
            continue
        for group in groups:
            path = group.get(F_PATH, "")
            if path and path not in by_path:
                by_path[path] = (nsx, group)
    return by_path
