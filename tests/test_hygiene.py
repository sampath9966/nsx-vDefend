"""Rule hygiene checks.

Every check gets a positive and a negative case. The negatives matter more
than the positives here: a report that fires on healthy rules is a report
people stop reading.
"""

import pytest

from nsx_toolkit.actions.hygiene import (
    act_hygiene,
    at_or_above,
    build_context,
    evaluate,
    match_key,
    matches_everything,
    vm_resolvable,
)
from nsx_toolkit.export import Exporter

VM_CRITERIA = [{"resource_type": "Condition", "member_type": "VirtualMachine",
                "key": "Tag", "operator": "EQUALS", "value": "env|prod"}]
IP_CRITERIA = [{"resource_type": "IPAddressExpression",
                "ip_addresses": ["10.0.0.0/8"]}]
SEGMENT_CRITERIA = [{"resource_type": "Condition", "member_type": "Segment",
                     "key": "Tag", "operator": "EQUALS", "value": "zone|dmz"}]


@pytest.fixture
def estate(lm):
    """A Local Manager with one healthy group that has a member."""
    group = lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    lm.state.group_members["g-web"] = [{"display_name": "web1", "id": "1"}]
    return lm, group


def findings_for(session, domain="default"):
    return evaluate(build_context([session], domain))


def checks_fired(session):
    return {f.check for f in findings_for(session)}


def healthy(lm, group, pid="p1", rid="r1", **kwargs):
    """A rule with nothing wrong with it, for the negative cases."""
    lm.state.add_policy(pid, "Policy " + pid)
    kwargs.setdefault("source_groups", [group["path"]])
    kwargs.setdefault("destination_groups", [group["path"]])
    kwargs.setdefault("scope", [group["path"]])
    kwargs.setdefault("services", ["/infra/services/HTTPS"])
    return lm.state.add_rule(pid, rid, **kwargs)


# --- a healthy rule produces nothing -------------------------------------
def test_a_healthy_rule_produces_no_findings(estate, make_session):
    lm, group = estate
    healthy(lm, group)
    assert checks_fired(make_session(lm)) == set()


# --- any-any --------------------------------------------------------------
def test_any_any_allow_is_critical(estate, make_session):
    lm, _ = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "r1", action="ALLOW")
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["any_any_allow"].severity == "critical"


def test_any_any_drop_is_high_not_critical(estate, make_session):
    lm, _ = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "r1", action="DROP")
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert "any_any_allow" not in found
    assert found["any_any_other"].severity == "high"


def test_a_scoped_rule_is_not_any_any(estate, make_session):
    lm, group = estate
    healthy(lm, group)
    assert "any_any_allow" not in checks_fired(make_session(lm))


def test_a_disabled_any_any_rule_is_not_reported_as_any_any(estate, make_session):
    """It is dead config, which is the disabled_rule finding, not a hole."""
    lm, _ = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "r1", action="ALLOW", disabled=True)
    fired = checks_fired(make_session(lm))
    assert "any_any_allow" not in fired
    assert "disabled_rule" in fired


# --- applied-to -----------------------------------------------------------
def test_applied_to_any_is_flagged(estate, make_session):
    lm, group = estate
    healthy(lm, group, scope=["ANY"])
    assert "broad_applied_to" in checks_fired(make_session(lm))


def test_a_scoped_applied_to_is_not_flagged(estate, make_session):
    lm, group = estate
    healthy(lm, group)
    assert "broad_applied_to" not in checks_fired(make_session(lm))


# --- group references -----------------------------------------------------
def test_a_reference_to_a_nonexistent_group_is_critical(estate, make_session):
    lm, group = estate
    healthy(lm, group, source_groups=["/infra/domains/default/groups/ghost"])
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["missing_group"].severity == "critical"
    assert "ghost" in found["missing_group"].detail


def test_a_group_with_no_criteria_is_reported_as_inert(estate, make_session):
    lm, group = estate
    inert = lm.state.add_group("g-inert", "Inert", expression=[])
    healthy(lm, group, source_groups=[inert["path"]])
    fired = checks_fired(make_session(lm))
    assert "no_criteria_group" in fired
    assert "empty_group" not in fired      # inert is provable; empty is not


def test_a_group_with_zero_members_is_soft(estate, make_session):
    lm, group = estate
    empty = lm.state.add_group("g-empty", "Empty", expression=VM_CRITERIA)
    lm.state.group_members["g-empty"] = []
    healthy(lm, group, source_groups=[empty["path"]])
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["empty_group"].confidence == "soft"
    assert found["empty_group"].severity == "low"


def test_an_ip_based_group_is_never_called_empty(estate, make_session):
    """The bug this prevents: /members/virtual-machines returns nothing for an
    IP-set group, so a naive count reports a live group as empty."""
    lm, group = estate
    ipset = lm.state.add_group("g-ip", "IP Set", expression=IP_CRITERIA)
    lm.state.group_members["g-ip"] = []
    healthy(lm, group, source_groups=[ipset["path"]])
    assert "empty_group" not in checks_fired(make_session(lm))


def test_a_segment_based_group_is_never_called_empty(estate, make_session):
    lm, group = estate
    seg = lm.state.add_group("g-seg", "Segment", expression=SEGMENT_CRITERIA)
    lm.state.group_members["g-seg"] = []
    healthy(lm, group, source_groups=[seg["path"]])
    assert "empty_group" not in checks_fired(make_session(lm))


def test_any_is_not_treated_as_a_missing_group(estate, make_session):
    lm, group = estate
    healthy(lm, group, source_groups=["ANY"])
    assert "missing_group" not in checks_fired(make_session(lm))


# --- disabled / logging ---------------------------------------------------
def test_a_disabled_rule_is_reported(estate, make_session):
    lm, group = estate
    healthy(lm, group, disabled=True)
    assert "disabled_rule" in checks_fired(make_session(lm))


def test_a_drop_without_logging_is_reported(estate, make_session):
    lm, group = estate
    healthy(lm, group, action="DROP", logged=False)
    assert "drop_not_logged" in checks_fired(make_session(lm))


def test_a_logged_drop_is_not_reported(estate, make_session):
    lm, group = estate
    healthy(lm, group, action="DROP", logged=True)
    assert "drop_not_logged" not in checks_fired(make_session(lm))


def test_an_unlogged_allow_is_not_reported(estate, make_session):
    """Only denies need the forensic trail."""
    lm, group = estate
    healthy(lm, group, action="ALLOW", logged=False)
    assert "drop_not_logged" not in checks_fired(make_session(lm))


# --- duplicates and shadowing --------------------------------------------
def test_an_identical_later_rule_is_a_duplicate(estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="first", sequence_number=10)
    healthy(lm, group, pid="p1", rid="second", sequence_number=20)
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["duplicate_rule"].record.rule_name == "second"
    assert "first" in found["duplicate_rule"].detail


def test_rules_differing_only_by_service_are_not_duplicates(estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="https", sequence_number=10,
            services=["/infra/services/HTTPS"])
    healthy(lm, group, pid="p1", rid="ssh", sequence_number=20,
            services=["/infra/services/SSH"])
    assert "duplicate_rule" not in checks_fired(make_session(lm))


def test_identical_rules_in_different_policies_are_not_duplicates(
        estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="r1")
    healthy(lm, group, pid="p2", rid="r1")
    assert "duplicate_rule" not in checks_fired(make_session(lm))


def test_a_rule_below_an_any_any_is_shadowed(estate, make_session):
    lm, group = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "catch-all", action="ALLOW", sequence_number=10)
    healthy(lm, group, pid="p1", rid="below", sequence_number=20)
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["shadowed_by_any_any"].record.rule_name == "below"
    assert found["shadowed_by_any_any"].severity == "high"


def test_a_rule_above_an_any_any_is_not_shadowed(estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="above", sequence_number=10)
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "catch-all", action="ALLOW", sequence_number=20)
    shadowed = [f.record.rule_name for f in findings_for(make_session(lm))
                if f.check == "shadowed_by_any_any"]
    assert "above" not in shadowed


def test_a_disabled_any_any_shadows_nothing(estate, make_session):
    lm, group = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "catch-all", action="ALLOW", disabled=True,
                      sequence_number=10)
    healthy(lm, group, pid="p1", rid="below", sequence_number=20)
    assert "shadowed_by_any_any" not in checks_fired(make_session(lm))


def test_an_any_any_limited_to_one_service_shadows_nothing(estate, make_session):
    """Without port arithmetic we cannot prove what it shadows, so we do not
    claim anything -- a false 'unreachable' is worse than no finding."""
    lm, group = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "https-any", action="ALLOW", sequence_number=10,
                      services=["/infra/services/HTTPS"])
    healthy(lm, group, pid="p1", rid="below", sequence_number=20)
    assert "shadowed_by_any_any" not in checks_fired(make_session(lm))


# --- hit counts -----------------------------------------------------------
def test_a_zero_hit_rule_is_soft_and_says_why(estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="r1")
    lm.state.set_hit_count("p1", "r1", 0)
    found = {f.check: f for f in findings_for(make_session(lm))}
    assert found["unused_rule"].confidence == "soft"
    assert "NOT proof" in found["unused_rule"].detail
    assert "baseline" in found["unused_rule"].detail


def test_a_rule_with_hits_is_not_reported_unused(estate, make_session):
    lm, group = estate
    healthy(lm, group, pid="p1", rid="r1")
    lm.state.set_hit_count("p1", "r1", 5)
    assert "unused_rule" not in checks_fired(make_session(lm))


def test_a_rule_with_no_statistics_is_not_reported_unused(estate, make_session):
    """Absent counters are unknown, not zero."""
    lm, group = estate
    healthy(lm, group, pid="p1", rid="r1")
    assert "unused_rule" not in checks_fired(make_session(lm))


def test_hit_checks_degrade_when_statistics_are_unsupported(estate, make_session):
    """A 404 on the statistics endpoint must not take the report down."""
    lm, group = estate
    lm.state.stats_unsupported = True
    healthy(lm, group, pid="p1", rid="r1", scope=["ANY"])
    session = make_session(lm)
    session.retries = 0
    ctx = build_context([session], "default")
    assert ctx.stats_supported is False
    fired = {f.check for f in evaluate(ctx)}
    assert "unused_rule" not in fired
    assert "broad_applied_to" in fired      # the static checks still ran


# --- helpers --------------------------------------------------------------
def test_vm_resolvable_recognises_criteria_types():
    assert vm_resolvable({"expression": VM_CRITERIA}) is True
    assert vm_resolvable({"expression": IP_CRITERIA}) is False
    assert vm_resolvable({"expression": SEGMENT_CRITERIA}) is False
    assert vm_resolvable({"expression": []}) is False


def test_matches_everything_requires_every_field_to_be_any():
    base = {"source_groups": ["ANY"], "destination_groups": ["ANY"],
            "services": ["ANY"], "scope": ["ANY"], "action": "ALLOW"}
    assert matches_everything(base) is True
    assert matches_everything(dict(base, services=["/infra/services/HTTPS"])) is False
    assert matches_everything(dict(base, scope=["/infra/g/a"])) is False
    assert matches_everything(dict(base, disabled=True)) is False
    assert matches_everything(dict(base, action="JUMP_TO_APPLICATION")) is False


def test_match_key_ignores_ordering():
    a = {"source_groups": ["a", "b"], "destination_groups": ["c"],
         "services": ["s1", "s2"], "scope": ["x"], "action": "ALLOW"}
    b = {"source_groups": ["b", "a"], "destination_groups": ["c"],
         "services": ["s2", "s1"], "scope": ["x"], "action": "ALLOW"}
    assert match_key(a) == match_key(b)


def test_at_or_above_filters_by_severity():
    class Fake:
        def __init__(self, severity):
            self.severity = severity
    findings = [Fake("critical"), Fake("high"), Fake("medium"), Fake("low")]
    assert len(at_or_above(findings, "critical")) == 1
    assert len(at_or_above(findings, "high")) == 2
    assert len(at_or_above(findings, "low")) == 4
    assert at_or_above(findings, "nonsense") == []


# --- the action -----------------------------------------------------------
def test_act_hygiene_stages_every_finding_for_export(estate, make_session):
    lm, group = estate
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "r1", action="ALLOW")
    exporter = Exporter()
    findings, worst = act_hygiene([make_session(lm)], "default", exporter)
    assert worst == "critical"
    rows = exporter.sets[0].rows
    assert len(rows) == len(findings)
    assert exporter.sets[0].label == "rule_hygiene"


def test_act_hygiene_on_a_clean_estate_reports_nothing(estate, make_session):
    lm, group = estate
    healthy(lm, group)
    exporter = Exporter()
    findings, worst = act_hygiene([make_session(lm)], "default", exporter)
    assert findings == []
    assert worst is None


def test_skipping_member_counts_drops_only_the_empty_group_check(
        estate, make_session):
    lm, group = estate
    empty = lm.state.add_group("g-empty", "Empty", expression=VM_CRITERIA)
    lm.state.group_members["g-empty"] = []
    healthy(lm, group, source_groups=[empty["path"]], scope=["ANY"])
    session = make_session(lm)
    ctx = build_context([session], "default", with_members=False)
    fired = {f.check for f in evaluate(ctx)}
    assert "empty_group" not in fired
    assert "broad_applied_to" in fired
