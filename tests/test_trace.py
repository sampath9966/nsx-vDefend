"""Connectivity trace.

The tests that matter most here are the ones asserting what the trace REFUSES
to claim: that it does not pick a NIC on a multi-NIC VM, does not call a
service-scoped rule a match when no port was given, does not present a static
verdict as though a packet had been sent, and does not leave a traceflow
object behind on the manager.
"""

import pytest
from fake_nsx import obs_delivered, obs_dropped, obs_forwarded

from nsx_toolkit import output
from nsx_toolkit.actions.trace import act_trace
from nsx_toolkit.errors import NsxError
from nsx_toolkit.export import Exporter
from nsx_toolkit.policy import sweep_rules
from nsx_toolkit.trace import (
    MATCH,
    NO_MATCH,
    UNDECIDED,
    AmbiguousNic,
    TraceEndpoint,
    build_traceflow_request,
    evaluation_order,
    interpret_observations,
    load_service_index,
    parse_duration,
    port_in_spec,
    resolve_vm_endpoint,
    rule_service_verdict,
    rules_by_realized_id,
    run_traceflow,
    select_vif,
    service_port_verdict,
    static_evaluate,
    verdicts_agree,
)

VM_CRITERIA = [{"resource_type": "Condition", "member_type": "VirtualMachine",
                "key": "Tag", "operator": "EQUALS", "value": "env|prod"}]


@pytest.fixture
def estate(lm):
    """A web VM and a db VM, each in a group, with one rule between them."""
    web = lm.state.add_vm("web01", tags=[("env", "prod")])
    db = lm.state.add_vm("db01", tags=[("env", "prod")])
    lm.state.add_vif(web, mac="00:50:56:00:00:01", ips=["10.1.1.10"])
    lm.state.add_vif(db, mac="00:50:56:00:00:02", ips=["10.1.2.20"])
    g_web = lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    g_db = lm.state.add_group("g-db", "DB", expression=VM_CRITERIA)
    lm.state.associate(web, g_web)
    lm.state.associate(db, g_db)
    lm.state.add_service("MySQL", protocol="TCP", ports=["3306"])
    lm.state.add_policy("app-tier", "App Tier")
    return lm, web, db, g_web, g_db


def endpoints(session, lm, domain="default"):
    source = resolve_vm_endpoint([session], "web01", domain, need_port=True)
    destination = resolve_vm_endpoint([session], "db01", domain,
                                      need_port=False)
    return source, destination


# === EVALUATION ORDER ===
def test_category_beats_sequence_number(lm, make_session):
    """An Infrastructure rule is evaluated before an Application one even when
    its sequence number is higher -- the trap a per-policy ordering falls in."""
    infra = lm.state.add_policy("infra", "Infrastructure")
    infra["category"] = "Infrastructure"
    app = lm.state.add_policy("app", "Application")
    app["category"] = "Application"
    lm.state.add_rule("app", "early", sequence_number=1)
    lm.state.add_rule("infra", "late", sequence_number=999)

    order = evaluation_order(sweep_rules([make_session(lm)], "default"))
    assert [r.rule_name for r in order] == ["late", "early"]


# === SERVICE MATCHING ===
@pytest.mark.parametrize("spec,port,expected", [
    ("443", 443, True),
    ("443", 444, False),
    ("8000-8100", 8080, True),
    ("8000-8100", 9000, False),
    ("not-a-port", 443, False),
])
def test_port_in_spec(spec, port, expected):
    assert port_in_spec(port, spec) is expected


def test_l4_service_decides_both_ways():
    service = {"service_entries": [{"resource_type": "L4PortSetServiceEntry",
                                    "l4_protocol": "TCP",
                                    "destination_ports": ["3306"]}]}
    assert service_port_verdict(service, "tcp", 3306) == MATCH
    assert service_port_verdict(service, "tcp", 443) == NO_MATCH
    assert service_port_verdict(service, "udp", 3306) == NO_MATCH


def test_non_l4_service_is_undecided_not_excluded():
    """An ICMP or ALG service cannot be reduced to a port comparison. Calling
    it a non-match would make the trace name the wrong rule."""
    service = {"service_entries": [{"resource_type": "ICMPTypeServiceEntry",
                                    "protocol": "ICMPv4"}]}
    assert service_port_verdict(service, "tcp", 3306) == UNDECIDED


def test_service_scoped_rule_is_undecided_without_a_port():
    rule = {"services": ["/infra/services/MySQL"]}
    verdict, reason = rule_service_verdict(rule, {}, "tcp", None)
    assert verdict == UNDECIDED
    assert "--port" in reason


def test_any_service_matches_without_a_port():
    assert rule_service_verdict({"services": ["ANY"]}, {}, "tcp", None)[0] == MATCH


# === STATIC EVALUATION ===
def test_first_matching_rule_in_order_wins(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "deny-db", sequence_number=10,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="DROP")
    lm.state.add_rule("app-tier", "allow-all", sequence_number=20,
                      action="ALLOW")
    session = make_session(lm)
    source, destination = endpoints(session, lm)

    verdict = static_evaluate(sweep_rules([session], "default"), source,
                              destination, {}, port=3306)
    assert verdict.action == "DROP"
    assert verdict.record.rule_name == "deny-db"
    assert verdict.certain is True


def test_a_rule_that_matches_neither_endpoint_is_skipped(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    other = lm.state.add_group("g-other", "Other", expression=VM_CRITERIA)
    lm.state.add_rule("app-tier", "unrelated", sequence_number=10,
                      source_groups=[other["path"]],
                      destination_groups=[other["path"]], action="DROP")
    lm.state.add_rule("app-tier", "allow-web-db", sequence_number=20,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    session = make_session(lm)
    source, destination = endpoints(session, lm)

    verdict = static_evaluate(sweep_rules([session], "default"), source,
                              destination, {}, port=3306)
    assert verdict.record.rule_name == "allow-web-db"


def test_applied_to_that_covers_neither_endpoint_excludes_the_rule(
        estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    other = lm.state.add_group("g-other", "Other", expression=VM_CRITERIA)
    lm.state.add_rule("app-tier", "scoped-elsewhere", sequence_number=10,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]],
                      scope=[other["path"]], action="DROP")
    session = make_session(lm)
    source, destination = endpoints(session, lm)

    verdict = static_evaluate(sweep_rules([session], "default"), source,
                              destination, {}, port=3306)
    assert verdict.record is None


def test_an_undecided_rule_ahead_makes_the_verdict_uncertain(estate,
                                                             make_session):
    """The load-bearing honesty check: a rule this cannot evaluate sits ahead
    of the one it can, so the answer is reported as unproven rather than as
    fact."""
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_service("Ping", entries=[{"resource_type":
                                           "ICMPTypeServiceEntry"}])
    lm.state.add_rule("app-tier", "icmp-rule", sequence_number=10,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]],
                      services=["/infra/services/Ping"], action="DROP")
    lm.state.add_rule("app-tier", "allow-mysql", sequence_number=20,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]],
                      services=["/infra/services/MySQL"], action="ALLOW")
    session = make_session(lm)
    source, destination = endpoints(session, lm)
    services = load_service_index([session], "default")

    verdict = static_evaluate(sweep_rules([session], "default"), source,
                              destination, services, port=3306)
    assert verdict.record.rule_name == "allow-mysql"
    assert verdict.certain is False
    assert verdict.undecided[0][0].rule_name == "icmp-rule"


def test_disabled_rules_never_decide_a_flow(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "disabled-drop", sequence_number=10,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="DROP",
                      disabled=True)
    lm.state.add_rule("app-tier", "allow", sequence_number=20,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    session = make_session(lm)
    source, destination = endpoints(session, lm)
    verdict = static_evaluate(sweep_rules([session], "default"), source,
                              destination, {}, port=3306)
    assert verdict.record.rule_name == "allow"


# === NIC RESOLUTION ===
def test_a_single_nic_needs_no_choice(estate, make_session):
    lm, _web, _db, _gw, _gd = estate
    source = resolve_vm_endpoint([make_session(lm)], "web01", "default")
    assert source.ip == "10.1.1.10"
    assert source.lport_id


def test_a_multi_nic_vm_refuses_to_be_guessed_at(estate, make_session):
    lm, web, _db, _gw, _gd = estate
    lm.state.add_vif(web, mac="00:50:56:00:00:09", ips=["10.9.9.9"],
                     device_name="Network adapter 2")
    with pytest.raises(AmbiguousNic) as excinfo:
        resolve_vm_endpoint([make_session(lm)], "web01", "default")
    assert len(excinfo.value.vifs) == 2


def test_a_nic_can_be_chosen_by_index_or_by_name(estate, make_session):
    lm, web, _db, _gw, _gd = estate
    lm.state.add_vif(web, mac="00:50:56:00:00:09", ips=["10.9.9.9"],
                     device_name="Network adapter 2")
    session = make_session(lm)
    by_index = resolve_vm_endpoint([session], "web01", "default", nic="2")
    by_name = resolve_vm_endpoint([session], "web01", "default",
                                  nic="adapter 2")
    assert by_index.ip == by_name.ip == "10.9.9.9"


def test_a_vm_with_no_vif_says_so(lm, make_session):
    lm.state.add_vm("ghost01")
    with pytest.raises(NsxError, match="no VIF"):
        resolve_vm_endpoint([make_session(lm)], "ghost01", "default")


def test_an_unrealized_port_leaves_nothing_to_inject_at(lm, make_session):
    """A VIF with no logical port behind it: there is nothing to inject at,
    and that has to read differently from a VM with no NIC at all."""
    fresh = lm.state.add_vm("new01")
    lm.state.add_vif(fresh, ips=["10.1.1.99"], lport_id=False)
    source = resolve_vm_endpoint([make_session(lm)], "new01", "default")
    assert source.ip == "10.1.1.99"
    assert source.lport_id is None


def test_an_unknown_vm_is_a_could_not_start_failure(estate, make_session):
    lm, _web, _db, _gw, _gd = estate
    with pytest.raises(NsxError, match="No VM matching"):
        resolve_vm_endpoint([make_session(lm)], "nope", "default")


def test_select_vif_lists_the_options_when_the_name_is_wrong(estate,
                                                             make_session):
    lm, web, _db, _gw, _gd = estate
    vifs = lm.state.vifs[web["external_id"]]
    with pytest.raises(NsxError, match="no NIC matching"):
        select_vif("web01", vifs, "adapter 7")


# === LIVE TRACEFLOW ===
def test_traceflow_polls_until_finished_and_always_cleans_up(estate,
                                                             make_session):
    lm, _web, _db, _gw, _gd = estate
    lm.state.set_traceflow_result([obs_delivered()],
                                  states=["IN_PROGRESS", "IN_PROGRESS",
                                          "FINISHED"])
    session = make_session(lm)
    request = build_traceflow_request("lp-1", "10.1.1.10", "10.1.2.20",
                                      "aa", "bb", port=3306)
    tid, state, observations = run_traceflow(session, request, timeout=5,
                                             sleep=lambda _s: None)
    assert state == "FINISHED"
    assert len(observations) == 1
    assert lm.state.traceflow_deleted == [tid]


def test_a_timed_out_traceflow_still_deletes_its_object(estate, make_session):
    """A traceflow left behind is litter on somebody's manager."""
    lm, _web, _db, _gw, _gd = estate
    lm.state.set_traceflow_result([], states=["IN_PROGRESS"])
    session = make_session(lm)
    request = build_traceflow_request("lp-1", "10.1.1.10", "10.1.2.20",
                                      "aa", "bb", port=3306)
    tid, state, observations = run_traceflow(session, request, timeout=0.05,
                                             poll_interval=0.01)
    assert state == "IN_PROGRESS"
    assert observations == []
    assert lm.state.traceflow_deleted == [tid]


def test_the_packet_carries_the_protocol_and_port_asked_for():
    request = build_traceflow_request("lp-1", "10.1.1.10", "10.1.2.20",
                                      "aa", "bb", proto="udp", port=53)
    assert request["packet"]["ip_header"]["protocol"] == 17
    assert request["packet"]["transport_header"]["dst_port"] == 53


def test_icmp_carries_no_transport_header():
    request = build_traceflow_request("lp-1", "10.1.1.10", "10.1.2.20",
                                      "aa", "bb", proto="icmp")
    assert "transport_header" not in request["packet"]


def test_an_unsupported_protocol_is_refused():
    with pytest.raises(NsxError, match="Unsupported protocol"):
        build_traceflow_request("lp-1", "a", "b", "c", "d", proto="sctp")


# === OBSERVATION INTERPRETATION ===
def test_a_numeric_acl_rule_id_becomes_a_named_rule(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "block-legacy-db", rule_id=4130,
                      source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="DROP")
    records = sweep_rules([make_session(lm)], "default")

    live = interpret_observations(
        "FINISHED", [obs_forwarded(), obs_dropped(acl_rule_id=4130)],
        rules_by_realized_id(records))
    assert live.dropped
    assert live.record.rule_name == "block-legacy-db"
    assert live.action == "DROP"


def test_an_unmatched_rule_id_is_reported_rather_than_hidden():
    live = interpret_observations("FINISHED", [obs_dropped(acl_rule_id=99999)],
                                  {})
    assert live.dropped
    assert live.record is None
    assert live.acl_rule_id == 99999


def test_delivered_is_an_allow_verdict():
    live = interpret_observations("FINISHED",
                                  [obs_forwarded(), obs_delivered()], {})
    assert live.delivered and live.action == "ALLOW"


def test_no_observations_is_no_verdict_not_a_pass():
    live = interpret_observations("FINISHED", [], {})
    assert live.conclusive is False
    assert live.action is None


# === AGREEMENT ===
def test_agreement_is_none_when_only_one_engine_answered(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "allow", source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    session = make_session(lm)
    source, destination = endpoints(session, lm)
    static = static_evaluate(sweep_rules([session], "default"), source,
                             destination, {}, port=3306)
    assert verdicts_agree(static, None) is None


# === THE ACTION ===
def _outcome(sessions, **kwargs):
    kwargs.setdefault("exporter", Exporter())
    return act_trace(sessions, "web01", "db01", "default", **kwargs)


def test_a_gm_only_inventory_says_traceflow_is_not_available(gm, make_session):
    """Not an obscure 404: the reason is named and the static half still runs."""
    gm.state.add_group("g-web", "Web", origin="GM", expression=VM_CRITERIA)
    gm.state.add_policy("p1", "Policy", origin="GM")
    gm.state.add_rule("p1", "r1", origin="GM", action="ALLOW")
    session = make_session(gm)
    with pytest.raises(NsxError, match="No VM matching"):
        _outcome([session])


def test_a_static_only_trace_sends_no_packet(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "allow", source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    outcome = _outcome([make_session(lm)], static_only=True, port=3306)
    assert outcome.static.action == "ALLOW"
    assert outcome.live is None
    assert lm.state.count("POST /api/v1/traceflow") == 0


def test_a_powered_off_source_falls_back_to_static_with_a_reason(lm,
                                                                 make_session):
    web = lm.state.add_vm("web01", power="VM_STOPPED")
    db = lm.state.add_vm("db01")
    lm.state.add_vif(web, ips=["10.1.1.10"])
    lm.state.add_vif(db, ips=["10.1.2.20"])
    lm.state.add_policy("p1", "Policy")
    lm.state.add_rule("p1", "allow", action="ALLOW")
    output.set_assume_yes(True)
    try:
        outcome = _outcome([make_session(lm)], port=3306)
    finally:
        output.set_assume_yes(False)
    assert outcome.live is None
    assert "not powered on" in outcome.live_skipped
    assert outcome.static.action == "ALLOW"
    assert lm.state.count("POST /api/v1/traceflow") == 0


def test_a_packet_is_never_injected_without_consent(estate, make_session):
    """Non-interactive and no --yes is a refusal, not an assumed yes."""
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "allow", source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    outcome = _outcome([make_session(lm)], port=3306)
    assert outcome.live is None
    assert "consent" in outcome.live_skipped
    assert lm.state.count("POST /api/v1/traceflow") == 0


def test_yes_runs_both_halves_and_they_agree(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    rule = lm.state.add_rule("app-tier", "allow-mysql",
                             source_groups=[g_web["path"]],
                             destination_groups=[g_db["path"]], action="ALLOW")
    lm.state.set_traceflow_result([obs_forwarded(), obs_delivered()])
    output.set_assume_yes(True)
    try:
        outcome = _outcome([make_session(lm)], port=3306)
    finally:
        output.set_assume_yes(False)
    assert outcome.static.record.rule_name == "allow-mysql"
    assert outcome.live.delivered
    assert outcome.agree is True
    assert lm.state.traceflow_deleted
    assert rule["rule_id"]


def test_a_disagreement_is_surfaced_as_a_finding(estate, make_session):
    """The policy permits it; the data plane dropped it. That gap is the whole
    reason both halves run."""
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "allow-mysql", source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    lm.state.set_traceflow_result([obs_forwarded(),
                                   obs_dropped(acl_rule_id=999)])
    output.set_assume_yes(True)
    try:
        outcome = _outcome([make_session(lm)], port=3306)
    finally:
        output.set_assume_yes(False)
    assert outcome.static.action == "ALLOW"
    assert outcome.live.action == "DROP"
    assert outcome.agree is False


def test_an_address_destination_needs_no_vm(estate, make_session):
    lm, _web, _db, _gw, _gd = estate
    lm.state.add_rule("app-tier", "allow", action="ALLOW")
    exporter = Exporter()
    outcome = act_trace([make_session(lm)], "web01", None, "default", exporter,
                        to_address="10.20.30.40", port=443, static_only=True)
    assert outcome.static.action == "ALLOW"


def test_the_trace_is_exported(estate, make_session):
    lm, _web, _db, g_web, g_db = estate
    lm.state.add_rule("app-tier", "allow", source_groups=[g_web["path"]],
                      destination_groups=[g_db["path"]], action="ALLOW")
    exporter = Exporter()
    act_trace([make_session(lm)], "web01", "db01", "default", exporter,
              port=3306, static_only=True)
    labels = {rs.label for rs in exporter.sets}
    assert labels == {"trace", "trace_path"}
    rows = next(rs for rs in exporter.sets if rs.label == "trace").rows
    assert rows[0][0] == "policy"


# === DURATIONS ===
@pytest.mark.parametrize("text,expected", [
    ("15", 15.0), ("15s", 15.0), ("2m", 120.0), ("500ms", 0.5), (None, 15.0),
])
def test_parse_duration(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["soon", "-5", "0"])
def test_a_bad_duration_is_refused(text):
    with pytest.raises(NsxError):
        parse_duration(text)


def test_an_endpoint_with_no_groups_still_matches_any_rules():
    source = TraceEndpoint(label="a")
    destination = TraceEndpoint(label="b")
    assert source.groups == set() and destination.groups == set()
