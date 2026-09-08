"""Profiles, projects, doctor, the name cache, sinks, restore and flows.

The tests that matter most here are the ones asserting a refusal or a
non-claim: that a multi-profile inventory will not guess which estate you
meant, that a capability probe never injects a packet, that TAB completion
never reaches the network, that a restore does not delete what the snapshot
merely failed to mention, and that a flow proposal reports an unclassified
address rather than inventing a group for it.
"""

import json

import pytest

from nsx_toolkit import namecache, output, sinks
from nsx_toolkit.actions.doctor import MISSING, NA, OK, act_doctor, probe_manager
from nsx_toolkit.actions.inspect import (
    act_policy_list,
    act_rule_list,
    act_service_list,
    describe_service,
)
from nsx_toolkit.actions.recommend import act_recommend
from nsx_toolkit.config import list_profiles, load_inventory, resolve_profile
from nsx_toolkit.errors import ConfigError
from nsx_toolkit.export import Exporter
from nsx_toolkit.flows import (
    build_address_index,
    propose_rules,
    read_flows,
    resolve_address,
)

VM_CRITERIA = [{"resource_type": "Condition", "member_type": "VirtualMachine",
                "key": "Tag", "operator": "EQUALS", "value": "env|prod"}]
IP_CRITERIA_WEB = [{"resource_type": "IPAddressExpression",
                    "ip_addresses": ["10.1.1.0/24"]}]
IP_CRITERIA_DB = [{"resource_type": "IPAddressExpression",
                   "ip_addresses": ["10.1.2.20"]}]


def write_json(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# === PROFILES ===
def _profile_inventory(tmp_path, **kwargs):
    payload = {"profiles": {
        "prod": {"managers": [{"name": "p1", "role": "lm", "host": "p"}]},
        "dr": {"managers": [{"name": "d1", "role": "lm", "host": "d"}]}}}
    payload.update(kwargs)
    return write_json(tmp_path, "inventory.json", payload)


def test_a_flat_inventory_still_loads_and_has_no_profiles(tmp_path):
    """Every config that exists today is this shape. It must never break."""
    path = write_json(tmp_path, "inventory.json",
                      {"managers": [{"name": "lm1", "role": "lm",
                                     "host": "h"}]})
    assert list_profiles(path) == []
    assert resolve_profile(path) == (None, "single estate")
    assert len(load_inventory(path)) == 1


def test_profile_selects_one_estate(tmp_path):
    path = _profile_inventory(tmp_path)
    assert list_profiles(path) == ["dr", "prod"]
    managers = load_inventory(path, profile="dr")
    assert [m["name"] for m in managers] == ["d1"]


def test_several_profiles_and_no_default_refuses_to_guess(tmp_path):
    """Guessing which estate to talk to is the one wrong answer that matters."""
    path = _profile_inventory(tmp_path)
    with pytest.raises(ConfigError, match="Choose one with --profile"):
        resolve_profile(path)


def test_default_profile_is_honoured(tmp_path):
    path = _profile_inventory(tmp_path, default_profile="prod")
    assert resolve_profile(path)[0] == "prod"


def test_explicit_profile_beats_the_default(tmp_path):
    path = _profile_inventory(tmp_path, default_profile="prod")
    assert resolve_profile(path, "dr")[0] == "dr"


def test_the_environment_is_read_when_nothing_else_says(tmp_path,
                                                        monkeypatch):
    path = _profile_inventory(tmp_path)
    monkeypatch.setenv("NSX_PROFILE", "dr")
    assert resolve_profile(path)[0] == "dr"


def test_a_single_profile_needs_no_default(tmp_path):
    path = write_json(tmp_path, "inventory.json", {"profiles": {
        "only": {"managers": [{"name": "m", "role": "lm", "host": "h"}]}}})
    assert resolve_profile(path) == ("only", "the only profile")


def test_an_unknown_profile_lists_the_real_ones(tmp_path):
    path = _profile_inventory(tmp_path)
    with pytest.raises(ConfigError, match="Known: dr, prod"):
        resolve_profile(path, "staging")


def test_profile_on_a_flat_inventory_says_so(tmp_path):
    path = write_json(tmp_path, "inventory.json",
                      {"managers": [{"name": "m", "role": "lm", "host": "h"}]})
    with pytest.raises(ConfigError, match="has no profiles"):
        resolve_profile(path, "prod")


# === PROJECTS ===
def test_project_scoping_changes_the_policy_base(lm, make_session):
    """A project has its own infra tree, so the base swaps rather than a
    filter being applied at each call site."""
    plain = make_session(lm)
    scoped = make_session(lm, project="tenant-a")
    assert plain.base("default") == "/policy/api/v1/infra"
    assert scoped.base("default") == \
        "/policy/api/v1/orgs/default/projects/tenant-a/infra"


def test_a_project_base_still_yields_a_policy_path_prefix():
    from nsx_toolkit.api import policy_path_prefix
    assert policy_path_prefix(
        "/policy/api/v1/orgs/default/projects/t1/infra") == \
        "/orgs/default/projects/t1/infra"
    assert policy_path_prefix("/policy/api/v1/infra") == "/infra"


def test_projects_are_listed_from_the_org(lm, make_session):
    lm.state.add_project("tenant-a", "Tenant A")
    session = make_session(lm)
    from nsx_toolkit.api import p_projects
    found = session.get_all(p_projects(session.org))
    assert [p["id"] for p in found] == ["tenant-a"]


# === DOCTOR ===
@pytest.fixture
def estate(lm):
    lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    lm.state.add_service("MySQL", protocol="TCP", ports=["3306"])
    lm.state.add_policy("app-tier", "App Tier")
    lm.state.add_rule("app-tier", "r1", action="ALLOW")
    return lm


def test_doctor_reports_every_surface_as_available(estate, make_session):
    probes, _version = probe_manager(make_session(estate), "default")
    by_name = {p.capability: p.status for p in probes}
    for capability in ("groups", "security policies", "services",
                       "vm inventory", "vifs", "logical ports", "traceflow"):
        assert by_name[capability] == OK, capability


def test_doctor_names_a_missing_surface_rather_than_failing(estate,
                                                            make_session):
    estate.state.stats_unsupported = True
    estate.state.traceflow_unsupported = True
    probes, _version = probe_manager(make_session(estate), "default")
    by_name = {p.capability: p.status for p in probes}
    assert by_name["traceflow"] == MISSING
    assert by_name["rule statistics"] == MISSING
    # Everything else still answers -- a missing surface is not an outage.
    assert by_name["groups"] == OK


def test_doctor_never_injects_a_packet(estate, make_session):
    """A capability check that ran a traceflow would put real traffic on the
    data plane every time somebody asked what their NSX supports."""
    act_doctor([make_session(estate)], "default", Exporter())
    assert estate.state.count("POST /api/v1/traceflow") == 0
    assert estate.state.traceflow_deleted == []


def test_doctor_marks_lm_only_surfaces_as_not_applicable_on_a_gm(gm,
                                                                 make_session):
    gm.state.add_group("g", origin="GM")
    probes, _version = probe_manager(make_session(gm), "default")
    by_name = {p.capability: p.status for p in probes}
    assert by_name["traceflow"] == NA
    assert by_name["vm inventory"] == NA


def test_doctor_reports_healthy_and_unhealthy(estate, make_session):
    _probes, healthy = act_doctor([make_session(estate)], "default",
                                  Exporter())
    assert healthy is True
    estate.state.traceflow_unsupported = True
    _probes, healthy = act_doctor([make_session(estate)], "default",
                                  Exporter())
    assert healthy is False


def test_doctor_stages_findings_for_machine_output(estate, make_session):
    exporter = Exporter()
    estate.state.traceflow_unsupported = True
    act_doctor([make_session(estate)], "default", exporter)
    findings = exporter.findings
    assert any(f["check"] == "traceflow" and not f["passed"] for f in findings)
    assert any(f["passed"] for f in findings)


# === READ COMMANDS ===
def test_rule_list_is_in_evaluation_order(lm, make_session):
    infra = lm.state.add_policy("infra", "Infra")
    infra["category"] = "Infrastructure"
    app = lm.state.add_policy("app", "App")
    app["category"] = "Application"
    lm.state.add_rule("app", "early", sequence_number=1)
    lm.state.add_rule("infra", "late", sequence_number=999)
    rows = act_rule_list([make_session(lm)], "default", Exporter())
    assert [r[5] for r in rows] == ["late", "early"]


def test_rule_list_filters(estate, make_session):
    estate.state.add_rule("app-tier", "drop-me", action="DROP")
    session = make_session(estate)
    assert len(act_rule_list([session], "default", Exporter(),
                             action="DROP")) == 1
    assert len(act_rule_list([session], "default", Exporter(),
                             contains="drop")) == 1
    assert act_rule_list([session], "default", Exporter(),
                         policy_ref="nope") == []


def test_policy_list_counts_rules(estate, make_session):
    rows = act_policy_list([make_session(estate)], "default", Exporter())
    assert rows[0][4] == "app-tier"
    assert rows[0][6] == "1"


def test_service_list_says_which_services_trace_can_decide(estate,
                                                           make_session):
    estate.state.add_service("Ping", entries=[
        {"resource_type": "ICMPTypeServiceEntry"}])
    rows = act_service_list([make_session(estate)], "default", Exporter())
    kinds = {r[0]: r[4] for r in rows}
    assert kinds["MySQL"] == "L4 port set"
    assert kinds["Ping"] != "L4 port set"


def test_describe_service_reports_ports():
    assert describe_service({"service_entries": [
        {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP",
         "destination_ports": ["443", "8443"]}]}) == ("TCP", "443,8443",
                                                      "L4 port set")


# === NAME CACHE ===
def test_the_cache_round_trips(tmp_path):
    root = str(tmp_path)
    namecache.update_cache(namecache.KIND_GROUP, ["g-web", "g-db"], root=root)
    assert namecache.cached_names(namecache.KIND_GROUP, root=root) == [
        "g-db", "g-web"]


def test_updating_one_kind_leaves_the_others_alone(tmp_path):
    """`group list --contains web` is a filtered view; replacing would shrink
    the cache to whatever the last filtered command happened to return."""
    root = str(tmp_path)
    namecache.update_cache(namecache.KIND_GROUP, ["g-web"], root=root)
    namecache.update_cache(namecache.KIND_POLICY, ["app-tier"], root=root)
    namecache.update_cache(namecache.KIND_GROUP, ["g-db"], root=root)
    assert namecache.cached_names(namecache.KIND_GROUP, root=root) == [
        "g-db", "g-web"]
    assert namecache.cached_names(namecache.KIND_POLICY, root=root) == [
        "app-tier"]


def test_a_missing_cache_reads_as_empty_never_raises(tmp_path):
    """Completion runs in a shell hook, where a traceback lands on the prompt."""
    assert namecache.cached_names("groups", root=str(tmp_path / "nope")) == []
    assert namecache.cache_age(root=str(tmp_path / "nope")) is None


def test_a_corrupt_cache_reads_as_empty(tmp_path):
    path = namecache.cache_path(root=str(tmp_path))
    (tmp_path).mkdir(exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not json")
    assert namecache.cached_names("groups", root=str(tmp_path)) == []


def test_profiles_and_projects_get_separate_caches(tmp_path):
    """Completing production names into a DR command is worse than completing
    nothing."""
    root = str(tmp_path)
    namecache.update_cache("groups", ["prod-only"], profile="prod", root=root)
    namecache.update_cache("groups", ["dr-only"], profile="dr", root=root)
    assert namecache.cached_names("groups", profile="prod", root=root) == [
        "prod-only"]
    assert namecache.cached_names("groups", profile="dr", root=root) == [
        "dr-only"]


def test_refresh_reads_every_kind(estate, make_session):
    import tempfile
    with tempfile.TemporaryDirectory() as root:
        path, counts = namecache.refresh_from_nsx(
            [make_session(estate)], "default", root=root)
        assert path
        assert counts["groups"] >= 1
        assert counts["policies"] >= 1
        assert counts["services"] >= 1


def test_list_commands_warm_the_cache(estate, make_session, tmp_path,
                                      monkeypatch):
    monkeypatch.setattr(namecache, "CACHE_DIR", str(tmp_path))
    act_policy_list([make_session(estate)], "default", Exporter(),
                    cache_key=(None, None))
    assert "app-tier" in namecache.cached_names(namecache.KIND_POLICY)


# === SINKS ===
def _findings():
    return [
        sinks.make_finding("any_any_allow", "critical", "wide open",
                           where="app/r1", detail="src and dst are ANY"),
        sinks.make_finding("drop_not_logged", "medium", "no log",
                           where="app/r2"),
        sinks.make_finding("groups", "ok", "fine", where="lm1", passed=True),
    ]


def test_junit_reports_failures_and_passes():
    xml = sinks.render_junit({"rule_hygiene": _findings()})
    assert 'failures="2"' in xml
    assert "<failure" in xml
    assert "any_any_allow" in xml


def test_junit_emits_a_testcase_even_with_no_findings():
    """An empty suite reads as 'did not run' in most CI UIs -- exactly the
    wrong thing to show for a clean estate."""
    xml = sinks.render_junit({"rule_hygiene": []})
    assert "<testcase" in xml and 'failures="0"' in xml


def test_junit_escapes_hostile_text():
    xml = sinks.render_junit({"s": [sinks.make_finding(
        "c", "high", 'a "quoted" & <angled> name', where="x")]})
    assert "&amp;" in xml or "&quot;" in xml
    import xml.etree.ElementTree as ET
    ET.fromstring(xml)   # parses, so the escaping is real


def test_sarif_maps_severities_and_skips_passes():
    doc = json.loads(sinks.render_sarif(_findings()))
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    assert {r["level"] for r in results} == {"error", "warning"}


def test_sarif_uses_a_logical_location_not_a_fake_file():
    """NSX objects are not files; a fake file path would make a UI offer to
    open one."""
    doc = json.loads(sinks.render_sarif(_findings()))
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert "logicalLocations" in location
    assert "physicalLocation" not in location


def test_metrics_carry_a_gauge_per_severity_and_a_timestamp():
    text = sinks.render_metrics("rule hygiene", _findings())
    assert 'nsxctl_findings{command="rule_hygiene",severity="critical"} 1' in text
    assert "nsxctl_last_run_timestamp_seconds" in text


def test_metrics_emit_a_zero_when_clean():
    """An alert rule needs a series that exists and reads zero, not one that
    vanishes."""
    text = sinks.render_metrics("drift", [])
    assert 'severity="none"} 0' in text


def test_a_fingerprint_ignores_when_the_run_happened():
    first = sinks.fingerprint(_findings())
    second = sinks.fingerprint(list(reversed(_findings())))
    assert first == second


def test_a_changed_finding_changes_the_fingerprint():
    changed = _findings()
    changed[0]["severity"] = "low"
    assert sinks.fingerprint(_findings()) != sinks.fingerprint(changed)


def test_quiet_unless_changed_state(tmp_path):
    root = str(tmp_path)
    changed, previous = sinks.changed_since_last("hygiene", _findings(),
                                                 root=root)
    assert changed is True and previous == {}
    sinks.save_state("hygiene", sinks.fingerprint(_findings()), {}, root=root)
    changed, previous = sinks.changed_since_last("hygiene", _findings(),
                                                 root=root)
    assert changed is False and previous["fingerprint"]


def test_a_webhook_refuses_a_non_http_url():
    from nsx_toolkit.errors import NsxError
    with pytest.raises(NsxError, match="http or https"):
        sinks.post_webhook("file:///etc/passwd", {})


def test_output_buffering_can_be_dropped_or_flushed(capsys):
    output.start_buffering()
    output.say("secret")
    assert capsys.readouterr().out == ""
    assert output.drop_buffered() == 1
    assert capsys.readouterr().out == ""

    output.start_buffering()
    output.say("kept")
    output.flush_buffered()
    assert "kept" in capsys.readouterr().out


# === FLOWS ===
FLOW_CSV = """src_ip,dst_ip,dst_port,protocol,action,flows
10.1.1.10,10.1.2.20,3306,tcp,ALLOW,842
10.1.1.11,10.1.2.20,3306,tcp,ALLOW,71
10.1.1.10,10.9.9.9,443,tcp,ALLOW,5
10.1.1.10,10.1.2.20,3307,tcp,DROP,3
"""


@pytest.fixture
def flow_estate(lm):
    lm.state.add_group("g-web", "Web", expression=IP_CRITERIA_WEB)
    lm.state.add_group("g-db", "DB", expression=IP_CRITERIA_DB)
    lm.state.add_policy("app-tier", "App Tier")
    return lm


def _flow_file(tmp_path, text=FLOW_CSV, name="flows.csv"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_flow_columns_are_matched_loosely(tmp_path):
    flows, problems = read_flows(_flow_file(tmp_path))
    assert problems == []
    # The DROP row is excluded: a blocked flow is evidence segmentation works.
    assert len(flows) == 3
    assert flows[0].port == 3306 and flows[0].protocol == "tcp"


def test_denied_flows_are_included_only_when_asked(tmp_path):
    flows, _ = read_flows(_flow_file(tmp_path), include_denied=True)
    assert len(flows) == 4


def test_a_json_flow_export_reads_too(tmp_path):
    path = write_json(tmp_path, "flows.json", [
        {"source": "10.1.1.10", "destination": "10.1.2.20", "port": 3306}])
    flows, problems = read_flows(path)
    assert len(flows) == 1 and problems == []


def test_a_bad_row_is_reported_not_fatal(tmp_path):
    path = _flow_file(tmp_path, "src_ip,dst_ip,dst_port\n10.1.1.1,,80\n"
                                "10.1.1.1,10.1.2.2,notaport\n"
                                "10.1.1.1,10.1.2.2,80\n")
    flows, problems = read_flows(path)
    assert len(flows) == 1
    assert len(problems) == 2


def test_an_address_resolves_through_a_cidr(flow_estate, make_session):
    from nsx_toolkit.policy import group_inventory
    groups = group_inventory([make_session(flow_estate)], "default")
    index = build_address_index(groups)
    assert resolve_address("10.1.1.10", index)          # inside 10.1.1.0/24
    assert resolve_address("10.1.2.20", index)          # exact
    assert resolve_address("10.9.9.9", index) == []     # nobody claims it


def test_proposals_aggregate_ports_per_pair(flow_estate, make_session,
                                            tmp_path):
    from nsx_toolkit.policy import group_inventory
    flows, _ = read_flows(_flow_file(tmp_path))
    groups = group_inventory([make_session(flow_estate)], "default")
    proposals, unresolved, wide = propose_rules(flows, groups)
    assert len(proposals) == 1
    assert proposals[0].ports == [3306]
    assert proposals[0].flow_count == 913        # 842 + 71
    assert wide == []
    # 10.9.9.9 belongs to no group and is reported rather than guessed at.
    assert [u.address for u in unresolved] == ["10.9.9.9"]


def test_a_pair_talking_on_many_ports_is_flagged_not_ruled(flow_estate,
                                                            make_session,
                                                            tmp_path):
    rows = ["src_ip,dst_ip,dst_port,protocol"]
    rows += ["10.1.1.10,10.1.2.20,{},tcp".format(p) for p in range(1, 30)]
    from nsx_toolkit.policy import group_inventory
    flows, _ = read_flows(_flow_file(tmp_path, "\n".join(rows) + "\n"))
    groups = group_inventory([make_session(flow_estate)], "default")
    proposals, _unresolved, wide = propose_rules(flows, groups, max_ports=12)
    assert proposals == []
    assert len(wide) == 1 and len(wide[0].ports) == 29


def test_the_proposal_is_an_apply_change_file(flow_estate, make_session,
                                              tmp_path):
    out = str(tmp_path / "proposed.json")
    act_recommend([make_session(flow_estate)], "default", Exporter(),
                  _flow_file(tmp_path), policy="app-tier", out_file=out)
    with open(out, encoding="utf-8") as f:
        document = json.load(f)
    assert document["rules"][0]["policy"] == "app-tier"
    assert document["rules"][0]["action"] == "ALLOW"

    # And it is a document `nsxctl apply` actually accepts.
    from nsx_toolkit.authoring import load_change_file
    assert load_change_file(out)["rules"]


def test_writing_a_change_file_needs_a_policy(flow_estate, make_session,
                                              tmp_path):
    with pytest.raises(ConfigError, match="needs --policy"):
        act_recommend([make_session(flow_estate)], "default", Exporter(),
                      _flow_file(tmp_path),
                      out_file=str(tmp_path / "out.json"))


def test_recommend_never_proposes_a_default_deny(flow_estate, make_session,
                                                 tmp_path):
    """No traffic seen in one window is not evidence none exists -- the same
    reason a zero hit count cannot retire a rule."""
    out = str(tmp_path / "proposed.json")
    act_recommend([make_session(flow_estate)], "default", Exporter(),
                  _flow_file(tmp_path), policy="app-tier", out_file=out)
    with open(out, encoding="utf-8") as f:
        document = json.load(f)
    assert all(r["action"] == "ALLOW" for r in document["rules"])
    assert not any("ANY" in str(r.get("source")) for r in document["rules"])


# === SNAPSHOT RESTORE ===
@pytest.fixture
def restore_estate(lm):
    lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    lm.state.add_policy("app-tier", "App Tier")
    lm.state.add_rule("app-tier", "allow-web", action="ALLOW")
    return lm


def _snapshot_of(session, domain="default"):
    from nsx_toolkit.snapshot import capture_snapshot
    return capture_snapshot([session], domain)


def _restore(session, snapshot, audit, prune=False):
    from nsx_toolkit.actions.author import act_restore

    class Ctx:
        sessions = [session]
        domain = "default"
        write_enabled = True
        exporter = Exporter()

    ctx = Ctx()
    ctx.audit = audit
    output.set_assume_yes(True)
    try:
        return act_restore(ctx, snapshot, dry_run=False, prune=prune)
    finally:
        output.set_assume_yes(False)


@pytest.fixture
def audit_log(tmp_path):
    from nsx_toolkit.audit import AuditLog
    return AuditLog(path=str(tmp_path / "audit.log"))


def test_restore_puts_a_changed_rule_back(restore_estate, make_session,
                                          audit_log):
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    restore_estate.state.touch("rule", "allow-web", pid="app-tier",
                               user="dave", action="DROP")
    assert restore_estate.state.rules["app-tier"][0]["action"] == "DROP"

    result = _restore(session, snapshot, audit_log)
    assert result.applied == 1
    assert restore_estate.state.rules["app-tier"][0]["action"] == "ALLOW"


def test_restoring_an_unchanged_estate_plans_nothing(restore_estate,
                                                     make_session, audit_log):
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    result = _restore(session, snapshot, audit_log)
    assert result.planned == 0
    assert restore_estate.state.count("PUT ") == 0


def test_restore_leaves_objects_the_snapshot_never_mentioned(restore_estate,
                                                             make_session,
                                                             audit_log):
    """A snapshot records what was there; it does not assert that nothing else
    may exist. A group created legitimately since is not drift to be erased."""
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    restore_estate.state.add_group("g-new", "Added later",
                                   expression=VM_CRITERIA)

    _restore(session, snapshot, audit_log)
    assert "g-new" in [g["id"] for g in restore_estate.state.groups]


def test_prune_deletes_what_the_snapshot_does_not_have(restore_estate,
                                                       make_session,
                                                       audit_log):
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    restore_estate.state.add_group("g-new", "Added later",
                                   expression=VM_CRITERIA)

    _restore(session, snapshot, audit_log, prune=True)
    assert "g-new" not in [g["id"] for g in restore_estate.state.groups]


def test_restore_is_audited_per_object(restore_estate, make_session,
                                       audit_log):
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    restore_estate.state.touch("rule", "allow-web", pid="app-tier",
                               action="DROP")
    _restore(session, snapshot, audit_log)
    entry = audit_log.last_n_normalised(1)[0]
    assert entry["object_type"] == "rule"
    assert entry["before"]["action"] == "DROP"
    assert entry["after"]["action"] == "ALLOW"


def test_a_concurrent_edit_during_restore_is_refused(restore_estate,
                                                     make_session, audit_log):
    """Restore goes through the same _revision check as any other write."""
    from nsx_toolkit.actions.author import PlanCache, plan_restore
    session = make_session(restore_estate)
    snapshot = _snapshot_of(session)
    restore_estate.state.touch("rule", "allow-web", pid="app-tier",
                               action="DROP")
    changes = plan_restore([session], "default", snapshot,
                           cache=PlanCache([session], "default"))
    # Somebody else edits it again after the plan was built.
    restore_estate.state.touch("rule", "allow-web", pid="app-tier",
                               user="dave", action="REJECT")

    from nsx_toolkit.actions.author import execute_plan
    output.set_assume_yes(True)
    try:
        result = execute_plan(changes, audit_log, write_enabled=True,
                              dry_run=False, sessions=[session],
                              exporter=Exporter())
    finally:
        output.set_assume_yes(False)
    assert result.failed == 1 and result.applied == 0
    assert restore_estate.state.rules["app-tier"][0]["action"] == "REJECT"
