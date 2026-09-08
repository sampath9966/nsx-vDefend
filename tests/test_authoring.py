"""Rule and group authoring.

The load-bearing tests here are the refusals: that a stale write is rejected
rather than clobbering someone's change, that a dry run writes nothing, that
criteria which would not mean what it reads as is refused rather than sent,
and that an object realized read-only from the Global Manager is not written
through a Local Manager.
"""

import json

import pytest

from nsx_toolkit import output
from nsx_toolkit.actions.author import (
    execute_plan,
    find_policy,
    find_rule,
    plan_change_file,
    plan_group,
    plan_rows,
    plan_rule,
    preflight_findings,
    undo_object_entry,
)
from nsx_toolkit.audit import OBJ_GROUP, OBJ_RULE, AuditLog, normalise_entry
from nsx_toolkit.authoring import (
    OP_CREATE,
    OP_DELETE,
    OP_MODIFY,
    describe_criteria,
    load_change_file,
    parse_criteria,
    sequence_for_move,
)
from nsx_toolkit.errors import ConfigError, NsxError
from nsx_toolkit.export import Exporter
from nsx_toolkit.policy import sweep_rules

VM_CRITERIA = [{"resource_type": "Condition", "member_type": "VirtualMachine",
                "key": "Tag", "operator": "EQUALS", "value": "env|prod"}]


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=str(tmp_path / "audit.log"))


@pytest.fixture
def estate(lm):
    lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    lm.state.add_group("g-db", "DB", expression=VM_CRITERIA)
    lm.state.add_service("MySQL", protocol="TCP", ports=["3306"])
    lm.state.add_policy("app-tier", "App Tier")
    return lm


def apply_now(changes, audit, sessions, domain="default", force=False):
    output.set_assume_yes(True)
    try:
        return execute_plan(changes, audit, write_enabled=True, dry_run=False,
                            force=force, sessions=sessions, domain=domain,
                            exporter=Exporter())
    finally:
        output.set_assume_yes(False)


# === CRITERIA ===
def test_a_tag_condition_uses_the_scope_pipe_tag_form():
    expression = parse_criteria("tag:env=prod")
    assert expression == [{"resource_type": "Condition",
                           "member_type": "VirtualMachine", "key": "Tag",
                           "operator": "EQUALS", "value": "env|prod"}]


def test_and_puts_a_conjunction_between_terms():
    expression = parse_criteria("tag:env=prod AND tag:tier=web")
    assert [item["resource_type"] for item in expression] == [
        "Condition", "ConjunctionOperator", "Condition"]
    assert expression[1]["conjunction_operator"] == "AND"


def test_contains_and_name_and_ip_terms():
    assert parse_criteria("tag:owner~plat")[0]["operator"] == "CONTAINS"
    assert parse_criteria("name=web-01")[0]["key"] == "Name"
    assert parse_criteria("ip:10.0.0.0/8,10.1.2.3")[0]["ip_addresses"] == [
        "10.0.0.0/8", "10.1.2.3"]


def test_mixed_and_or_is_refused_rather_than_reinterpreted():
    """NSX applies one conjunction operator per expression. Sending this would
    silently select a different set of workloads than it reads as."""
    with pytest.raises(ConfigError, match="mixes AND and OR"):
        parse_criteria("tag:env=prod AND tag:tier=web OR tag:tier=api")


@pytest.mark.parametrize("text", [
    "AND tag:env=prod",
    "tag:env=prod AND",
    "tag:env=prod AND AND tag:tier=web",
    "tag:env",
    "colour:blue",
    "",
])
def test_malformed_criteria_is_refused(text):
    with pytest.raises(ConfigError):
        parse_criteria(text)


def test_criteria_round_trips_back_to_something_readable():
    assert describe_criteria(parse_criteria("tag:env=prod AND name~web")) == \
        "tag:env=prod AND name~web"


# === PLANNING ===
def test_creating_a_group_plans_one_create(estate, make_session):
    changes = plan_group([make_session(estate)], "default", "g-api",
                         criteria="tag:tier=api")
    assert len(changes) == 1
    assert changes[0].op == OP_CREATE
    assert changes[0].before is None


def test_editing_a_group_plans_a_modify_with_a_field_diff(estate,
                                                          make_session):
    changes = plan_group([make_session(estate)], "default", "g-web",
                         criteria="tag:env=staging")
    assert changes[0].op == OP_MODIFY
    rows = plan_rows(changes)
    assert any(row[4].startswith("expression") for row in rows)
    assert all(row[7] == "security" for row in rows
               if row[4].startswith("expression"))


def test_an_edit_that_changes_nothing_plans_nothing(estate, make_session):
    """Re-applying the state NSX is already in is not a write."""
    session = make_session(estate)
    assert plan_group([session], "default", "g-web",
                      criteria="tag:env=prod") == []


def test_creating_a_group_with_no_criteria_is_refused(estate, make_session):
    with pytest.raises(NsxError, match="needs --criteria"):
        plan_group([make_session(estate)], "default", "g-new")


def test_a_new_rule_gets_a_sequence_number_after_the_last_one(estate,
                                                              make_session):
    estate.state.add_rule("app-tier", "existing", sequence_number=10)
    changes = plan_rule([make_session(estate)], "default", "new-rule",
                        policy_ref="app-tier", action="DROP")
    assert changes[0].after["sequence_number"] == 20


def test_group_and_service_names_resolve_to_paths(estate, make_session):
    changes = plan_rule([make_session(estate)], "default", "allow-web-db",
                        policy_ref="app-tier", sources=["g-web"],
                        destinations=["DB"], services=["MySQL"],
                        action="ALLOW")
    body = changes[0].after
    assert body["source_groups"] == ["/infra/domains/default/groups/g-web"]
    assert body["destination_groups"] == ["/infra/domains/default/groups/g-db"]
    assert body["services"] == ["/infra/services/MySQL"]


def test_an_unknown_group_name_is_refused_before_any_write(estate,
                                                           make_session):
    with pytest.raises(NsxError, match="No group called"):
        plan_rule([make_session(estate)], "default", "r1",
                  policy_ref="app-tier", sources=["g-nope"])


def test_an_invalid_action_is_refused(estate, make_session):
    with pytest.raises(ConfigError, match="action must be"):
        plan_rule([make_session(estate)], "default", "r1",
                  policy_ref="app-tier", action="PERMIT")


def test_creating_a_rule_needs_a_policy(estate, make_session):
    with pytest.raises(NsxError, match="needs --policy"):
        plan_rule([make_session(estate)], "default", "r1", action="ALLOW")


def test_an_ambiguous_rule_name_asks_for_the_policy(estate, make_session):
    estate.state.add_policy("other", "Other")
    estate.state.add_rule("app-tier", "shared")
    estate.state.add_rule("other", "shared")
    with pytest.raises(NsxError, match="Narrow it with --policy"):
        find_rule([make_session(estate)], "default", "shared")


def test_a_policy_resolves_by_id_or_display_name(estate, make_session):
    session = make_session(estate)
    by_id = find_policy([session], "default", "app-tier")[1]
    by_name = find_policy([session], "default", "App Tier")[1]
    assert by_id["id"] == by_name["id"] == "app-tier"


# === GM-AUTHORED OBJECTS ===
def test_a_gm_authored_group_is_not_written_through_an_lm(lm, make_session):
    """NSX realizes GM objects read-only onto each LM. Writing there fails
    inside NSX with a message that reads like a bug in this tool."""
    lm.state.add_group("g-global", "Global", origin="GM",
                       expression=VM_CRITERIA)
    with pytest.raises(NsxError, match="realized read-only"):
        plan_group([make_session(lm)], "default", "g-global",
                   criteria="tag:env=dev")


# === WRITES ===
def test_a_dry_run_writes_nothing(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-api", criteria="tag:tier=api")
    execute_plan(changes, audit, write_enabled=True, dry_run=True,
                 sessions=[session], exporter=Exporter())
    assert estate.state.count("PUT ") == 0
    assert len(estate.state.groups) == 2


def test_writes_disabled_blocks_the_apply(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-api", criteria="tag:tier=api")
    result = execute_plan(changes, audit, write_enabled=False, dry_run=False,
                          sessions=[session], exporter=Exporter())
    assert result.blocked == 1 and result.applied == 0
    assert estate.state.count("PUT ") == 0


def test_creating_a_group_for_real(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-api", criteria="tag:tier=api")
    result = apply_now(changes, audit, [session])
    assert result.applied == 1
    created = next(g for g in estate.state.groups if g["id"] == "g-api")
    assert created["expression"][0]["value"] == "tier|api"


def test_a_stale_revision_is_refused_rather_than_clobbering(estate,
                                                            make_session,
                                                            audit):
    """The safety mechanism is NSX's own: the plan carries the _revision it
    read, and somebody else's edit in between makes the write fail."""
    session = make_session(estate)
    changes = plan_group([session], "default", "g-web",
                         criteria="tag:env=staging")
    # Somebody edits the same group in the UI after the plan was built.
    estate.state.touch("group", "g-web", user="dave", display_name="Web (edited)")

    result = apply_now(changes, audit, [session])
    assert result.applied == 0 and result.failed == 1
    live = next(g for g in estate.state.groups if g["id"] == "g-web")
    assert live["display_name"] == "Web (edited)"
    assert live["expression"][0]["value"] == "env|prod"


def test_force_overrides_the_revision_check(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-web",
                         criteria="tag:env=staging")
    estate.state.touch("group", "g-web", user="dave")
    result = apply_now(changes, audit, [session], force=True)
    assert result.applied == 1
    live = next(g for g in estate.state.groups if g["id"] == "g-web")
    assert live["expression"][0]["value"] == "env|staging"


def test_deleting_a_group(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-db", delete=True)
    assert changes[0].op == OP_DELETE
    apply_now(changes, audit, [session])
    assert [g["id"] for g in estate.state.groups] == ["g-web"]


def test_creating_a_rule_for_real(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_rule([session], "default", "allow-web-db",
                        policy_ref="app-tier", sources=["g-web"],
                        destinations=["g-db"], services=["MySQL"],
                        action="ALLOW")
    apply_now(changes, audit, [session])
    rule = estate.state.rules["app-tier"][0]
    assert rule["id"] == "allow-web-db"
    assert rule["action"] == "ALLOW"


# === MOVE ===
def test_move_before_picks_a_number_in_the_gap(estate, make_session):
    estate.state.add_rule("app-tier", "first", sequence_number=10)
    estate.state.add_rule("app-tier", "second", sequence_number=30)
    session = make_session(estate)
    records = list(sweep_rules([session], "default"))
    target = next(r for r in records if r.rule_id == "second")
    assert 10 < sequence_for_move(records, target, before=True) < 30


def test_move_refuses_rather_than_renumbering_the_whole_policy(estate,
                                                               make_session):
    """Rewriting every rule's sequence to make room is a far bigger change
    than the one that was asked for, and on a shared policy it is other
    people's diff too."""
    estate.state.add_rule("app-tier", "first", sequence_number=10)
    estate.state.add_rule("app-tier", "second", sequence_number=11)
    session = make_session(estate)
    records = list(sweep_rules([session], "default"))
    target = next(r for r in records if r.rule_id == "second")
    with pytest.raises(NsxError, match="needs renumbering"):
        sequence_for_move(records, target, before=True)


# === PREFLIGHT ===
def test_an_any_any_allow_is_caught_before_it_is_written(estate,
                                                         make_session):
    """The whole payoff of sequencing authoring after rule hygiene."""
    session = make_session(estate)
    changes = plan_rule([session], "default", "wide-open",
                        policy_ref="app-tier", action="ALLOW")
    findings = preflight_findings(changes[0], [session], "default")
    assert "any_any_allow" in {f.check for f in findings}


def test_a_well_scoped_rule_triggers_no_preflight_findings(estate,
                                                           make_session):
    session = make_session(estate)
    estate.state.group_members["g-web"] = [{"display_name": "web1"}]
    estate.state.group_members["g-db"] = [{"display_name": "db1"}]
    changes = plan_rule([session], "default", "allow-web-db",
                        policy_ref="app-tier", sources=["g-web"],
                        destinations=["g-db"], services=["MySQL"],
                        scope=["g-web"], action="ALLOW")
    assert preflight_findings(changes[0], [session], "default") == []


# === DECLARATIVE APPLY ===
def _write_change_file(tmp_path, payload, name="changes.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_a_change_file_plans_groups_and_rules(estate, make_session, tmp_path):
    path = _write_change_file(tmp_path, {
        "groups": [{"id": "g-api", "criteria": "tag:tier=api"}],
        "rules": [{"id": "allow-api", "policy": "app-tier",
                   "source": "g-web", "destination": ["g-db"],
                   "action": "ALLOW"}]})
    changes = plan_change_file([make_session(estate)], "default", path)
    assert [c.kind for c in changes] == ["group", "rule"]


def test_state_absent_plans_a_delete(estate, make_session, tmp_path):
    path = _write_change_file(tmp_path, {
        "groups": [{"id": "g-db", "state": "absent"}]})
    changes = plan_change_file([make_session(estate)], "default", path)
    assert changes[0].op == OP_DELETE


def test_a_change_file_that_matches_nsx_plans_nothing(estate, make_session,
                                                      tmp_path):
    path = _write_change_file(tmp_path, {
        "groups": [{"id": "g-web", "display_name": "Web",
                    "criteria": "tag:env=prod"}]})
    assert plan_change_file([make_session(estate)], "default", path) == []


@pytest.mark.parametrize("payload,match", [
    ({"gruops": []}, "unknown section"),
    ({"groups": {}}, "must be a list"),
    ({"groups": [{"criteria": "tag:a=b"}]}, "has no 'id'"),
    ({"groups": [{"id": "g", "state": "maybe"}]}, "state must be"),
])
def test_a_malformed_change_file_is_refused(tmp_path, payload, match):
    path = _write_change_file(tmp_path, payload)
    with pytest.raises(ConfigError, match=match):
        load_change_file(path)


def test_a_change_file_that_is_not_json_says_so(tmp_path):
    path = tmp_path / "changes.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_change_file(str(path))


# === AUDIT ===
def test_an_object_write_is_audited_with_both_sides(estate, make_session,
                                                    audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-web",
                         criteria="tag:env=staging")
    apply_now(changes, audit, [session])
    entry = audit.last_n_normalised(1)[0]
    assert entry["object_type"] == OBJ_GROUP
    assert entry["before"]["expression"][0]["value"] == "env|prod"
    assert entry["after"]["expression"][0]["value"] == "env|staging"


def test_a_failed_write_is_audited_too(estate, make_session, audit):
    session = make_session(estate)
    changes = plan_group([session], "default", "g-web",
                         criteria="tag:env=staging")
    estate.state.touch("group", "g-web", user="dave")
    apply_now(changes, audit, [session])
    entry = audit.last_n_normalised(1)[0]
    assert entry["status"] == "failed"


def test_a_pre_authoring_tag_entry_still_reads_and_undoes(tmp_path):
    """A log written before authoring existed has no object_type at all. It
    must still list, and still undo, exactly as it did."""
    path = tmp_path / "old-audit.log"
    path.write_text(json.dumps({
        "timestamp": "2026-01-01T00:00:00Z", "user": "sam",
        "manager": "lm1", "action": "bulk_update_tags",
        "vm_display_name": "web01", "vm_external_id": "ext-web01",
        "tags_before": [{"scope": "env", "tag": "dev"}],
        "tags_after": [{"scope": "env", "tag": "prod"}],
        "status": "success", "detail": ""}) + "\n", encoding="utf-8")
    entry = AuditLog(path=str(path)).last_n_normalised(1)[0]
    assert entry["object_type"] == "vm_tags"
    assert entry["object_name"] == "web01"
    assert entry["before"] == [("env", "dev")]
    assert entry["after"] == [("env", "prod")]
    # The fields the tag undo path reads are still there, untouched.
    assert entry["raw"]["vm_external_id"] == "ext-web01"


def test_a_tag_entry_written_now_still_carries_the_old_fields(audit):
    audit.log("bulk_update_tags", "lm1", "web01", "ext-1",
              [("env", "dev")], [("env", "prod")])
    raw = audit.last_n(1)[0]
    assert raw["vm_display_name"] == "web01"
    assert raw["tags_before"] == [{"scope": "env", "tag": "dev"}]
    assert raw["object_type"] == "vm_tags"
    assert normalise_entry(raw)["before"] == [("env", "dev")]


# === UNDO ===
def test_undoing_a_create_deletes_it(estate, make_session, audit):
    session = make_session(estate)
    apply_now(plan_group([session], "default", "g-api",
                         criteria="tag:tier=api"), audit, [session])
    entry = audit.last_n_normalised(1)[0]

    output.set_assume_yes(True)
    try:
        undo_object_entry(entry, [session], "default", audit)
    finally:
        output.set_assume_yes(False)
    assert "g-api" not in [g["id"] for g in estate.state.groups]


def test_undoing_a_modify_restores_the_before_body(estate, make_session,
                                                   audit):
    session = make_session(estate)
    apply_now(plan_group([session], "default", "g-web",
                         criteria="tag:env=staging"), audit, [session])
    entry = audit.last_n_normalised(1)[0]

    output.set_assume_yes(True)
    try:
        undo_object_entry(entry, [session], "default", audit)
    finally:
        output.set_assume_yes(False)
    live = next(g for g in estate.state.groups if g["id"] == "g-web")
    assert live["expression"][0]["value"] == "env|prod"


def test_undoing_a_delete_recreates_it_but_says_it_cannot_promise(
        estate, make_session, audit, capsys):
    session = make_session(estate)
    apply_now(plan_group([session], "default", "g-db", delete=True), audit,
              [session])
    entry = audit.last_n_normalised(1)[0]
    assert entry["object_type"] == OBJ_GROUP

    output.set_assume_yes(True)
    try:
        undo_object_entry(entry, [session], "default", audit)
    finally:
        output.set_assume_yes(False)
    assert "g-db" in [g["id"] for g in estate.state.groups]
    assert "cannot be guaranteed" in capsys.readouterr().out


def test_undoing_a_rule_write(estate, make_session, audit):
    session = make_session(estate)
    estate.state.add_rule("app-tier", "r1", action="ALLOW")
    apply_now(plan_rule([session], "default", "r1", action="DROP"), audit,
              [session])
    assert estate.state.rules["app-tier"][0]["action"] == "DROP"

    entry = audit.last_n_normalised(1)[0]
    assert entry["object_type"] == OBJ_RULE
    output.set_assume_yes(True)
    try:
        undo_object_entry(entry, [session], "default", audit)
    finally:
        output.set_assume_yes(False)
    assert estate.state.rules["app-tier"][0]["action"] == "ALLOW"


# === ONE READ PER PLAN ===
def test_a_rule_can_reference_a_group_the_same_file_creates(estate,
                                                            make_session,
                                                            tmp_path, audit):
    """The central reason to write one file instead of two commands: the
    group does not exist to be looked up when the rule is planned."""
    path = _write_change_file(tmp_path, {
        "groups": [{"id": "g-api", "criteria": "tag:tier=api"}],
        "rules": [{"id": "allow-api-db", "policy": "app-tier",
                   "source": ["g-api"], "destination": ["g-db"],
                   "action": "ALLOW"}]})
    session = make_session(estate)
    changes = plan_change_file([session], "default", path)
    rule = next(c for c in changes if c.kind == "rule")
    assert rule.after["source_groups"] == [
        "/infra/domains/default/groups/g-api"]

    apply_now(changes, audit, [session])
    created = next(r for r in estate.state.rules["app-tier"]
                   if r["id"] == "allow-api-db")
    assert created["source_groups"] == ["/infra/domains/default/groups/g-api"]
    assert "g-api" in [g["id"] for g in estate.state.groups]


def test_planning_many_rules_reads_the_estate_once(estate, make_session,
                                                   tmp_path):
    """Planning N rules must not sweep the estate N times -- the same N+1 that
    made bulk tagging fetch the VM inventory once per CSV row."""
    estate.state.add_rule("app-tier", "existing", sequence_number=10)
    session = make_session(estate)
    entries = [{"id": "r{}".format(i), "policy": "app-tier",
                "source": ["g-web"], "destination": ["g-db"],
                "action": "ALLOW"} for i in range(6)]
    policies_path = "GET /policy/api/v1/infra/domains/default/security-policies"

    def reads_for(rules, name):
        path = _write_change_file(tmp_path, {"rules": rules}, name=name)
        before = estate.state.count(policies_path)
        plan_change_file([session], "default", path)
        return estate.state.count(policies_path) - before

    assert reads_for(entries, "six.json") == reads_for(entries[:1], "one.json")
