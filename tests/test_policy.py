"""The shared policy sweep that reverse lookup and rule hygiene both use."""

from fake_nsx import FakeNsx

from nsx_toolkit.policy import RuleRecord, group_inventory, ordered_sessions, sweep_rules


def test_global_managers_are_swept_first(make_session, lm, gm):
    """The dedup is order-dependent: GM must come first or a GM rule gets
    attributed to whichever Local Manager happened to be scanned earliest."""
    # Deliberately passed LM-first, to prove the ordering is imposed and not
    # merely inherited from the caller.
    sessions = [make_session(lm), make_session(gm)]
    gms, lms = ordered_sessions(sessions)
    assert [s.name for s in gms] == ["gm1"]
    assert [s.name for s in lms] == ["lm1"]


def test_sweep_returns_every_rule_on_one_manager(lm, make_session):
    lm.state.add_policy("p1", "Policy One")
    lm.state.add_rule("p1", "r1")
    lm.state.add_rule("p1", "r2")
    lm.state.add_policy("p2", "Policy Two")
    lm.state.add_rule("p2", "r3")

    records = sweep_rules([make_session(lm)], "default")
    assert sorted(r.rule_id for r in records) == ["r1", "r2", "r3"]
    assert {r.policy_name for r in records} == {"Policy One", "Policy Two"}
    assert all(r.origin == "LM" for r in records)


def test_a_gm_rule_realized_on_two_lms_appears_once(make_session):
    with FakeNsx(role="gm", name="gm") as gm, \
            FakeNsx(role="lm", name="lm1") as lm1, \
            FakeNsx(role="lm", name="lm2") as lm2:
        for fake in (gm, lm1, lm2):
            fake.state.add_policy("gpol", origin="GM")
            fake.state.add_rule("gpol", "grule", origin="GM")
        records = sweep_rules(
            [make_session(gm), make_session(lm1), make_session(lm2)], "default")
        assert len(records) == 1
        assert records[0].nsx.name == "gm"
        assert records[0].origin == "GM"


def test_lm_native_rules_survive_alongside_gm_rules(make_session):
    with FakeNsx(role="gm", name="gm") as gm, FakeNsx(role="lm", name="lm1") as lm1:
        for fake in (gm, lm1):
            fake.state.add_policy("gpol", origin="GM")
            fake.state.add_rule("gpol", "grule", origin="GM")
        lm1.state.add_policy("lpol", origin="LM")
        lm1.state.add_rule("lpol", "lrule", origin="LM")

        records = sweep_rules([make_session(gm), make_session(lm1)], "default")
        by_id = {r.rule_id: r for r in records}
        assert set(by_id) == {"grule", "lrule"}
        assert by_id["grule"].origin == "GM"
        assert by_id["lrule"].origin == "LM"


def test_a_gm_rule_seen_only_through_an_lm_is_labelled_as_such(make_session, lm):
    """With no GM connected, a realized GM rule is still recognisable as one."""
    lm.state.add_policy("gpol", origin="GM")
    lm.state.add_rule("gpol", "grule", origin="GM")
    records = sweep_rules([make_session(lm)], "default")
    assert records[0].origin == "GM (via LM)"


def test_rules_without_a_path_are_never_deduplicated(lm, make_session):
    """Two rules with no path cannot be proven identical, so dropping one
    would under-report."""
    lm.state.add_policy("p1")
    for rid in ("r1", "r2"):
        rule = lm.state.add_rule("p1", rid)
        rule["path"] = ""
    records = sweep_rules([make_session(lm)], "default")
    assert len(records) == 2


def test_an_unreachable_manager_does_not_abort_the_sweep(make_session, lm):
    with FakeNsx(role="lm", name="broken") as broken:
        broken.state.fail_next("/domains/default/security-policies", times=99)
        lm.state.add_policy("p1")
        lm.state.add_rule("p1", "r1")
        sessions = [make_session(broken), make_session(lm)]
        for s in sessions:
            s.retries = 0
        records = sweep_rules(sessions, "default")
        assert [r.rule_id for r in records] == ["r1"]


def test_group_refs_covers_source_destination_and_scope(lm, make_session):
    lm.state.add_policy("p1")
    lm.state.add_rule("p1", "r1", source_groups=["/infra/g/a"],
                      destination_groups=["/infra/g/b"], scope=["/infra/g/c"])
    record = sweep_rules([make_session(lm)], "default")[0]
    assert record.group_refs() == {"/infra/g/a", "/infra/g/b", "/infra/g/c"}
    assert record.directions_for({"/infra/g/a"}) == ["source"]
    assert record.directions_for({"/infra/g/c"}) == ["applied_to"]
    assert record.directions_for(
        {"/infra/g/a", "/infra/g/b", "/infra/g/c"}) == [
            "source", "dest", "applied_to"]


def test_group_inventory_indexes_by_path_with_gm_winning(make_session):
    with FakeNsx(role="gm", name="gm") as gm, FakeNsx(role="lm", name="lm1") as lm1:
        for fake in (gm, lm1):
            fake.state.add_group("gg1", "Global Web", origin="GM")
        lm1.state.add_group("lg1", "Local Web", origin="LM")

        inventory = group_inventory(
            [make_session(gm), make_session(lm1)], "default")
        gm_path = "/global-infra/domains/default/groups/gg1"
        lm_path = "/infra/domains/default/groups/lg1"
        assert set(inventory) == {gm_path, lm_path}
        assert inventory[gm_path][0].name == "gm"
        assert inventory[lm_path][0].name == "lm1"


def test_rule_record_exposes_readable_names(lm, make_session):
    lm.state.add_policy("p1", "Web Policy")
    lm.state.add_rule("p1", "r1", display_name="Allow Web")
    record = sweep_rules([make_session(lm)], "default")[0]
    assert isinstance(record, RuleRecord)
    assert record.policy_name == "Web Policy"
    assert record.rule_name == "Allow Web"
    assert record.policy_id == "p1"
    assert record.rule_id == "r1"
