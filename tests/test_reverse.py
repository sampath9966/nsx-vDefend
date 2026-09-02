"""Reverse lookup: member-type-agnostic groups and GM/LM rule dedup."""

from fake_nsx import FakeNsx

from nsx_toolkit.actions.reverse import act_reverse_lookup
from nsx_toolkit.export import Exporter


def _rows(exporter, label="reverse_lookup"):
    for rs in exporter.sets:
        if rs.label == label:
            return rs.rows
    return []


def test_finds_groups_via_association_endpoint(lm, make_session):
    vm = lm.state.add_vm("web1", tags=[("env", "prod")])
    # A group matched on Segment criteria: its /members/virtual-machines
    # sub-resource returns nothing, but the VM is still an effective member.
    g = lm.state.add_group("seg-group", "Segment Matched Group")
    lm.state.associate(vm, g)
    lm.state.add_policy("pol1")
    lm.state.add_rule("pol1", "r1", source_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_reverse_lookup([s], "web1", "default", exp)
    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][4] == "Segment Matched Group"


def test_gm_rule_realized_on_many_lms_is_reported_once(make_session):
    """A GM rule is realized read-only onto every LM, so a naive scan reports
    it once per site. It must be deduped by rule path and attributed to GM."""
    with FakeNsx(role="gm", name="gm1") as gm, \
            FakeNsx(role="lm", name="lm1") as lm1, \
            FakeNsx(role="lm", name="lm2") as lm2:
        gpath = "/global-infra/domains/default/groups/gg1"
        for fake in (gm, lm1, lm2):
            g = fake.state.add_group("gg1", "Global Web", origin="GM")
            fake.state.add_policy("gpol", "Global Policy", origin="GM")
            fake.state.add_rule("gpol", "grule", source_groups=[gpath],
                                origin="GM", display_name="Global Rule")
            assert g["path"] == gpath

        vm = lm1.state.add_vm("web1")
        lm1.state.associate(vm, lm1.state.groups[0])
        lm2.state.add_vm("web1-other")

        sessions = [make_session(gm), make_session(lm1), make_session(lm2)]
        exp = Exporter()
        act_reverse_lookup(sessions, "web1", "default", exp)
        rows = _rows(exp)

        assert len(rows) == 1, "GM rule should appear once, not once per LM"
        assert rows[0][1] == "gm1"        # attributed to the GM
        assert rows[0][8] == "GM"         # rule_origin


def test_lm_native_rule_is_kept_alongside_gm_rules(make_session):
    with FakeNsx(role="gm", name="gm1") as gm, FakeNsx(role="lm", name="lm1") as lm1:
        gpath = "/global-infra/domains/default/groups/gg1"
        lpath = "/infra/domains/default/groups/lg1"
        for fake in (gm, lm1):
            fake.state.add_group("gg1", "Global Web", origin="GM")
            fake.state.add_policy("gpol", origin="GM")
            fake.state.add_rule("gpol", "grule", source_groups=[gpath], origin="GM")
        lm1.state.add_group("lg1", "Local Web", origin="LM")
        lm1.state.add_policy("lpol", origin="LM")
        lm1.state.add_rule("lpol", "lrule", destination_groups=[lpath], origin="LM")

        vm = lm1.state.add_vm("web1")
        for g in lm1.state.groups:
            lm1.state.associate(vm, g)

        exp = Exporter()
        act_reverse_lookup([make_session(gm), make_session(lm1)],
                           "web1", "default", exp)
        rows = _rows(exp)
        origins = sorted(r[8] for r in rows)
        assert origins == ["GM", "LM"]


def test_direction_is_reported_per_rule(lm, make_session):
    vm = lm.state.add_vm("web1")
    g = lm.state.add_group("g1", "Web")
    lm.state.associate(vm, g)
    lm.state.add_policy("pol1")
    lm.state.add_rule("pol1", "r1", source_groups=[g["path"]],
                      destination_groups=[g["path"]], scope=[g["path"]])
    exp = Exporter()
    act_reverse_lookup([make_session(lm)], "web1", "default", exp)
    assert _rows(exp)[0][10] == "source, dest, applied_to"


def test_vm_in_no_groups_reports_cleanly(lm, make_session):
    lm.state.add_vm("orphan")
    exp = Exporter()
    act_reverse_lookup([make_session(lm)], "orphan", "default", exp)
    assert _rows(exp) == []


def test_missing_vm_stages_an_empty_result(lm, make_session):
    exp = Exporter()
    act_reverse_lookup([make_session(lm)], "nope", "default", exp)
    assert [rs.label for rs in exp.sets] == ["reverse_lookup"]
    assert _rows(exp) == []
