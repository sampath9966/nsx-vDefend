"""Tests for `nsxctl vm groups` -- VM-centric group membership views."""

from fake_nsx import FakeNsx

from nsx_toolkit.actions.vm import act_vm_groups
from nsx_toolkit.export import Exporter


def _rows(exporter):
    for rs in exporter.sets:
        if rs.label == "vm_groups":
            return rs.rows
    return []


def test_vm_groups_basic(lm, make_session):
    """Happy path: VM found, associated with a group, group has a rule."""
    vm = lm.state.add_vm("web-prod-01", external_id="ext-web1")
    g = lm.state.add_group("g-web", "Web Servers",
                           expression=[{"resource_type": "Condition",
                                        "member_type": "VirtualMachine",
                                        "key": "Tag",
                                        "operator": "EQUALS",
                                        "value": "web"}])
    lm.state.associate(vm, g)
    lm.state.add_policy("pol-app")
    lm.state.add_rule("pol-app", "allow-web", source_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_vm_groups([s], "web-prod-01", "default", exp)

    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][0] == "web-prod-01"   # vm
    assert rows[0][2] == "g-web"         # group_id
    assert rows[0][3] == "Web Servers"   # group_name
    assert rows[0][6] == "1"             # rule_count


def test_vm_not_found(lm, make_session):
    """No VM matching the needle -- empty export, no crash."""
    s = make_session(lm)
    exp = Exporter()
    act_vm_groups([s], "nonexistent-vm", "default", exp)
    assert _rows(exp) == []


def test_vm_no_associations(lm, make_session):
    """VM exists but belongs to no groups."""
    lm.state.add_vm("lonely-vm", external_id="ext-lonely")
    s = make_session(lm)
    exp = Exporter()
    act_vm_groups([s], "lonely-vm", "default", exp)
    assert _rows(exp) == []


def test_vm_multiple_groups(lm, make_session):
    """VM in two groups; rule counts are tracked per group."""
    vm = lm.state.add_vm("multi-vm", external_id="ext-multi")
    g1 = lm.state.add_group("g-web", "Web Servers")
    g2 = lm.state.add_group("g-all", "All VMs")
    lm.state.associate(vm, g1)
    lm.state.associate(vm, g2)
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "r1", source_groups=[g1["path"]])
    lm.state.add_rule("pol", "r2", destination_groups=[g2["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_vm_groups([s], "multi-vm", "default", exp)

    rows = _rows(exp)
    assert len(rows) == 2
    by_gid = {r[2]: r for r in rows}
    assert by_gid["g-web"][6] == "1"
    assert by_gid["g-all"][6] == "1"


def test_gm_supplement(make_session):
    """GM associations are picked up as a best-effort supplement."""
    with FakeNsx(role="lm", name="lm1") as lm, \
            FakeNsx(role="gm", name="gm1") as gm:
        vm = lm.state.add_vm("global-vm", external_id="ext-gvm")

        # Group and association only on GM
        g = gm.state.add_group("g-global", "Global Group", origin="GM")
        gm.state.associate(vm, g)

        sessions = [make_session(gm), make_session(lm)]
        exp = Exporter()
        act_vm_groups(sessions, "global-vm", "default", exp)

        rows = _rows(exp)
        assert any(r[2] == "g-global" for r in rows)


def test_vm_substring_match(lm, make_session):
    """find_vms uses substring matching -- 'web' matches 'web-prod-01'."""
    vm = lm.state.add_vm("web-prod-01", external_id="ext-web1")
    g = lm.state.add_group("g-web", "Web Servers")
    lm.state.associate(vm, g)

    s = make_session(lm)
    exp = Exporter()
    act_vm_groups([s], "web", "default", exp)
    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][0] == "web-prod-01"
