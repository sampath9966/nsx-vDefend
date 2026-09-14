"""Tests for nsxctl segment list, edge list, bgp."""
from nsx_toolkit.actions.topo import act_bgp, act_edge_list, act_segment_list
from nsx_toolkit.export import Exporter


def _rows(exp, label):
    for rs in exp.sets:
        if rs.label == label:
            return rs.rows
    return []


# ── segment list ─────────────────────────────────────────────────────────────

def test_segment_list_basic(lm, make_session):
    lm.state.add_segment("seg-1", display_name="web-seg",
                         gateway="192.168.1.1/24",
                         connectivity_path="/infra/tier-1s/t1-web")
    lm.state.add_segment("seg-2", display_name="db-seg",
                         gateway="10.0.0.1/24")
    exp = Exporter()
    act_segment_list([make_session(lm)], "default", exp)
    rows = _rows(exp, "segments")
    assert len(rows) == 2
    names = {r[1] for r in rows}
    assert "web-seg" in names and "db-seg" in names


def test_segment_list_contains_filter(lm, make_session):
    lm.state.add_segment("seg-1", display_name="web-seg")
    lm.state.add_segment("seg-2", display_name="db-seg")
    exp = Exporter()
    act_segment_list([make_session(lm)], "default", exp, contains="web")
    rows = _rows(exp, "segments")
    assert len(rows) == 1
    assert rows[0][1] == "web-seg"


def test_segment_list_type_filter_vlan(lm, make_session):
    lm.state.add_segment("seg-overlay", display_name="overlay-seg")
    lm.state.add_segment("seg-vlan", display_name="vlan-seg", vlan_ids=[100])
    exp = Exporter()
    act_segment_list([make_session(lm)], "default", exp, seg_type="vlan")
    rows = _rows(exp, "segments")
    assert len(rows) == 1
    assert rows[0][1] == "vlan-seg"
    assert rows[0][2] == "vlan"


def test_segment_list_type_filter_overlay(lm, make_session):
    lm.state.add_segment("seg-overlay", display_name="overlay-seg")
    lm.state.add_segment("seg-vlan", display_name="vlan-seg", vlan_ids=[200])
    exp = Exporter()
    act_segment_list([make_session(lm)], "default", exp, seg_type="overlay")
    rows = _rows(exp, "segments")
    assert len(rows) == 1
    assert rows[0][2] == "overlay"


def test_segment_list_empty(lm, make_session):
    exp = Exporter()
    act_segment_list([make_session(lm)], "default", exp)
    rows = _rows(exp, "segments")
    assert rows == []


# ── edge list ─────────────────────────────────────────────────────────────────

def test_edge_list_basic(lm, make_session):
    lm.state.add_edge_node("edge-1", display_name="edge-node-1",
                           admin_state="UP", status="NODE_READY")
    lm.state.add_edge_node("edge-2", display_name="edge-node-2",
                           admin_state="DOWN", status="FAILED")
    exp = Exporter()
    act_edge_list([make_session(lm)], exp)
    rows = _rows(exp, "edges")
    assert len(rows) == 2
    names = {r[1] for r in rows}
    assert "edge-node-1" in names and "edge-node-2" in names


def test_edge_list_empty(lm, make_session):
    exp = Exporter()
    act_edge_list([make_session(lm)], exp)
    rows = _rows(exp, "edges")
    assert rows == []


# ── bgp ───────────────────────────────────────────────────────────────────────

def test_bgp_established(lm, make_session):
    lm.state.add_tier0("t0-1", display_name="T0-Main")
    lm.state.add_locale_service("t0-1", "ls-1")
    lm.state.add_bgp_neighbor("t0-1", "ls-1", "10.0.0.1",
                               remote_as="65001", state="ESTABLISHED",
                               uptime=3600, prefixes=100)
    exp = Exporter()
    act_bgp([make_session(lm)], "default", exp)
    rows = _rows(exp, "bgp")
    assert len(rows) == 1
    assert rows[0][2] == "10.0.0.1"
    assert rows[0][3] == "65001"


def test_bgp_down_only_filter(lm, make_session):
    lm.state.add_tier0("t0-1")
    lm.state.add_locale_service("t0-1", "ls-1")
    lm.state.add_bgp_neighbor("t0-1", "ls-1", "10.0.0.1", state="ESTABLISHED")
    lm.state.add_bgp_neighbor("t0-1", "ls-1", "10.0.0.2", state="IDLE")
    exp = Exporter()
    act_bgp([make_session(lm)], "default", exp, down_only=True)
    rows = _rows(exp, "bgp")
    assert len(rows) == 1
    assert rows[0][2] == "10.0.0.2"


def test_bgp_tier0_filter(lm, make_session):
    lm.state.add_tier0("t0-a", display_name="T0-Alpha")
    lm.state.add_locale_service("t0-a", "ls-a")
    lm.state.add_bgp_neighbor("t0-a", "ls-a", "1.1.1.1", state="ESTABLISHED")
    lm.state.add_tier0("t0-b", display_name="T0-Beta")
    lm.state.add_locale_service("t0-b", "ls-b")
    lm.state.add_bgp_neighbor("t0-b", "ls-b", "2.2.2.2", state="ESTABLISHED")
    exp = Exporter()
    act_bgp([make_session(lm)], "default", exp, tier0="Alpha")
    rows = _rows(exp, "bgp")
    assert len(rows) == 1
    assert rows[0][2] == "1.1.1.1"


def test_bgp_empty(lm, make_session):
    exp = Exporter()
    act_bgp([make_session(lm)], "default", exp)
    rows = _rows(exp, "bgp")
    assert rows == []
