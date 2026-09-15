"""Tests for context-profile list, idps events, idps profiles."""
from nsx_toolkit.actions.idps import (
    act_context_profile_list,
    act_ids_events,
    act_ids_profiles,
)
from nsx_toolkit.export import Exporter


def _rows(exp, label):
    for rs in exp.sets:
        if rs.label == label:
            return rs.rows
    return []


# ── context-profile list ──────────────────────────────────────────────────────

def test_context_profile_list_basic(lm, make_session):
    lm.state.add_context_profile("cp-1", display_name="SSL",
                                  profile_type="AppID",
                                  attrs=[{"key": "APP_ID", "value": "SSL"}])
    lm.state.add_context_profile("cp-2", display_name="HTTP2",
                                  profile_type="AppID")
    exp = Exporter()
    act_context_profile_list([make_session(lm)], exp)
    rows = _rows(exp, "context_profiles")
    assert len(rows) == 2
    names = {r[2] for r in rows}
    assert "SSL" in names and "HTTP2" in names


def test_context_profile_list_contains(lm, make_session):
    lm.state.add_context_profile("cp-1", display_name="SSL-AppID")
    lm.state.add_context_profile("cp-2", display_name="HTTP-AppID")
    exp = Exporter()
    act_context_profile_list([make_session(lm)], exp, contains="ssl")
    rows = _rows(exp, "context_profiles")
    assert len(rows) == 1
    assert rows[0][2] == "SSL-AppID"


def test_context_profile_list_empty(lm, make_session):
    exp = Exporter()
    act_context_profile_list([make_session(lm)], exp)
    rows = _rows(exp, "context_profiles")
    assert rows == []


# ── idps events ───────────────────────────────────────────────────────────────

def test_ids_events_basic(lm, make_session):
    lm.state.add_ids_event(severity="HIGH", sig_id="2001",
                            src="10.0.0.1", dst="10.0.0.2", count=5)
    lm.state.add_ids_event(severity="CRITICAL", sig_id="3001",
                            src="192.168.1.1", dst="192.168.1.2")
    exp = Exporter()
    act_ids_events([make_session(lm)], exp)
    rows = _rows(exp, "ids_events")
    assert len(rows) == 2
    sigs = {r[3] for r in rows}
    assert "2001" in sigs and "3001" in sigs


def test_ids_events_severity_filter(lm, make_session):
    lm.state.add_ids_event(severity="HIGH", sig_id="1001")
    lm.state.add_ids_event(severity="MEDIUM", sig_id="2002")
    exp = Exporter()
    act_ids_events([make_session(lm)], exp, severity="HIGH")
    rows = _rows(exp, "ids_events")
    assert len(rows) == 1
    assert rows[0][3] == "1001"


def test_ids_events_empty(lm, make_session):
    exp = Exporter()
    act_ids_events([make_session(lm)], exp)
    rows = _rows(exp, "ids_events")
    assert rows == []


# ── idps profiles ─────────────────────────────────────────────────────────────

def test_ids_profiles_basic(lm, make_session):
    lm.state.add_ids_profile("prof-1", display_name="Balanced",
                              overrides=[{"sig_id": "9001"}])
    lm.state.add_ids_profile("prof-2", display_name="Strict")
    exp = Exporter()
    act_ids_profiles([make_session(lm)], exp)
    rows = _rows(exp, "ids_profiles")
    assert len(rows) == 2
    names = {r[2] for r in rows}
    assert "Balanced" in names
    balanced = next(r for r in rows if r[2] == "Balanced")
    assert balanced[3] == "1"   # one overridden signature


def test_ids_profiles_empty(lm, make_session):
    exp = Exporter()
    act_ids_profiles([make_session(lm)], exp)
    rows = _rows(exp, "ids_profiles")
    assert rows == []
