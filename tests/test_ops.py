"""Tests for `nsxctl alarms`, `nsxctl cert list`, `nsxctl capacity`."""

from nsx_toolkit.actions.ops import act_alarms, act_capacity, act_cert_list
from nsx_toolkit.export import Exporter


def _rows(exp, label):
    for rs in exp.sets:
        if rs.label == label:
            return rs.rows
    return []


# ---- alarms ----------------------------------------------------------------

def test_alarms_basic(lm, make_session):
    """Happy path: one open alarm, appears in output."""
    lm.state.add_alarm("a1", severity="HIGH", summary="CPU spike",
                       status="OPEN", node_id="mgr-01", event_count=3)
    s = make_session(lm)
    exp = Exporter()
    act_alarms([s], exp)
    rows = _rows(exp, "alarms")
    assert len(rows) == 1
    assert rows[0][1] == "HIGH"
    assert rows[0][2] == "CPU spike"
    assert rows[0][4] == "3"


def test_alarms_empty(lm, make_session):
    """No alarms: empty export, no crash."""
    s = make_session(lm)
    exp = Exporter()
    act_alarms([s], exp)
    assert _rows(exp, "alarms") == []


def test_alarms_severity_filter(lm, make_session):
    """--severity high hides LOW alarms."""
    lm.state.add_alarm("a1", severity="HIGH", summary="High alert")
    lm.state.add_alarm("a2", severity="LOW", summary="Low note")
    s = make_session(lm)
    exp = Exporter()
    act_alarms([s], exp, severity="HIGH")
    rows = _rows(exp, "alarms")
    assert len(rows) == 1
    assert rows[0][1] == "HIGH"


def test_alarms_sorted_by_severity(lm, make_session):
    """CRITICAL sorts before LOW."""
    lm.state.add_alarm("a1", severity="LOW", summary="low")
    lm.state.add_alarm("a2", severity="CRITICAL", summary="critical")
    s = make_session(lm)
    exp = Exporter()
    act_alarms([s], exp)
    rows = _rows(exp, "alarms")
    assert rows[0][1] == "CRITICAL"
    assert rows[1][1] == "LOW"


def test_alarms_dedup_across_managers(make_session):
    """Same alarm id from two managers appears once."""
    from fake_nsx import FakeNsx
    with FakeNsx(role="lm", name="lm1") as lm1, \
            FakeNsx(role="lm", name="lm2") as lm2:
        lm1.state.add_alarm("dup-id", severity="HIGH", summary="shared")
        lm2.state.add_alarm("dup-id", severity="HIGH", summary="shared")
        sessions = [make_session(lm1), make_session(lm2)]
        exp = Exporter()
        act_alarms(sessions, exp)
        rows = _rows(exp, "alarms")
        assert len(rows) == 1


# ---- cert list -------------------------------------------------------------

def test_cert_ok(lm, make_session):
    """Cert with 365 days left → OK."""
    lm.state.add_cert("c1", display_name="my-cert", not_after_days=365)
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp)
    rows = _rows(exp, "certificates")
    assert len(rows) == 1
    assert rows[0][1] == "my-cert"
    assert int(rows[0][3]) > 300


def test_cert_warning(lm, make_session):
    """Cert expiring in 60 days with warn_days=90 → WARNING."""
    lm.state.add_cert("c1", not_after_days=60)
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp, warn_days=90)
    rows = _rows(exp, "certificates")
    assert len(rows) == 1
    assert int(rows[0][3]) < 90


def test_cert_critical(lm, make_session):
    """Cert expiring in 15 days → CRITICAL regardless of warn_days."""
    lm.state.add_cert("c1", not_after_days=15)
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp)
    rows = _rows(exp, "certificates")
    assert len(rows) == 1
    assert int(rows[0][3]) <= 30


def test_cert_expired(lm, make_session):
    """Cert that expired yesterday → EXPIRED."""
    lm.state.add_cert("c1", not_after_days=-1)
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp)
    rows = _rows(exp, "certificates")
    assert len(rows) == 1
    assert int(rows[0][3]) < 0


def test_cert_expired_only_filter(lm, make_session):
    """--expired hides OK certs, keeps expired ones."""
    lm.state.add_cert("c-ok", not_after_days=365)
    lm.state.add_cert("c-exp", not_after_days=-1)
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp, expired_only=True)
    rows = _rows(exp, "certificates")
    assert len(rows) == 1
    assert rows[0][1] == "c-exp"


def test_cert_empty(lm, make_session):
    """No certificates: empty export."""
    s = make_session(lm)
    exp = Exporter()
    act_cert_list([s], exp)
    assert _rows(exp, "certificates") == []


# ---- capacity --------------------------------------------------------------

def test_capacity_basic(lm, make_session):
    """Usage rows appear in the export."""
    lm.state.set_capacity([
        {"usage_type": "DFW_RULES", "current_usage_count": 500,
         "max_supported_count": 1000,
         "min_threshold_percent": 75, "max_threshold_percent": 90},
    ])
    s = make_session(lm)
    exp = Exporter()
    act_capacity([s], exp)
    rows = _rows(exp, "capacity")
    assert len(rows) == 1
    assert rows[0][1] == "DFW_RULES"
    assert rows[0][2] == "500"
    assert rows[0][4] == "50%"


def test_capacity_empty(lm, make_session):
    """No capacity data: empty export, no crash."""
    s = make_session(lm)
    exp = Exporter()
    act_capacity([s], exp)
    assert _rows(exp, "capacity") == []
