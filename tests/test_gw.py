"""Tests for gw-policy list, gw-rule list, gw-rule hygiene."""
from nsx_toolkit.actions.gw_inspect import (
    act_gw_hygiene,
    act_gw_policy_list,
    act_gw_rule_list,
)
from nsx_toolkit.export import Exporter


def _rows(exp, label):
    for rs in exp.sets:
        if rs.label == label:
            return rs.rows
    return []


# ── gw-policy list ────────────────────────────────────────────────────────────

def test_gw_policy_list_basic(lm, make_session):
    lm.state.add_gw_policy("gw-pol-1", display_name="perimeter")
    lm.state.add_gw_rule("gw-pol-1", "r1")
    exp = Exporter()
    act_gw_policy_list([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_policies")
    assert len(rows) == 1
    assert rows[0][2] == "perimeter"
    assert rows[0][5] == "1"   # rule count


def test_gw_policy_list_contains(lm, make_session):
    lm.state.add_gw_policy("gw-p1", display_name="perimeter-edge")
    lm.state.add_gw_policy("gw-p2", display_name="internal-gw")
    exp = Exporter()
    act_gw_policy_list([make_session(lm)], "default", exp, contains="perim")
    rows = _rows(exp, "gw_policies")
    assert len(rows) == 1
    assert rows[0][2] == "perimeter-edge"


def test_gw_policy_list_empty(lm, make_session):
    exp = Exporter()
    act_gw_policy_list([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_policies")
    assert rows == []


# ── gw-rule list ──────────────────────────────────────────────────────────────

def test_gw_rule_list_basic(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="edge-pol")
    lm.state.add_gw_rule("pol-1", "r1", display_name="allow-web", action="ALLOW")
    lm.state.add_gw_rule("pol-1", "r2", display_name="drop-rest", action="DROP")
    exp = Exporter()
    act_gw_rule_list([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_rules")
    assert len(rows) == 2
    rule_names = {r[3] for r in rows}
    assert "allow-web" in rule_names
    assert "drop-rest" in rule_names


def test_gw_rule_list_disabled_filter(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", display_name="active", disabled=False)
    lm.state.add_gw_rule("pol-1", "r2", display_name="disabled-rule", disabled=True)
    exp = Exporter()
    act_gw_rule_list([make_session(lm)], "default", exp, disabled_only=True)
    rows = _rows(exp, "gw_rules")
    assert len(rows) == 1
    assert rows[0][3] == "disabled-rule"


def test_gw_rule_list_action_filter(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", action="ALLOW")
    lm.state.add_gw_rule("pol-1", "r2", action="DROP")
    exp = Exporter()
    act_gw_rule_list([make_session(lm)], "default", exp, action="DROP")
    rows = _rows(exp, "gw_rules")
    assert len(rows) == 1


# ── gw-rule hygiene ───────────────────────────────────────────────────────────

def test_gw_hygiene_any_any(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", action="ALLOW",
                          src=["ANY"], dst=["ANY"])
    exp = Exporter()
    act_gw_hygiene([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_hygiene")
    assert any(r[3] == "any-any-allow" for r in rows)


def test_gw_hygiene_disabled(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", disabled=True)
    exp = Exporter()
    act_gw_hygiene([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_hygiene")
    assert any(r[3] == "disabled-rule" for r in rows)


def test_gw_hygiene_drop_not_logged(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", action="DROP", logged=False)
    exp = Exporter()
    act_gw_hygiene([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_hygiene")
    assert any(r[3] == "drop-not-logged" for r in rows)


def test_gw_hygiene_clean(lm, make_session):
    lm.state.add_gw_policy("pol-1")
    lm.state.add_gw_rule("pol-1", "r1", action="ALLOW",
                          src=["/infra/domains/default/groups/g-web"],
                          dst=["/infra/domains/default/groups/g-db"])
    exp = Exporter()
    act_gw_hygiene([make_session(lm)], "default", exp)
    rows = _rows(exp, "gw_hygiene")
    assert rows == []
