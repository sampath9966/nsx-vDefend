"""Tests for gw-policy / gw-rule write operations."""
from nsx_toolkit import output
from nsx_toolkit.actions.gw_write import (
    act_gw_policy_create,
    act_gw_policy_delete,
    act_gw_rule_create,
    act_gw_rule_delete,
    act_gw_rule_edit,
    act_gw_rule_move,
)
from nsx_toolkit.export import Exporter

# ── helpers ───────────────────────────────────────────────────────────────────

def _session(lm, make_session):
    return make_session(lm)


# ── gw-policy create ──────────────────────────────────────────────────────────

def test_gw_policy_create_dryrun(lm, make_session):
    exp = Exporter()
    act_gw_policy_create([_session(lm, make_session)], "default", exp,
                         name="perimeter", category="LocalGatewayRules",
                         seq=10, enable_writes=False, yes=False)
    assert len(lm.state.gw_policies) == 0


def test_gw_policy_create_writes(lm, make_session):
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_policy_create([_session(lm, make_session)], "default", exp,
                         name="perimeter", category="LocalGatewayRules",
                         seq=10, enable_writes=True, yes=True)
    assert any(p["display_name"] == "perimeter" for p in lm.state.gw_policies)


# ── gw-policy delete ──────────────────────────────────────────────────────────

def test_gw_policy_delete(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="edge-pol")
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_policy_delete([_session(lm, make_session)], "default", exp,
                         name="edge-pol", enable_writes=True, yes=True)
    assert not any(p["id"] == "pol-1" for p in lm.state.gw_policies)


# ── gw-rule create ────────────────────────────────────────────────────────────

def test_gw_rule_create_dryrun(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    exp = Exporter()
    act_gw_rule_create([_session(lm, make_session)], "default", exp,
                       policy="perimeter", name="allow-web",
                       src=None, dst=None, service=None,
                       action="ALLOW", seq=10, logged=True, disabled=False,
                       enable_writes=False, yes=False)
    assert len(lm.state.gw_rules.get("pol-1", [])) == 0


def test_gw_rule_create_writes(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_rule_create([_session(lm, make_session)], "default", exp,
                       policy="perimeter", name="allow-web",
                       src=None, dst=None, service=None,
                       action="ALLOW", seq=10, logged=True, disabled=False,
                       enable_writes=True, yes=True)
    rules = lm.state.gw_rules.get("pol-1", [])
    assert any(r["display_name"] == "allow-web" for r in rules)


# ── gw-rule edit ──────────────────────────────────────────────────────────────

def test_gw_rule_edit_action(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    lm.state.add_gw_rule("pol-1", "r1", display_name="rule-one", action="ALLOW")
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_rule_edit([_session(lm, make_session)], "default", exp,
                     policy="perimeter", name="rule-one",
                     action="DROP", src=None, dst=None, service=None,
                     logged=None, disabled=None,
                     enable_writes=True, yes=True)
    rules = lm.state.gw_rules.get("pol-1", [])
    r = next(r for r in rules if r["id"] == "r1")
    assert r["action"] == "DROP"


# ── gw-rule move ──────────────────────────────────────────────────────────────

def test_gw_rule_move_before(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    lm.state.add_gw_rule("pol-1", "r1", display_name="first", action="ALLOW")
    lm.state.add_gw_rule("pol-1", "r2", display_name="second", action="DROP")
    # first has seq=10, second has seq=20
    # move "second" before "first" → second gets seq=9
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_rule_move([_session(lm, make_session)], "default", exp,
                     policy="perimeter", name="second", before="first",
                     enable_writes=True, yes=True)
    rules = lm.state.gw_rules.get("pol-1", [])
    r2 = next(r for r in rules if r["id"] == "r2")
    assert r2["sequence_number"] < 10


# ── gw-rule delete ────────────────────────────────────────────────────────────

def test_gw_rule_delete(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    lm.state.add_gw_rule("pol-1", "r1", display_name="allow-web")
    output.set_assume_yes(True)
    exp = Exporter()
    act_gw_rule_delete([_session(lm, make_session)], "default", exp,
                       policy="perimeter", name="allow-web",
                       enable_writes=True, yes=True)
    rules = lm.state.gw_rules.get("pol-1", [])
    assert not any(r["id"] == "r1" for r in rules)


# ── write gate ────────────────────────────────────────────────────────────────

def test_gw_rule_create_requires_enable_writes(lm, make_session):
    lm.state.add_gw_policy("pol-1", display_name="perimeter")
    exp = Exporter()
    act_gw_rule_create([_session(lm, make_session)], "default", exp,
                       policy="perimeter", name="blocked-rule",
                       src=None, dst=None, service=None,
                       action="ALLOW", seq=10, logged=True, disabled=False,
                       enable_writes=False, yes=False)
    assert len(lm.state.gw_rules.get("pol-1", [])) == 0
