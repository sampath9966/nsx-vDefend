"""Tests for `nsxctl rule search --ip` -- IP-based rule search."""

from nsx_toolkit.actions.inspect import act_rule_search
from nsx_toolkit.export import Exporter


def _rows(exporter):
    for rs in exporter.sets:
        if rs.label == "rule_search":
            return rs.rows
    return []


def _ip_expr(addrs):
    return [{"resource_type": "IPAddressExpression",
             "ip_addresses": list(addrs)}]


def _condition_expr():
    return [{"resource_type": "Condition",
             "member_type": "VirtualMachine",
             "key": "Tag",
             "operator": "EQUALS",
             "value": "web"}]


def test_exact_ip_match(lm, make_session):
    """A group with an explicit IPAddressExpression containing the query IP."""
    g = lm.state.add_group("g-ip", "IP Group",
                           expression=_ip_expr(["10.1.2.3", "10.1.2.4"]))
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "allow-ip",
                      source_groups=[g["path"]], action="ALLOW")

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.1.2.3")

    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][3] == "allow-ip"
    assert "exact" in rows[0][6]


def test_any_always_matches(lm, make_session):
    """A rule with ANY source always includes the query IP."""
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "catch-all", action="DROP")  # default src=ANY

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="192.168.1.1")

    rows = _rows(exp)
    assert len(rows) == 1
    assert "ANY" in rows[0][6]


def test_condition_group_is_possible(lm, make_session):
    """Tag-based groups can't be evaluated statically -- reported as possible."""
    g = lm.state.add_group("g-tag", "Tag Group", expression=_condition_expr())
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "tag-rule", source_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.0.0.1")

    rows = _rows(exp)
    assert len(rows) == 1
    assert "possible" in rows[0][6]


def test_certain_flag_hides_possible(lm, make_session):
    """--certain removes 'possible' rows, keeps only exact and ANY."""
    g = lm.state.add_group("g-tag", "Tag Group", expression=_condition_expr())
    g_ip = lm.state.add_group("g-ip", "IP Group",
                               expression=_ip_expr(["10.0.0.1"]))
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "tag-rule", source_groups=[g["path"]])
    lm.state.add_rule("pol", "ip-rule", source_groups=[g_ip["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.0.0.1", certain_only=True)

    rows = _rows(exp)
    rule_names = [r[3] for r in rows]
    assert "ip-rule" in rule_names
    assert "tag-rule" not in rule_names


def test_ip_not_in_group_not_matched(lm, make_session):
    """Rule where both src and dst are IP groups that don't contain the query IP."""
    g = lm.state.add_group("g-other", "Other Network",
                           expression=_ip_expr(["172.16.0.0/16"]))
    lm.state.add_policy("pol")
    # Both sides restricted to 172.16.0.0/16 — neither contains 10.1.2.3
    lm.state.add_rule("pol", "other-rule",
                      source_groups=[g["path"]],
                      destination_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.1.2.3")

    rows = _rows(exp)
    assert rows == []


def test_cidr_query_matches_subnet(lm, make_session):
    """Query /24 CIDR is covered by a /16 group expression."""
    g = lm.state.add_group("g-net", "Big Net",
                           expression=_ip_expr(["10.0.0.0/8"]))
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "net-rule", destination_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.1.0.0/24")

    rows = _rows(exp)
    assert len(rows) == 1
    assert "exact" in rows[0][7]


def test_invalid_ip_returns_empty(lm, make_session):
    """Bad IP input returns empty rows without crashing."""
    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="not-an-ip")
    assert _rows(exp) == []


def test_policy_filter(lm, make_session):
    """--policy filter restricts to rules in matching policies only."""
    g = lm.state.add_group("g-ip", "IP Group",
                           expression=_ip_expr(["10.1.2.3"]))
    lm.state.add_policy("app-tier")
    lm.state.add_policy("other-tier")
    lm.state.add_rule("app-tier", "r-app", source_groups=[g["path"]])
    lm.state.add_rule("other-tier", "r-other", source_groups=[g["path"]])

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.1.2.3", policy_ref="app")

    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][3] == "r-app"


def test_drop_action_included(lm, make_session):
    """DROP rules are included -- the search shows all matching rules."""
    g = lm.state.add_group("g-ip", "IP Group",
                           expression=_ip_expr(["10.5.0.0/16"]))
    lm.state.add_policy("pol")
    lm.state.add_rule("pol", "drop-rule", source_groups=[g["path"]],
                      action="DROP")

    s = make_session(lm)
    exp = Exporter()
    act_rule_search([s], "default", exp, ip="10.5.1.1")

    rows = _rows(exp)
    assert len(rows) == 1
    assert rows[0][4] == "DROP"
