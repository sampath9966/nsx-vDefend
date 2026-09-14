"""Tests for `nsxctl terraform export`."""
import os

from nsx_toolkit.actions.terraform import (
    _cert_hcl,
    _expression_to_hcl,
    _group_hcl,
    _hcl_list,
    _hcl_str,
    _imports_hcl,
    _policy_hcl,
    _tf_id,
    act_terraform_export,
)


# --- unit helpers -----------------------------------------------------------

def test_tf_id_sanitize():
    assert _tf_id("my-group") == "my_group"
    assert _tf_id("123-start") == "_123_start"
    assert _tf_id("") == "_resource"
    assert _tf_id("abc_DEF") == "abc_DEF"
    assert _tf_id("a.b/c") == "a_b_c"


def test_hcl_str_escaping():
    assert _hcl_str('say "hi"') == r'"say \"hi\""'
    assert _hcl_str("back\\slash") == '"back\\\\slash"'
    assert _hcl_str("plain") == '"plain"'


def test_hcl_list_empty_and_values():
    assert _hcl_list([]) == "[]"
    assert _hcl_list(["a", "b"]) == '["a", "b"]'


# --- group HCL --------------------------------------------------------------

def test_group_empty_expression():
    g = {"id": "g-empty", "display_name": "Empty Group", "expression": []}
    block = _group_hcl(g, "default")
    assert 'resource "nsxt_policy_group"' in block
    assert 'nsx_id       = "g-empty"' in block
    assert 'domain       = "default"' in block
    assert "criteria" not in block


def test_group_condition():
    expr = [{"resource_type": "Condition",
             "key": "Tag", "operator": "EQUALS",
             "member_type": "VirtualMachine", "value": "env|prod"}]
    g = {"id": "g-cond", "display_name": "Cond Group", "expression": expr}
    block = _group_hcl(g, "default")
    assert "criteria {" in block
    assert "condition {" in block
    assert 'key         = "Tag"' in block
    assert 'value       = "env|prod"' in block


def test_group_ipaddress():
    expr = [{"resource_type": "IPAddressExpression",
             "ip_addresses": ["10.0.0.0/8", "192.168.1.0/24"]}]
    g = {"id": "g-ip", "display_name": "IP Group", "expression": expr}
    block = _group_hcl(g, "default")
    assert "ipaddress_expression {" in block
    assert "10.0.0.0/8" in block


def test_group_conjunction_and():
    expr = [
        {"resource_type": "Condition",
         "key": "Tag", "operator": "EQUALS",
         "member_type": "VirtualMachine", "value": "env|prod"},
        {"resource_type": "ConjunctionOperator",
         "conjunction_operator": "AND"},
        {"resource_type": "Condition",
         "key": "Tag", "operator": "EQUALS",
         "member_type": "VirtualMachine", "value": "tier|web"},
    ]
    block = _expression_to_hcl(expr)
    assert block.count("criteria {") == 2
    assert "conjunction {" in block
    assert '"AND"' in block


# --- policy HCL -------------------------------------------------------------

def test_policy_with_rules():
    policy = {"id": "p-web", "display_name": "Web Policy",
              "category": "Application", "sequence_number": 1,
              "scope": ["ANY"]}
    rules = [
        {"id": "r-allow", "display_name": "Allow Web",
         "source_groups": ["ANY"], "destination_groups": ["/infra/groups/g-web"],
         "services": ["/infra/services/HTTPS"], "action": "ALLOW",
         "direction": "IN_OUT", "ip_protocol": "IPV4_IPV6",
         "logged": True, "disabled": False, "sequence_number": 10},
    ]
    block = _policy_hcl(policy, rules, "default")
    assert 'resource "nsxt_policy_security_policy"' in block
    assert 'nsx_id          = "p-web"' in block
    assert "rule {" in block
    assert 'action             = "ALLOW"' in block
    assert "source_groups      = []" in block
    assert "/infra/groups/g-web" in block


# --- cert HCL ---------------------------------------------------------------

def test_cert_hcl_block():
    cert = {"id": "cert-01", "display_name": "My Cert"}
    block = _cert_hcl(cert)
    assert 'resource "nsxt_certificate"' in block
    assert 'nsx_id       = "cert-01"' in block
    assert "# pem_encoded" in block


# --- imports HCL ------------------------------------------------------------

def test_imports_hcl():
    groups = [{"id": "g-web"}]
    policies = [{"id": "p-web"}]
    certs = [{"id": "cert-01"}]
    block = _imports_hcl(groups, policies, certs, "default")
    assert "nsxt_policy_group.g_web" in block
    assert '"default/g-web"' in block
    assert "nsxt_policy_security_policy.p_web" in block
    assert '"default/p-web"' in block
    assert "nsxt_certificate.cert_01" in block
    assert '"cert-01"' in block


# --- integration tests ------------------------------------------------------

def test_export_creates_files(lm, make_session, tmp_path):
    """Full export writes provider.tf + all per-manager files."""
    lm.state.add_group("g-web", display_name="Web Group")
    lm.state.add_policy("p-web", display_name="Web Policy")
    lm.state.add_rule("p-web", "r-allow")
    lm.state.add_cert("cert-01", display_name="My Cert")
    s = make_session(lm)

    act_terraform_export([s], str(tmp_path), domain="default",
                         types=["groups", "dfw", "certs"])

    assert os.path.isfile(str(tmp_path / "provider.tf"))
    mgr_dir = tmp_path / s.name
    assert os.path.isfile(str(mgr_dir / "groups.tf"))
    assert os.path.isfile(str(mgr_dir / "dfw.tf"))
    assert os.path.isfile(str(mgr_dir / "certs.tf"))
    assert os.path.isfile(str(mgr_dir / "imports.tf"))

    groups_tf = (mgr_dir / "groups.tf").read_text()
    assert "nsxt_policy_group" in groups_tf
    assert "g-web" in groups_tf

    dfw_tf = (mgr_dir / "dfw.tf").read_text()
    assert "nsxt_policy_security_policy" in dfw_tf

    imports_tf = (mgr_dir / "imports.tf").read_text()
    assert "nsxt_policy_group" in imports_tf
    assert "nsxt_certificate" in imports_tf


def test_export_types_filter(lm, make_session, tmp_path):
    """--types groups skips dfw.tf and certs.tf."""
    lm.state.add_group("g-db", display_name="DB Group")
    lm.state.add_policy("p-db", display_name="DB Policy")
    lm.state.add_rule("p-db", "r-drop")
    lm.state.add_cert("cert-02", display_name="Cert 2")
    s = make_session(lm)

    act_terraform_export([s], str(tmp_path), domain="default", types=["groups"])

    mgr_dir = tmp_path / s.name
    assert os.path.isfile(str(mgr_dir / "groups.tf"))
    assert not os.path.exists(str(mgr_dir / "dfw.tf"))
    assert not os.path.exists(str(mgr_dir / "certs.tf"))
