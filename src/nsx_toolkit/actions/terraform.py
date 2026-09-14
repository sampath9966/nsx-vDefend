"""Terraform HCL export: groups, DFW policies, certificates.

Generates a directory tree of .tf files from live NSX configuration so an
existing estate can be imported into Terraform state and managed with the
vmware/nsxt provider. No new API endpoints: reuses policy.py + http.py.

Output layout:
  {out_dir}/
    provider.tf            # NSX provider stub
    {manager}/
      groups.tf            # nsxt_policy_group resources
      dfw.tf               # nsxt_policy_security_policy resources
      certs.tf             # nsxt_certificate resources
      imports.tf           # import {} blocks (Terraform >= 1.5)
"""
import os
import re

from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_CATEGORY,
    F_DESCRIPTION,
    F_DEST_GROUPS,
    F_DIRECTION,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_EXPRESSIONS,
    F_EXTERNAL_IDS,
    F_ID,
    F_IP_ADDRESSES,
    F_IP_PROTOCOL,
    F_KEY,
    F_LOGGED,
    F_MEMBER_TYPE,
    F_OPERATOR,
    F_PATH,
    F_PATHS,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SERVICES,
    F_SOURCE_GROUPS,
    F_VALUE,
    RT,
    RT_CONDITION,
    RT_CONJUNCTION,
    RT_EXTERNALID,
    RT_IPADDRESS,
    RT_NESTED,
    RT_PATHEXPR,
    p_groups,
    p_sec_policies,
    p_sec_rules,
)
from ..errors import NsxError
from ..output import say, section
from ..policy import fetch_rules_for, policies_for

_TF_ID_RE = re.compile(r"[^A-Za-z0-9_]")


def _tf_id(s):
    result = _TF_ID_RE.sub("_", str(s))
    if result and result[0].isdigit():
        result = "_" + result
    return result or "_resource"


def _hcl_str(v):
    escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(escaped)


def _hcl_list(items):
    if not items:
        return "[]"
    return "[{}]".format(", ".join(_hcl_str(i) for i in items))


def _hcl_groups(paths):
    """Rule source/dest/scope field: ANY → [] for Terraform provider."""
    if not paths or list(paths) == [ANY]:
        return "[]"
    return _hcl_list(paths)


def _indent(text, n=2):
    pad = " " * n
    return "\n".join(pad + line if line.strip() else line
                     for line in text.splitlines())


def _element_block(elem):
    """One expression element (non-conjunction) → HCL block lines."""
    rt = elem.get(RT, "")
    lines = []
    if rt == RT_CONDITION:
        lines.append("condition {")
        lines.append('  key         = {}'.format(_hcl_str(elem.get(F_KEY, ""))))
        lines.append('  operator    = {}'.format(_hcl_str(elem.get(F_OPERATOR, ""))))
        lines.append('  member_type = {}'.format(_hcl_str(elem.get(F_MEMBER_TYPE, ""))))
        lines.append('  value       = {}'.format(_hcl_str(elem.get(F_VALUE, ""))))
        lines.append("}")
    elif rt == RT_IPADDRESS:
        ips = elem.get(F_IP_ADDRESSES, [])
        lines.append("ipaddress_expression {")
        lines.append("  ip_addresses = {}".format(_hcl_list(ips)))
        lines.append("}")
    elif rt == RT_PATHEXPR:
        paths = elem.get(F_PATHS, [])
        lines.append("path_expression {")
        lines.append("  member_paths = {}".format(_hcl_list(paths)))
        lines.append("}")
    elif rt == RT_EXTERNALID:
        ext_ids = elem.get(F_EXTERNAL_IDS, [])
        lines.append("external_id_expression {")
        lines.append("  external_ids = {}".format(_hcl_list(ext_ids)))
        if F_MEMBER_TYPE in elem:
            lines.append('  member_type  = {}'.format(
                _hcl_str(elem[F_MEMBER_TYPE])))
        lines.append("}")
    elif rt == RT_NESTED:
        inner = _expression_to_hcl(elem.get(F_EXPRESSIONS, []))
        lines.append("criteria {")
        lines.append(_indent(inner))
        lines.append("}")
    else:
        lines.append("# unsupported expression type: {}".format(rt))
    return "\n".join(lines)


def _expression_to_hcl(expr_list):
    """NSX expression list → HCL criteria/conjunction blocks."""
    if not expr_list:
        return ""
    segments = []
    current = []
    conjunctions = []
    for elem in expr_list:
        if elem.get(RT) == RT_CONJUNCTION:
            segments.append(current)
            conjunctions.append(elem.get("conjunction_operator", "AND"))
            current = []
        else:
            current.append(elem)
    segments.append(current)

    parts = []
    for i, seg in enumerate(segments):
        if not seg:
            continue
        if i > 0 and i - 1 < len(conjunctions):
            parts.append("conjunction {{\n  operator = {}\n}}".format(
                _hcl_str(conjunctions[i - 1])))
        inner_lines = []
        for elem in seg:
            inner_lines.append(_element_block(elem))
        parts.append("criteria {{\n{}\n}}".format(
            _indent("\n".join(inner_lines))))
    return "\n".join(parts)


def _group_hcl(group, domain):
    """nsxt_policy_group resource block."""
    gid = group.get(F_ID, "unknown")
    name = group.get(F_DISPLAY_NAME, gid)
    desc = group.get(F_DESCRIPTION, "")
    exprs = group.get("expression", [])
    tid = _tf_id(gid)

    lines = ['resource "nsxt_policy_group" {} {{'.format(_hcl_str(tid))]
    lines.append('  display_name = {}'.format(_hcl_str(name)))
    lines.append('  nsx_id       = {}'.format(_hcl_str(gid)))
    lines.append('  domain       = {}'.format(_hcl_str(domain)))
    if desc:
        lines.append('  description  = {}'.format(_hcl_str(desc)))
    if exprs:
        criteria_hcl = _expression_to_hcl(exprs)
        if criteria_hcl:
            lines.append("")
            lines.append(_indent(criteria_hcl))
    lines.append("}")
    return "\n".join(lines)


def _rule_block(rule):
    """One rule {} block inside a security policy resource."""
    rid = rule.get(F_ID, "unknown")
    name = rule.get(F_DISPLAY_NAME, rid)
    src = rule.get(F_SOURCE_GROUPS, [])
    dst = rule.get(F_DEST_GROUPS, [])
    scope = rule.get(F_SCOPE, [])
    svcs = rule.get(F_SERVICES, [])
    action = rule.get(F_ACTION_FIELD, "ALLOW")
    direction = rule.get(F_DIRECTION, "IN_OUT")
    ip_proto = rule.get(F_IP_PROTOCOL, "IPV4_IPV6")
    logged = str(rule.get(F_LOGGED, False)).lower()
    disabled = str(rule.get(F_DISABLED, False)).lower()
    seq = rule.get(F_SEQUENCE_NUMBER, 0)

    lines = ["rule {"]
    lines.append('  display_name       = {}'.format(_hcl_str(name)))
    lines.append('  nsx_id             = {}'.format(_hcl_str(rid)))
    lines.append('  action             = {}'.format(_hcl_str(action)))
    lines.append('  direction          = {}'.format(_hcl_str(direction)))
    lines.append('  ip_protocol        = {}'.format(_hcl_str(ip_proto)))
    lines.append('  source_groups      = {}'.format(_hcl_groups(src)))
    lines.append('  destination_groups = {}'.format(_hcl_groups(dst)))
    if scope and list(scope) != [ANY]:
        lines.append('  scope              = {}'.format(_hcl_list(scope)))
    if svcs and list(svcs) != [ANY]:
        lines.append('  services           = {}'.format(_hcl_list(svcs)))
    lines.append('  logged             = {}'.format(logged))
    lines.append('  disabled           = {}'.format(disabled))
    lines.append('  sequence_number    = {}'.format(int(seq or 0)))
    lines.append("}")
    return "\n".join(lines)


def _policy_hcl(policy, rules, domain):
    """nsxt_policy_security_policy resource block with inline rule blocks."""
    pid = policy.get(F_ID, "unknown")
    name = policy.get(F_DISPLAY_NAME, pid)
    category = policy.get(F_CATEGORY, "Application")
    scope = policy.get(F_SCOPE, [])
    seq = policy.get(F_SEQUENCE_NUMBER, 0)
    tid = _tf_id(pid)

    lines = ['resource "nsxt_policy_security_policy" {} {{'.format(_hcl_str(tid))]
    lines.append('  display_name    = {}'.format(_hcl_str(name)))
    lines.append('  nsx_id          = {}'.format(_hcl_str(pid)))
    lines.append('  domain          = {}'.format(_hcl_str(domain)))
    lines.append('  category        = {}'.format(_hcl_str(category)))
    lines.append('  sequence_number = {}'.format(int(seq or 0)))
    lines.append('  locked          = false')
    if scope and list(scope) != [ANY]:
        lines.append('  scope           = {}'.format(_hcl_list(scope)))
    for rule in rules:
        lines.append("")
        lines.append(_indent(_rule_block(rule)))
    lines.append("}")
    return "\n".join(lines)


def _cert_hcl(cert):
    """nsxt_certificate resource block (PEM not available via API)."""
    cid = cert.get(F_ID, "unknown")
    name = cert.get(F_DISPLAY_NAME, cid)
    tid = _tf_id(cid)

    lines = ['resource "nsxt_certificate" {} {{'.format(_hcl_str(tid))]
    lines.append('  display_name = {}'.format(_hcl_str(name)))
    lines.append('  nsx_id       = {}'.format(_hcl_str(cid)))
    lines.append('  # pem_encoded = "<paste certificate PEM here>"')
    lines.append("}")
    return "\n".join(lines)


def _imports_hcl(groups, policies, certs, domain):
    """terraform import {} blocks for all exported resources (Terraform >= 1.5)."""
    lines = []
    for g in groups:
        gid = g.get(F_ID, "")
        tid = _tf_id(gid)
        lines.append("import {")
        lines.append('  to = nsxt_policy_group.{}'.format(tid))
        lines.append('  id = "{}/{}"'.format(domain, gid))
        lines.append("}")
    for p in policies:
        pid = p.get(F_ID, "")
        tid = _tf_id(pid)
        lines.append("import {")
        lines.append('  to = nsxt_policy_security_policy.{}'.format(tid))
        lines.append('  id = "{}/{}"'.format(domain, pid))
        lines.append("}")
    for c in certs:
        cid = c.get(F_ID, "")
        tid = _tf_id(cid)
        lines.append("import {")
        lines.append('  to = nsxt_certificate.{}'.format(tid))
        lines.append('  id = "{}"'.format(cid))
        lines.append("}")
    return "\n".join(lines)


_PROVIDER_TF = '''\
terraform {
  required_providers {
    nsxt = {
      source  = "vmware/nsxt"
      version = ">= 3.3.0"
    }
  }
  required_version = ">= 1.5"
}

provider "nsxt" {
  host                 = "<NSX_MANAGER_HOST>"
  username             = "<USERNAME>"
  password             = "<PASSWORD>"
  allow_unverified_ssl = true
}
'''


def act_terraform_export(sessions, out_dir, domain="default",
                         types=("groups", "dfw", "certs")):
    """Fetch NSX config from all managers and write Terraform HCL files."""
    os.makedirs(out_dir, exist_ok=True)
    provider_path = os.path.join(out_dir, "provider.tf")
    with open(provider_path, "w", encoding="utf-8") as f:
        f.write(_PROVIDER_TF)
    say("Wrote {}".format(provider_path))

    for nsx in sessions:
        mgr_dir = os.path.join(out_dir, nsx.name)
        os.makedirs(mgr_dir, exist_ok=True)
        section("{} — Terraform export".format(nsx.name))

        groups = []
        if "groups" in types:
            try:
                base = nsx.base(domain)
                groups = nsx.get_all(p_groups(base, domain))
            except NsxError as exc:
                say("  groups skipped: {}".format(exc))
                groups = []
            if groups:
                blocks = [_group_hcl(g, domain) for g in groups]
                path = os.path.join(mgr_dir, "groups.tf")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n\n".join(blocks) + "\n")
                say("  groups.tf ({} groups)".format(len(groups)))

        policies = []
        policy_rule_map = {}
        if "dfw" in types:
            policies = policies_for(nsx, domain)
            if policies:
                pairs = fetch_rules_for(nsx, domain, policies)
                for pol, rule in pairs:
                    pid = pol.get(F_ID, "")
                    policy_rule_map.setdefault(pid, []).append(rule)
                blocks = []
                for pol in policies:
                    pid = pol.get(F_ID, "")
                    rules = policy_rule_map.get(pid, [])
                    blocks.append(_policy_hcl(pol, rules, domain))
                path = os.path.join(mgr_dir, "dfw.tf")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n\n".join(blocks) + "\n")
                say("  dfw.tf ({} policies)".format(len(policies)))

        certs = []
        if "certs" in types:
            try:
                certs = nsx.get_certificates()
            except NsxError as exc:
                say("  certs skipped: {}".format(exc))
                certs = []
            if certs:
                blocks = [_cert_hcl(c) for c in certs]
                path = os.path.join(mgr_dir, "certs.tf")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n\n".join(blocks) + "\n")
                say("  certs.tf ({} certs)".format(len(certs)))

        if groups or policies or certs:
            imports = _imports_hcl(groups, policies, certs, domain)
            if imports:
                path = os.path.join(mgr_dir, "imports.tf")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(imports + "\n")
                say("  imports.tf")
