"""Gateway Firewall write operations: create, edit, move, delete rules and policies."""
import re

from ..api import (
    ANY,
    F_DISPLAY_NAME,
    F_ID,
    F_SEQUENCE_NUMBER,
)
from ..errors import NsxError
from ..output import cBG, cBR, cBY, confirm, say, section


def _gw_slug(name):
    """Turn a display name into a valid NSX object ID."""
    slug = re.sub(r"[^a-zA-Z0-9_-]", "-", name).strip("-")
    return slug or "rule"


def _resolve_policy(nsx, name, domain):
    """Return the first gateway policy matching *name* (exact then substring)."""
    policies = nsx.get_gw_policies(domain)
    exact = next((p for p in policies
                  if p.get(F_DISPLAY_NAME) == name or p.get(F_ID) == name), None)
    if exact:
        return exact
    hits = [p for p in policies
            if name.lower() in (p.get(F_DISPLAY_NAME) or "").lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise NsxError(
            "Ambiguous policy name '{}': matches {}. Use the full name.".format(
                name, ", ".join(p.get(F_DISPLAY_NAME, p.get(F_ID)) for p in hits)))
    raise NsxError("Gateway policy '{}' not found.".format(name))


def _resolve_rule(nsx, policy_id, name, domain):
    """Return the first rule in *policy_id* matching *name*."""
    rules = nsx.get_gw_rules(policy_id, domain)
    exact = next((r for r in rules
                  if r.get(F_DISPLAY_NAME) == name or r.get(F_ID) == name), None)
    if exact:
        return exact
    hits = [r for r in rules
            if name.lower() in (r.get(F_DISPLAY_NAME) or "").lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise NsxError(
            "Ambiguous rule name '{}': matches {}.".format(
                name, ", ".join(r.get(F_DISPLAY_NAME, r.get(F_ID)) for r in hits)))
    raise NsxError("Rule '{}' not found in policy.".format(name))


# ── gw-policy create / delete ────────────────────────────────────────────────

def act_gw_policy_create(sessions, domain, exporter, name, category,
                         seq, enable_writes, yes):
    """Create a gateway policy on every session."""
    pid = _gw_slug(name)
    body = {
        "id": pid,
        "display_name": name,
        "category": category,
        "sequence_number": seq,
    }
    section("GW policy create — {}".format(name))
    if not enable_writes:
        say("  {} id={} category={} seq={}".format(
            cBY("DRY RUN:"), pid, category, seq))
        say("  Re-run with --enable-writes to apply.")
        return
    for nsx in sessions:
        try:
            nsx.put_gw_policy(domain, pid, body)
            say("  {} [{}]".format(cBG("Created"), nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))


def act_gw_policy_delete(sessions, domain, exporter, name, enable_writes, yes):
    """Delete a gateway policy on every session."""
    section("GW policy delete — {}".format(name))
    if not enable_writes:
        say("  {} Re-run with --enable-writes to apply.".format(cBY("DRY RUN.")))
        return
    for nsx in sessions:
        try:
            pol = _resolve_policy(nsx, name, domain)
            pid = pol[F_ID]
            say("  About to delete policy '{}' ({}) from [{}]".format(
                pol.get(F_DISPLAY_NAME, pid), pid, nsx.name))
            if not confirm("  Proceed? [y/N]: "):
                say("  Cancelled.")
                continue
            nsx.delete_gw_policy(domain, pid)
            say("  {} [{}]".format(cBG("Deleted"), nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))


# ── gw-rule create / edit / move / delete ────────────────────────────────────

def act_gw_rule_create(sessions, domain, exporter, policy, name,
                       src, dst, service, action, seq, logged,
                       disabled, enable_writes, yes):
    """Create a gateway firewall rule."""
    rid = _gw_slug(name)
    body = {
        "id": rid,
        "display_name": name,
        "action": action.upper(),
        "source_groups": src or [ANY],
        "destination_groups": dst or [ANY],
        "services": [service] if service else [ANY],
        "sequence_number": seq,
        "logged": logged,
        "disabled": disabled,
    }
    section("GW rule create — {}".format(name))
    if not enable_writes:
        say("  {} policy={} action={} src={} dst={} service={}".format(
            cBY("DRY RUN:"), policy, action,
            src or ["ANY"], dst or ["ANY"], service or "ANY"))
        say("  Re-run with --enable-writes to apply.")
        return
    for nsx in sessions:
        try:
            pol = _resolve_policy(nsx, policy, domain)
            pid = pol[F_ID]
            nsx.put_gw_rule(domain, pid, rid, body)
            say("  {} [{}]".format(cBG("Created"), nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))


def act_gw_rule_edit(sessions, domain, exporter, policy, name,
                     action, src, dst, service, logged, disabled,
                     enable_writes, yes):
    """Edit fields on an existing gateway firewall rule."""
    section("GW rule edit — {}".format(name))
    if not enable_writes:
        say("  {} Re-run with --enable-writes to apply.".format(cBY("DRY RUN.")))
        return
    for nsx in sessions:
        try:
            pol = _resolve_policy(nsx, policy, domain)
            pid = pol[F_ID]
            rule = _resolve_rule(nsx, pid, name, domain)
            updated = dict(rule)
            if action is not None:
                updated["action"] = action.upper()
            if src is not None:
                updated["source_groups"] = src
            if dst is not None:
                updated["destination_groups"] = dst
            if service is not None:
                updated["services"] = [service]
            if logged is not None:
                updated["logged"] = logged
            if disabled is not None:
                updated["disabled"] = disabled
            if not confirm("  Apply changes to '{}' in [{}]? [y/N]: ".format(
                    name, nsx.name)):
                say("  Cancelled.")
                continue
            nsx.put_gw_rule(domain, pid, rule[F_ID], updated)
            say("  {} [{}]".format(cBG("Updated"), nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))


def act_gw_rule_move(sessions, domain, exporter, policy, name,
                     before, enable_writes, yes):
    """Reorder a gateway rule to appear before another rule."""
    section("GW rule move — {} before {}".format(name, before))
    if not enable_writes:
        say("  {} Re-run with --enable-writes to apply.".format(cBY("DRY RUN.")))
        return
    for nsx in sessions:
        try:
            pol = _resolve_policy(nsx, policy, domain)
            pid = pol[F_ID]
            rule = _resolve_rule(nsx, pid, name, domain)
            anchor = _resolve_rule(nsx, pid, before, domain)
            anchor_seq = anchor.get(F_SEQUENCE_NUMBER, 10)
            new_seq = max(1, anchor_seq - 1)
            updated = dict(rule)
            updated[F_SEQUENCE_NUMBER] = new_seq
            nsx.put_gw_rule(domain, pid, rule[F_ID], updated)
            say("  {} seq={} [{}]".format(cBG("Moved"), new_seq, nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))


def act_gw_rule_delete(sessions, domain, exporter, policy, name,
                       enable_writes, yes):
    """Delete a gateway firewall rule."""
    section("GW rule delete — {}".format(name))
    if not enable_writes:
        say("  {} Re-run with --enable-writes to apply.".format(cBY("DRY RUN.")))
        return
    for nsx in sessions:
        try:
            pol = _resolve_policy(nsx, policy, domain)
            pid = pol[F_ID]
            rule = _resolve_rule(nsx, pid, name, domain)
            rid = rule[F_ID]
            say("  About to delete '{}' ({}) from policy '{}' [{}]".format(
                rule.get(F_DISPLAY_NAME, rid), rid,
                pol.get(F_DISPLAY_NAME, pid), nsx.name))
            if not confirm("  Proceed? [y/N]: "):
                say("  Cancelled.")
                continue
            nsx.delete_gw_rule(domain, pid, rid)
            say("  {} [{}]".format(cBG("Deleted"), nsx.name))
        except NsxError as e:
            say("  {} [{}] {}".format(cBR("FAILED"), nsx.name, str(e)))
