"""Connectivity trace: can A reach B, and which rule decided it.

The engine lives in trace.py. This is the operator-facing half, and its one
job beyond printing is to **keep the two answers apart**. "What the policy
says" and "what the data plane did" are different claims, they can legitimately
differ, and a report that blends them into one verdict is worse than either
alone -- so they get separate headings, separate wording, and an explicit
agreement line at the end.
"""

from ..api import F_CATEGORY, F_SEQUENCE_NUMBER
from ..errors import NsxError
from ..output import (
    ask,
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cG,
    confirm,
    cR,
    hr,
    is_interactive,
    say,
    section,
    warn,
)
from ..policy import group_inventory, sweep_rules
from ..trace import (
    DEFAULT_PROTO,
    TF_FINISHED,
    TRACE_DEFAULT_TIMEOUT,
    AmbiguousNic,
    TraceEndpoint,
    build_traceflow_request,
    describe_vif,
    disagreement_reasons,
    groups_containing_address,
    interpret_observations,
    load_service_index,
    local_managers,
    observation_line,
    resolve_vm_endpoint,
    rules_by_realized_id,
    run_traceflow,
    static_evaluate,
    verdicts_agree,
)

TRACE_HEADERS = ["engine", "verdict", "rule", "policy", "manager", "detail"]
TRACE_PATH_HEADERS = ["step", "observation", "component", "node", "detail"]

UNDECIDED_CONSOLE_LIMIT = 5


class TraceOutcome:
    """What the command produced, so the caller can pick an exit code."""

    __slots__ = ("static", "live", "agree", "live_skipped")

    def __init__(self, static=None, live=None, agree=None, live_skipped=""):
        self.static = static
        self.live = live
        self.agree = agree
        self.live_skipped = live_skipped

    @property
    def has_verdict(self):
        if self.live is not None and self.live.conclusive:
            return True
        return bool(self.static and self.static.record)


def _action_colour(action):
    return {"ALLOW": cG, "DROP": cR, "REJECT": cR}.get(action, cBY)


def _rule_label(record):
    seq = record.rule.get(F_SEQUENCE_NUMBER)
    category = record.policy.get(F_CATEGORY)
    bits = []
    if seq is not None:
        bits.append("seq {}".format(seq))
    if category:
        bits.append(str(category))
    suffix = "  [{}]".format(", ".join(bits)) if bits else ""
    return "rule '{}' in policy '{}'{}".format(
        cB(record.rule_name), record.policy_name, cD(suffix))


# === STATIC HALF ===
def _print_static(verdict, proto, port):
    say("\n  {}   {}".format(cB("WHAT THE POLICY SAYS"),
                             cD("(evaluated here -- no packet sent)")))
    hr()
    if verdict.record is None:
        say("    {} no rule in this domain matches {}/{}.".format(
            cBY("NO MATCH:"), proto, port if port is not None else "any"))
        say("    {}".format(cD(
            "NSX's own default applies. If the default section is in another "
            "domain it was not swept.")))
    else:
        colour = _action_colour(verdict.action)
        say("    {}  by {}".format(colour(verdict.action),
                                   _rule_label(verdict.record)))
        say("    {}".format(cD("on {}  ({} rule(s) evaluated)".format(
            verdict.record.nsx.name, verdict.evaluated))))

    if verdict.undecided:
        say("\n    {} {} rule(s) ahead of this one could not be "
            "decided:".format(cBY("UNCERTAIN:"), len(verdict.undecided)))
        for record, reason in verdict.undecided[:UNDECIDED_CONSOLE_LIMIT]:
            say("      {} / {}".format(cB(record.policy_name), record.rule_name))
            say("        {}".format(cD(reason)))
        if len(verdict.undecided) > UNDECIDED_CONSOLE_LIMIT:
            say("      {}".format(cD("... +{} more".format(
                len(verdict.undecided) - UNDECIDED_CONSOLE_LIMIT))))
        say("    {}".format(cD(
            "Any of them may be the real match, so the verdict above is the "
            "first rule this can prove -- not necessarily the first rule NSX "
            "hits.")))


# === LIVE HALF ===
def _print_live(live):
    say("\n  {}   {}".format(cB("WHAT THE DATA PLANE DID"),
                             cD("(traceflow -- a synthetic packet was sent)")))
    hr()
    if live.state != TF_FINISHED:
        say("    {} traceflow ended in state {}.".format(cBY("NO VERDICT:"),
                                                         live.state))
        say("    {}".format(cD(
            "No observation came back, so nothing is claimed about this "
            "flow either way.")))
        return
    if not live.conclusive:
        say("    {} the packet was neither delivered nor dropped in the "
            "observations returned.".format(cBY("NO VERDICT:")))
        return

    obs = live.verdict_obs
    if live.delivered:
        say("    {}  at {}".format(
            cBG("DELIVERED"), obs.get("transport_node_name", "?")))
    else:
        say("    {}  at {} on {}".format(
            cBR("DROPPED"), obs.get("component_type", "?"),
            obs.get("transport_node_name", "?")))
        if live.record is not None:
            say("    by {}".format(_rule_label(live.record)))
            say("    {}".format(cD("acl_rule_id {}".format(live.acl_rule_id))))
        elif live.acl_rule_id:
            say("    by DFW rule id {} -- {}".format(
                cB(str(live.acl_rule_id)),
                cD("no rule in this domain carries that id")))
        elif obs.get("reason"):
            say("    reason: {}".format(obs.get("reason")))

    if live.observations:
        say("\n    {}".format(cD("path:")))
        for entry in live.observations:
            say("      {}".format(cD(observation_line(entry))))


# === AGREEMENT ===
def _print_agreement(outcome):
    if outcome.live_skipped:
        say("\n  {} {}".format(cBY("Live trace not run:"), outcome.live_skipped))
        return
    if outcome.agree is None:
        return
    hr()
    if outcome.agree:
        say("  {} the policy and the data plane tell the same story.".format(
            cBG("Agreed:")))
        return
    say("  {} the policy and the data plane disagree.".format(
        cBR("DISAGREEMENT:")))
    say("    policy says   : {}".format(
        _action_colour(outcome.static.action)(outcome.static.action or "?")))
    say("    data plane did: {}".format(
        _action_colour(outcome.live.action)(outcome.live.action or "?")))
    say("\n    {}".format(cD("This is a finding, not an error. Causes, most "
                             "likely first:")))
    for reason in disagreement_reasons(outcome.static, outcome.live):
        say("      - {}".format(cD(reason)))


# === ROWS ===
def _rows_for(outcome):
    rows = []
    static = outcome.static
    if static is not None:
        record = static.record
        rows.append([
            "policy", static.action or "no_match",
            record.rule_name if record else "",
            record.policy_name if record else "",
            record.nsx.name if record else "",
            "certain" if static.certain else "{} rule(s) undecided".format(
                len(static.undecided))])
    live = outcome.live
    if live is not None:
        rows.append([
            "data_plane", live.action or live.state,
            live.record.rule_name if live.record else (
                str(live.acl_rule_id) if live.acl_rule_id else ""),
            live.record.policy_name if live.record else "",
            live.record.nsx.name if live.record else "",
            "state {}".format(live.state)])
    return rows


def _path_rows(live):
    rows = []
    for index, obs in enumerate((live.observations if live else []), 1):
        rows.append([str(index),
                     str(obs.get("resource_type", "")).replace(
                         "TraceflowObservation", ""),
                     obs.get("component_type", ""),
                     obs.get("transport_node_name", ""),
                     obs.get("reason", "")])
    return rows


# === ACTION ===
def act_trace(sessions, source_name, target_name=None, domain="default",
              exporter=None, port=None, proto=DEFAULT_PROTO, to_address=None,
              static_only=False, nic=None, timeout=TRACE_DEFAULT_TIMEOUT):
    """Trace one flow. Returns a TraceOutcome; prints the whole report.

    Static evaluation always runs: it is nearly free once the rule sweep has
    happened (and the sweep has to happen anyway, to turn a numeric
    acl_rule_id into a rule name), it needs no packet, and it is the only
    answer available on a Global Manager or a powered-off VM.
    """
    section("CONNECTIVITY TRACE")

    want_live = not static_only
    live_skipped = ""
    if want_live and not local_managers(sessions):
        want_live = False
        live_skipped = (
            "traceflow is a Local Manager API -- the Global Manager does not "
            "serve it, and this inventory has no LM connected.")

    source = resolve_vm_endpoint(sessions, source_name, domain, nic=nic,
                                 need_port=want_live)
    destination = _resolve_destination(sessions, target_name, to_address,
                                       domain)

    if want_live and not source.powered_on:
        want_live = False
        live_skipped = (
            "{} is not powered on, so it has no live port to inject a packet "
            "at.".format(source.label))
    elif want_live and not source.lport_id:
        want_live = False
        live_skipped = (
            "{}'s NIC has no realized logical port on {} -- there is nothing "
            "to inject at.".format(source.label, source.nsx.name))
    elif want_live and not destination.ip:
        want_live = False
        live_skipped = (
            "no address resolved for the destination. Give one explicitly "
            "with --to ADDRESS.")

    say("  source      : {}".format(cC(source.describe())))
    say("  destination : {}".format(cC(destination.describe())))
    say("  flow        : {}/{}".format(proto,
                                       port if port is not None else "any"))
    if source.groups or destination.groups:
        say("  groups      : source {}, destination {}".format(
            len(source.groups), len(destination.groups)))

    records = sweep_rules(sessions, domain)
    services = load_service_index(sessions, domain)
    static = static_evaluate(records, source, destination, services,
                             proto=proto, port=port)
    _print_static(static, proto, port)

    live = None
    if want_live:
        live, live_skipped = _run_live(source, destination, records,
                                       proto, port, timeout)
        if live is not None:
            _print_live(live)

    outcome = TraceOutcome(static=static, live=live,
                           agree=verdicts_agree(static, live),
                           live_skipped=live_skipped)
    _print_agreement(outcome)
    hr()

    if exporter is not None:
        exporter.stage("trace", TRACE_HEADERS, _rows_for(outcome))
        exporter.stage("trace_path", TRACE_PATH_HEADERS, _path_rows(live))
    return outcome


def _resolve_destination(sessions, target_name, to_address, domain):
    """A VM by name, or a bare address."""
    if to_address:
        groups = group_inventory(sessions, domain)
        return TraceEndpoint(ip=to_address, label=to_address,
                             groups=groups_containing_address(groups,
                                                              to_address))
    if not target_name:
        raise NsxError("Give a destination VM, or an address with --to.")
    return resolve_vm_endpoint(sessions, target_name, domain, need_port=False)


def _run_live(source, destination, records, proto, port, timeout):
    """(LiveVerdict or None, reason it was skipped).

    The packet is synthetic and harmless, but it is real traffic on somebody's
    data plane, so it is confirmed like a write rather than assumed like a
    read.
    """
    prompt = "\n  {} inject a synthetic {}/{} packet at {} on {}? [y/N]: ".format(
        cB("Traceflow:"), proto, port if port is not None else "any",
        source.label, source.nsx.name)
    if not confirm(prompt):
        if not is_interactive():
            return None, ("injecting a packet needs consent. Pass --yes for a "
                          "script, or --static for policy evaluation only.")
        return None, "declined at the prompt."

    request = build_traceflow_request(
        source.lport_id, source.ip, destination.ip, source.mac,
        destination.mac, proto=proto, port=port)
    try:
        _tid, state, observations = run_traceflow(source.nsx, request,
                                                  timeout=timeout)
    except NsxError as e:
        return None, "traceflow failed on {}: {}".format(source.nsx.name, e)
    return interpret_observations(state, observations,
                                  rules_by_realized_id(records)), ""


def report_ambiguous_nic(error):
    """Print the NIC list a multi-NIC VM needs the operator to choose from."""
    warn(str(error))
    say("  {} has these NICs:".format(cB(error.vm_name)))
    for index, vif in enumerate(error.vifs):
        say("    {}".format(describe_vif(vif, index)))
    say("\n  {}".format(cD("Re-run with --nic 1, or --nic 'Network adapter 2'.")))


def trace_menu(ctx):
    """Interactive entry: menu 17."""
    source = ask("  Source VM: ")
    if not source:
        return
    target = ask("  Destination VM (blank to give an address): ", default="")
    address = "" if target else ask("  Destination address: ", default="")
    if not target and not address:
        say("  Need a destination.")
        return
    port = ask("  Destination port (blank = any): ", default="")
    proto = ask("  Protocol [tcp]: ", default=DEFAULT_PROTO)
    live = confirm("  Send a real traceflow packet? [y/N]: ")
    try:
        act_trace(ctx.sessions, source, target or None, ctx.domain,
                  ctx.exporter, port=int(port) if port.strip().isdigit() else None,
                  proto=proto or DEFAULT_PROTO, to_address=address or None,
                  static_only=not live)
    except AmbiguousNic as e:
        report_ambiguous_nic(e)
