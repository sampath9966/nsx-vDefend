"""Can A reach B, and which rule decided it.

Two engines answer that question, and **they answer different questions**, so
nothing here ever prints them in the same voice:

  * **Live traceflow** injects a synthetic packet at the source VM's logical
    port and reports what the data plane actually did with it. It is the truth,
    and it is only available where a real port exists to inject at.
  * **Static evaluation** walks the deduplicated rule set in NSX evaluation
    order and reports the first rule that matches. It works on a Global
    Manager, on a powered-off VM, and on a rule that has not been realized
    onto a host yet -- but it is what the policy *says*, not what happened.

When both run and disagree, that disagreement is itself the finding: NAT, a
partial realization, or a rule not yet pushed to a host will all produce it.

Four things make the live path harder than it looks.

**Traceflow is a Manager API and does not exist on the Global Manager.** It is
`/api/v1/traceflow`, absolute, not under `/infra`, so the command has to find
the Local Manager that actually hosts the source VM and target that manager.
A GM-only inventory cannot trace at all and is told so.

**It needs a logical port, not a VM.** VM -> VIF -> logical switch port is the
real resolution chain. A multi-NIC VM is genuinely ambiguous, so the NICs are
listed and the operator picks; a powered-off VM or an unrealized port gets its
own message rather than an obscure failure inside NSX.

**It is asynchronous and it injects a real packet.** POST returns an id,
observations arrive over the next few seconds, and the traceflow object has to
be deleted afterwards. Unlike everything else in the toolkit this is a read
that does something to the data plane -- synthetic and harmless, but real --
so it sits behind the same confirmation posture as a write.

**The verdict comes back as a number.** An observation says "dropped by
acl_rule_id 4130", with no name attached. `rule_id` on the policy rule carries
that same integer, so the deduplicated sweep that rule hygiene already
produces is what turns 4130 into "rule 'block-legacy-db' in policy 'app-tier'".
"""

import time

from .api import (
    F_ACL_RULE_ID,
    F_ACTION_FIELD,
    F_ATTACHMENT,
    F_CATEGORY,
    F_COMPONENT_NAME,
    F_COMPONENT_TYPE,
    F_DESTINATION_PORTS,
    F_DEVICE_NAME,
    F_DISABLED,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_EXTERNAL_ID,
    F_ID,
    F_IP_ADDRESS_INFO,
    F_IP_ADDRESSES,
    F_L4_PROTOCOL,
    F_LPORT_ATTACHMENT_ID,
    F_LPORT_ID,
    F_MAC_ADDRESS,
    F_OPERATION_STATE,
    F_PACKET,
    F_PATH,
    F_POWER_STATE,
    F_REASON,
    F_RULE_ID,
    F_SCOPE,
    F_SEQUENCE_NO,
    F_SEQUENCE_NUMBER,
    F_SERVICE_ENTRIES,
    F_SERVICES,
    F_TARGET_ID,
    F_TRANSPORT_NODE_NAME,
    IP_PROTOCOLS,
    OBS_DELIVERED_TYPES,
    OBS_DROP_TYPES,
    PARAM_ATTACHMENT_ID,
    PARAM_OWNER_VM_ID,
    PARAM_VM_EXTERNAL_ID,
    PATH_FABRIC_VIFS,
    PATH_LOGICAL_PORTS,
    PATH_TRACEFLOW,
    ROLE_LM,
    RT,
    RT_FIELDS_PACKET,
    RT_L4_PORTSET,
    TF_FINISHED,
    TF_IN_PROGRESS,
    TF_TERMINAL_STATES,
    category_rank,
    group_id_from_path,
    p_services,
    p_traceflow_observations,
    p_traceflow_one,
    p_vm_group_assoc,
)
from .errors import NsxError
from .output import debug
from .policy import (
    is_wildcard,
    listed_values,
    ordered_sessions,
    rule_sequence,
)

# How a rule relates to the flow being traced.
MATCH, NO_MATCH, UNDECIDED = "match", "no_match", "undecided"

TRACE_DEFAULT_TIMEOUT = 15.0
TRACE_POLL_INTERVAL = 0.5
DEFAULT_PROTO = "tcp"
POWERED_ON = "VM_RUNNING"

# The MAC used when the destination is an address rather than a VM we can
# resolve. NSX rewrites the L2 header on a routed traceflow anyway, and the
# request is marked routed, so this is a placeholder and not a claim.
PLACEHOLDER_MAC = "02:00:00:00:00:01"


def parse_duration(text, default=TRACE_DEFAULT_TIMEOUT):
    """'15', '15s' or '2m' -> seconds. Raises on anything else."""
    if text is None or str(text).strip() == "":
        return default
    raw = str(text).strip().lower()
    multiplier = 1.0
    if raw.endswith("ms"):
        raw, multiplier = raw[:-2], 0.001
    elif raw.endswith("s"):
        raw = raw[:-1]
    elif raw.endswith("m"):
        raw, multiplier = raw[:-1], 60.0
    try:
        seconds = float(raw) * multiplier
    except ValueError:
        raise NsxError(
            "Could not read '{}' as a duration. Use 15, 15s or 2m.".format(
                text)) from None
    if seconds <= 0:
        raise NsxError("Timeout must be greater than zero.")
    return seconds


# === ENDPOINT RESOLUTION ===
class TraceEndpoint:
    """One end of a trace: a VM with a port to inject at, or a bare address."""

    __slots__ = ("nsx", "vm", "vif", "lport_id", "ip", "mac", "label", "groups")

    def __init__(self, nsx=None, vm=None, vif=None, lport_id=None, ip=None,
                 mac=None, label="", groups=None):
        self.nsx = nsx
        self.vm = vm
        self.vif = vif
        self.lport_id = lport_id
        self.ip = ip
        self.mac = mac
        self.label = label
        self.groups = set(groups or ())

    @property
    def is_vm(self):
        return self.vm is not None

    @property
    def powered_on(self):
        return (self.vm or {}).get(F_POWER_STATE) == POWERED_ON

    def describe(self):
        if not self.is_vm:
            return "{} (address)".format(self.ip or self.label)
        parts = [self.label]
        if self.ip:
            parts.append(self.ip)
        if self.nsx is not None:
            parts.append("on " + self.nsx.name)
        return "  ".join(parts)


class AmbiguousNic(NsxError):
    """A multi-NIC VM was traced without saying which NIC.

    Deliberately not resolved by picking the first one: on a VM with a
    management NIC and a data NIC, injecting at the wrong one answers a
    question nobody asked.
    """

    def __init__(self, vm_name, vifs):
        self.vm_name = vm_name
        self.vifs = list(vifs)
        super().__init__(
            "{} has {} NICs -- say which one with --nic.".format(
                vm_name, len(self.vifs)))


def local_managers(sessions):
    return [s for s in sessions if s.role == ROLE_LM]


def find_vm_on_lms(sessions, needle):
    """(nsx, vm) for the Local Manager that hosts a VM.

    Traceflow, VM inventory and tags are all LM-local, so this is also the
    answer to "which manager do I POST the traceflow to".
    """
    for nsx in local_managers(sessions):
        try:
            hits = nsx.find_vms(needle, exact=True) or nsx.find_vms(needle)
        except NsxError as e:
            debug("VM lookup on {} failed: {}".format(nsx.name, e))
            continue
        if hits:
            return nsx, hits[0]
    return None, None


def vifs_for_vm(nsx, vm):
    """Every virtual NIC of a VM, in device order."""
    ext = vm.get(F_EXTERNAL_ID)
    if not ext:
        return []
    vifs = nsx.get_all(PATH_FABRIC_VIFS, params={PARAM_OWNER_VM_ID: ext})
    return sorted(vifs, key=lambda v: str(v.get(F_DEVICE_NAME, "")))


def vif_addresses(vif):
    """Every IP NSX has learned on a VIF."""
    out = []
    for info in (vif.get(F_IP_ADDRESS_INFO) or []):
        out.extend(str(ip).split("/")[0] for ip in (info.get(F_IP_ADDRESSES) or []))
    return out


def describe_vif(vif, index=0):
    ips = vif_addresses(vif)
    return "{}. {:24s} {:20s} {}".format(
        index + 1,
        vif.get(F_DEVICE_NAME, "?"),
        vif.get(F_MAC_ADDRESS, "?"),
        ", ".join(ips) or "(no address learned)")


def select_vif(vm_name, vifs, wanted=None):
    """Pick the NIC to trace from, or refuse to guess.

    `wanted` accepts a 1-based index or a device-name substring, so both
    `--nic 2` and `--nic "Network adapter 2"` work.
    """
    if not vifs:
        raise NsxError(
            "{} has no VIF on this manager. A VM that has never been powered "
            "on, or whose NIC is not attached to an NSX segment, has no "
            "logical port to trace from.".format(vm_name))
    if wanted:
        text = str(wanted).strip()
        if text.isdigit() and 1 <= int(text) <= len(vifs):
            return vifs[int(text) - 1]
        needle = text.lower()
        hits = [v for v in vifs
                if needle in str(v.get(F_DEVICE_NAME, "")).lower()
                or needle == str(v.get(F_MAC_ADDRESS, "")).lower()]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise NsxError("{} has no NIC matching '{}'. It has: {}".format(
                vm_name, wanted,
                "; ".join(str(v.get(F_DEVICE_NAME, "?")) for v in vifs)))
        raise AmbiguousNic(vm_name, hits)
    if len(vifs) == 1:
        return vifs[0]
    raise AmbiguousNic(vm_name, vifs)


def logical_port_for_vif(nsx, vif):
    """The logical switch port a VIF is attached to, or None if unrealized."""
    attachment = vif.get(F_LPORT_ATTACHMENT_ID)
    if not attachment:
        return None
    try:
        ports = nsx.get_all(PATH_LOGICAL_PORTS,
                            params={PARAM_ATTACHMENT_ID: attachment})
    except NsxError as e:
        debug("logical port lookup failed: {}".format(e))
        return None
    for port in ports:
        if (port.get(F_ATTACHMENT) or {}).get(F_ID) == attachment:
            return port
    return ports[0] if ports else None


def vm_group_paths(nsx, domain, vm):
    """Every group path a VM is an effective member of.

    Uses NSX's own reverse-association index rather than each group's VM
    member sub-resource, for the reason act_reverse_lookup documents: the
    sub-resource is silent for groups matched on VIF, IP-set, segment or
    segment-port criteria, and a static verdict computed from a partial
    membership set would name the wrong rule.
    """
    ext = vm.get(F_EXTERNAL_ID)
    if not ext:
        return set()
    try:
        assocs = nsx.get_all(p_vm_group_assoc(nsx.base(domain)),
                             params={PARAM_VM_EXTERNAL_ID: ext})
    except NsxError as e:
        debug("association lookup on {} failed: {}".format(nsx.name, e))
        return set()
    paths = set()
    for assoc in assocs:
        path = assoc.get(F_PATH)
        if path:
            paths.add(path)
        target = assoc.get(F_TARGET_ID)
        if target:
            paths.add(target)
    return paths


def groups_containing_address(groups, address):
    """Group paths whose criteria literally lists an address.

    Deliberately a literal match and not CIDR arithmetic: an address endpoint
    resolves to the groups that name it and nothing more, so a static verdict
    for `--to 10.20.30.40` under-claims rather than inventing membership.
    """
    if not address:
        return set()
    hits = set()
    for path, (_nsx, group) in groups.items():
        for item in (group.get(F_EXPRESSION) or []):
            values = item.get(F_IP_ADDRESSES) or []
            if any(str(v).split("/")[0] == address for v in values):
                hits.add(path)
                hits.add(group.get(F_ID, ""))
    hits.discard("")
    return hits


def resolve_vm_endpoint(sessions, needle, domain, nic=None, need_port=True):
    """A VM endpoint, with its NIC, address and group membership resolved."""
    nsx, vm = find_vm_on_lms(sessions, needle)
    if vm is None:
        raise NsxError(
            "No VM matching '{}' on any Local Manager. VM inventory is "
            "LM-local -- a Global Manager holds none.".format(needle))
    name = vm.get(F_DISPLAY_NAME, needle)
    endpoint = TraceEndpoint(nsx=nsx, vm=vm, label=name,
                             groups=vm_group_paths(nsx, domain, vm))
    if not need_port:
        # Static evaluation matches on group membership, never on addresses,
        # so no NIC is chosen here: picking one to fill in an IP column would
        # be a guess that reads like a fact on a multi-NIC VM.
        try:
            vifs = vifs_for_vm(nsx, vm)
        except NsxError as e:
            debug("VIF lookup for {} failed: {}".format(name, e))
            vifs = []
        if len(vifs) == 1 or (vifs and nic):
            chosen = select_vif(name, vifs, nic)
            endpoint.vif = chosen
            endpoint.mac = chosen.get(F_MAC_ADDRESS)
            addresses = vif_addresses(chosen)
            endpoint.ip = addresses[0] if addresses else None
        return endpoint

    vif = select_vif(name, vifs_for_vm(nsx, vm), nic)
    endpoint.vif = vif
    endpoint.mac = vif.get(F_MAC_ADDRESS)
    addresses = vif_addresses(vif)
    endpoint.ip = addresses[0] if addresses else None
    port = logical_port_for_vif(nsx, vif)
    endpoint.lport_id = (port or {}).get(F_ID)
    return endpoint


# === STATIC EVALUATION ===
def evaluation_order(records):
    """Rules in the order NSX evaluates them.

    Category first, and that is the part a per-policy ordering misses: every
    rule in an earlier category is evaluated before any rule in a later one,
    whatever the sequence numbers say. Rule hygiene only ever compares rules
    inside one policy, so it never needed this; a verdict does.
    """
    def key(record):
        return (category_rank(record.policy.get(F_CATEGORY)),
                _int_or_zero(record.policy.get(F_SEQUENCE_NUMBER)),
                str(record.policy_name),
                rule_sequence(record),
                str(record.rule_name))
    return sorted(records, key=key)


def _int_or_zero(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def load_service_index(sessions, domain):
    """{service path: service} across every manager, GM first.

    Needed because a rule names its services by path, and "does this rule
    cover port 3306" cannot be answered from the path alone.
    """
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    index = {}
    for nsx in gm_sessions + lm_sessions:
        try:
            services = nsx.get_all(p_services(nsx.base(domain)))
        except NsxError as e:
            debug("service listing on {} failed: {}".format(nsx.name, e))
            continue
        for service in services:
            path = service.get(F_PATH)
            if path and path not in index:
                index[path] = service
    return index


def port_in_spec(port, spec):
    """Whether a port falls in an NSX port spec ('443' or '8000-8100')."""
    text = str(spec).strip()
    try:
        if "-" in text:
            low, _, high = text.partition("-")
            return int(low) <= int(port) <= int(high)
        return int(text) == int(port)
    except (TypeError, ValueError):
        return False


def service_port_verdict(service, proto, port):
    """MATCH / NO_MATCH / UNDECIDED for one service against a port.

    Only `L4PortSetServiceEntry` reduces to a port comparison. ICMP, ALG,
    IP-protocol and nested entries are left UNDECIDED rather than guessed at:
    claiming a rule does not match when it might is how a trace names the
    wrong rule.
    """
    entries = service.get(F_SERVICE_ENTRIES) or []
    if not entries:
        return UNDECIDED
    excluded = False
    for entry in entries:
        if entry.get(RT) != RT_L4_PORTSET:
            return UNDECIDED
        same_proto = str(entry.get(F_L4_PROTOCOL, "")).upper() == \
            str(proto).upper()
        ports = entry.get(F_DESTINATION_PORTS) or []
        if not ports:
            if same_proto:
                return MATCH
            excluded = True
            continue
        if same_proto and any(port_in_spec(port, spec) for spec in ports):
            return MATCH
        excluded = True
    return NO_MATCH if excluded else UNDECIDED


def rule_service_verdict(rule, services, proto, port):
    """MATCH / NO_MATCH / UNDECIDED for a rule's whole service list."""
    named = listed_values(rule, F_SERVICES)
    if is_wildcard(named):
        return MATCH, ""
    if port is None:
        return UNDECIDED, ("limited to {} and no --port was given".format(
            ", ".join(_service_names(named, services))))
    undecided = []
    for path in named:
        service = services.get(path)
        if service is None:
            undecided.append(path.rsplit("/", 1)[-1])
            continue
        verdict = service_port_verdict(service, proto, port)
        if verdict == MATCH:
            return MATCH, ""
        if verdict == UNDECIDED:
            undecided.append(service.get(F_DISPLAY_NAME) or
                             path.rsplit("/", 1)[-1])
    if undecided:
        return UNDECIDED, ("service {} is not a plain L4 port set".format(
            ", ".join(sorted(undecided))))
    return NO_MATCH, ""


def _service_names(paths, services):
    names = []
    for path in paths:
        service = services.get(path)
        names.append(service.get(F_DISPLAY_NAME) if service
                     else path.rsplit("/", 1)[-1])
    return names or ["(none)"]


def _side_matches(rule, field, endpoint_groups):
    """Whether one side of a rule can match an endpoint."""
    named = listed_values(rule, field)
    if is_wildcard(named):
        return True
    if not endpoint_groups:
        return False
    if set(named) & endpoint_groups:
        return True
    # A rule may name a group by path where the association index returned an
    # id, or the other way round; compare on ids as well before deciding no.
    ids = {group_id_from_path(p) for p in named}
    return bool(ids & {group_id_from_path(p) for p in endpoint_groups})


def rule_flow_verdict(record, source, destination, services, proto, port):
    """(MATCH | NO_MATCH | UNDECIDED, reason) for one rule against one flow.

    Direction is deliberately not used to exclude a rule. The packet crosses
    both endpoints' vNICs, so an IN rule enforced at the destination and an
    OUT rule enforced at the source are both on its path; treating either as
    inapplicable would skip a rule that really can decide the flow.
    """
    rule = record.rule
    if rule.get(F_DISABLED):
        return NO_MATCH, "disabled"

    scope = listed_values(rule, F_SCOPE)
    if not is_wildcard(scope):
        endpoints = source.groups | destination.groups
        if not (set(scope) & endpoints or
                {group_id_from_path(p) for p in scope} &
                {group_id_from_path(p) for p in endpoints}):
            return NO_MATCH, "applied-to does not cover either endpoint"

    if not _side_matches(rule, "source_groups", source.groups):
        return NO_MATCH, "source does not match"
    if not _side_matches(rule, "destination_groups", destination.groups):
        return NO_MATCH, "destination does not match"

    verdict, reason = rule_service_verdict(rule, services, proto, port)
    if verdict == MATCH:
        return MATCH, ""
    if verdict == NO_MATCH:
        return NO_MATCH, "service does not cover {}/{}".format(proto, port)
    return UNDECIDED, reason


class StaticVerdict:
    """What the policy says, and how much of it could actually be decided."""

    __slots__ = ("record", "undecided", "evaluated")

    def __init__(self, record=None, undecided=(), evaluated=0):
        self.record = record
        self.undecided = list(undecided)
        self.evaluated = evaluated

    @property
    def action(self):
        if self.record is None:
            return None
        return self.record.rule.get(F_ACTION_FIELD, "?")

    @property
    def allowed(self):
        return self.action == "ALLOW"

    @property
    def certain(self):
        """A verdict is only certain when nothing ahead of it was undecided.

        An undecided rule earlier in evaluation order could have matched
        first, which would make it -- not this one -- the real answer.
        """
        return bool(self.record) and not self.undecided


def static_evaluate(records, source, destination, services, proto=DEFAULT_PROTO,
                    port=None):
    """First matching rule in NSX evaluation order, with what it could not
    decide along the way."""
    undecided = []
    evaluated = 0
    for record in evaluation_order(records):
        evaluated += 1
        verdict, reason = rule_flow_verdict(record, source, destination,
                                            services, proto, port)
        if verdict == MATCH:
            return StaticVerdict(record, undecided, evaluated)
        if verdict == UNDECIDED:
            undecided.append((record, reason))
    return StaticVerdict(None, undecided, evaluated)


# === LIVE TRACEFLOW ===
def rules_by_realized_id(records):
    """{acl_rule_id: RuleRecord}. The join between an observation and a name."""
    index = {}
    for record in records:
        realized = record.rule.get(F_RULE_ID)
        if realized is None:
            continue
        try:
            index[int(realized)] = record
        except (TypeError, ValueError):
            continue
    return index


def build_traceflow_request(lport_id, src_ip, dst_ip, src_mac, dst_mac,
                            proto=DEFAULT_PROTO, port=None, src_port=49152,
                            frame_size=128):
    """The synthetic packet to inject, and where to inject it."""
    protocol = IP_PROTOCOLS.get(str(proto).lower())
    if protocol is None:
        raise NsxError("Unsupported protocol '{}'. Use {}.".format(
            proto, " | ".join(sorted(IP_PROTOCOLS))))
    packet = {
        RT: RT_FIELDS_PACKET,
        "transport_type": "UNICAST",
        "frame_size": frame_size,
        # Routed: the trace is between two workloads that may be on different
        # segments, and the L2 header is rewritten by the first hop anyway.
        "routed": True,
        "eth_header": {"src_mac": src_mac or PLACEHOLDER_MAC,
                       "dst_mac": dst_mac or PLACEHOLDER_MAC},
        "ip_header": {"src_ip": src_ip, "dst_ip": dst_ip,
                      "protocol": protocol, "ttl": 64},
    }
    if protocol in (6, 17):
        packet["transport_header"] = {"src_port": src_port,
                                      "dst_port": int(port or 0)}
    return {F_LPORT_ID: lport_id, F_PACKET: packet}


def run_traceflow(nsx, request, timeout=TRACE_DEFAULT_TIMEOUT,
                  poll_interval=TRACE_POLL_INTERVAL, sleep=time.sleep):
    """Create, poll and clean up one traceflow.

    Returns (traceflow_id, state, observations). The object is always deleted,
    including when the poll times out: a traceflow left behind is litter on
    somebody's manager.
    """
    created = nsx.post(PATH_TRACEFLOW, body=request)
    tid = created.get(F_ID)
    if not tid:
        raise NsxError("NSX accepted the traceflow but returned no id.")
    state = created.get(F_OPERATION_STATE, TF_IN_PROGRESS)
    observations = []
    try:
        deadline = time.monotonic() + float(timeout)
        while state not in TF_TERMINAL_STATES:
            if time.monotonic() >= deadline:
                break
            sleep(poll_interval)
            status = nsx.get(p_traceflow_one(tid))
            state = status.get(F_OPERATION_STATE, state)
        if state == TF_FINISHED:
            observations = nsx.get_all(p_traceflow_observations(tid))
    finally:
        try:
            nsx.delete(p_traceflow_one(tid))
        except NsxError as e:
            debug("traceflow {} could not be deleted: {}".format(tid, e))
    return tid, state, observations


class LiveVerdict:
    """What the data plane actually did with the packet."""

    __slots__ = ("state", "observations", "verdict_obs", "record", "acl_rule_id")

    def __init__(self, state, observations, verdict_obs=None, record=None,
                 acl_rule_id=None):
        self.state = state
        self.observations = list(observations)
        self.verdict_obs = verdict_obs
        self.record = record
        self.acl_rule_id = acl_rule_id

    @property
    def delivered(self):
        return bool(self.verdict_obs) and \
            self.verdict_obs.get(RT) in OBS_DELIVERED_TYPES

    @property
    def dropped(self):
        return bool(self.verdict_obs) and \
            self.verdict_obs.get(RT) in OBS_DROP_TYPES

    @property
    def conclusive(self):
        return self.delivered or self.dropped

    @property
    def action(self):
        if self.delivered:
            return "ALLOW"
        return "DROP" if self.dropped else None


def interpret_observations(state, observations, rules_by_id):
    """Turn the observation list into a verdict, naming the rule if it can.

    An acl_rule_id with no matching policy rule is reported as the raw number
    rather than silently dropped: an unmatched id usually means the rule lives
    outside the domain being swept, and hiding it would look like no rule was
    involved at all.
    """
    ordered = sorted(observations, key=lambda o: _int_or_zero(o.get(F_SEQUENCE_NO)))
    verdict_obs = None
    for obs in ordered:
        if obs.get(RT) in OBS_DROP_TYPES or obs.get(RT) in OBS_DELIVERED_TYPES:
            verdict_obs = obs
            break
    acl_id = None
    record = None
    if verdict_obs is not None and verdict_obs.get(F_ACL_RULE_ID) is not None:
        acl_id = _int_or_zero(verdict_obs.get(F_ACL_RULE_ID))
        record = rules_by_id.get(acl_id)
    return LiveVerdict(state, ordered, verdict_obs, record, acl_id)


def observation_line(obs):
    """One hop of the packet's path, for the console."""
    kind = str(obs.get(RT, "")).replace("TraceflowObservation", "") or "?"
    where = obs.get(F_TRANSPORT_NODE_NAME) or obs.get(F_COMPONENT_NAME) or ""
    component = obs.get(F_COMPONENT_TYPE) or ""
    reason = obs.get(F_REASON)
    tail = "  {}".format(reason) if reason else ""
    return "{:12s} {:14s} {}{}".format(kind, component, where, tail)


# === AGREEMENT ===
def verdicts_agree(static, live):
    """Whether the policy and the data plane told the same story.

    None when there is nothing to compare -- one of the two did not produce a
    verdict, which is not a disagreement.
    """
    if live is None or not live.conclusive or static.action is None:
        return None
    if static.action != live.action:
        return False
    if live.record is not None and static.record is not None:
        return live.record.path == static.record.path
    return True


def disagreement_reasons(static, live):
    """Why the two engines can legitimately differ, most likely first."""
    reasons = []
    if live is not None and live.record is None and live.acl_rule_id:
        reasons.append(
            "the data plane named rule id {} and no policy rule in this "
            "domain carries it -- the rule may live in another domain, or on "
            "a manager not in this inventory".format(live.acl_rule_id))
    reasons.append(
        "a rule edited in the policy but not yet realized onto the host "
        "still reads as authoritative here and has no effect there")
    reasons.append(
        "NAT rewrites addresses between the two ends, so the packet the "
        "firewall saw is not the one the policy was matched against")
    if not static.certain:
        reasons.append(
            "static evaluation could not decide {} earlier rule(s), any of "
            "which may be the real match".format(len(static.undecided)))
    return reasons


def endpoint_summary_rows(source, destination, proto, port):
    return [
        ["source", source.describe(), source.lport_id or "",
         str(len(source.groups))],
        ["destination", destination.describe(), destination.lport_id or "",
         str(len(destination.groups))],
        ["flow", "{}/{}".format(proto, port if port is not None else "any"),
         "", ""],
    ]
