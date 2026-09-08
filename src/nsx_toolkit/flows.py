"""Observed flows into a proposed ruleset.

The question every segmentation project actually gets stuck on is not "what
rules do I have" but "what rules do I *need*" -- and the only honest answer
comes from traffic that really happened.

**This reads a flow export you already have** rather than talking to NSX
Intelligence. That is a deliberate choice: the Intelligence recommendation API
is licensed separately, is not present on most estates, and I cannot verify
its shapes against a real appliance -- so building against it would mean
shipping a large feature tested only against my own assumptions. A flow export
is something every site can produce (NSX Intelligence export, vRNI, a
firewall-log query, even `nsxctl trace` output pasted together), and the
proposal it produces is a plain `nsxctl apply` change file you review before
anything is written.

What it will and will not claim:

  * It proposes ALLOW rules for traffic that was observed. It never proposes a
    default-deny, because "I saw no traffic on this port" is not evidence that
    none exists -- the same reasoning that makes a zero hit count insufficient
    to delete a rule.
  * A flow whose endpoints cannot be resolved to groups is reported, not
    silently dropped. An unresolved endpoint is the most important row in the
    file: it is the workload nobody has classified.
  * Ports are aggregated per source/destination pair, and a pair with more
    distinct ports than `--max-ports` is flagged rather than turned into a
    rule with fifty entries, because that is usually a scanner or a monitoring
    host and deserves a human.
"""

import csv
import ipaddress
import json
import os

from .api import F_DISPLAY_NAME, F_EXPRESSION, F_ID, F_IP_ADDRESSES
from .errors import ConfigError

# Column names accepted for each field, lowercased. Every flow exporter names
# these differently and none of them are wrong, so the reader accepts the
# common spellings instead of demanding one.
COLUMN_ALIASES = {
    "source": ("source", "src", "src_ip", "source_ip", "sourceaddress",
               "source_address", "src_addr"),
    "destination": ("destination", "dst", "dst_ip", "destination_ip",
                    "destinationaddress", "destination_address", "dst_addr"),
    "port": ("port", "dst_port", "destination_port", "dstport", "port_display",
             "service_port", "destinationport"),
    "protocol": ("protocol", "proto", "ip_protocol", "l4_protocol"),
    "action": ("action", "flow_action", "disposition"),
    "count": ("count", "flows", "sessions", "hits", "packets"),
}

DEFAULT_MAX_PORTS = 12
ALLOWED_ACTIONS = ("allow", "allowed", "accept", "accepted", "permit", "")


class Flow:
    """One observed conversation, already aggregated by the exporter."""

    __slots__ = ("source", "destination", "port", "protocol", "count", "line")

    def __init__(self, source, destination, port, protocol="tcp", count=1,
                 line=0):
        self.source = source
        self.destination = destination
        self.port = port
        self.protocol = (protocol or "tcp").lower()
        self.count = count
        self.line = line

    def key(self):
        return (self.source, self.destination, self.protocol)


def _pick(row, field):
    for alias in COLUMN_ALIASES[field]:
        for key in row:
            if key and key.strip().lower() == alias:
                value = row[key]
                if value not in (None, ""):
                    return str(value).strip()
    return ""


def _normalise_protocol(text):
    value = str(text or "tcp").strip().lower()
    if value in ("6", "tcp"):
        return "tcp"
    if value in ("17", "udp"):
        return "udp"
    if value in ("1", "icmp", "icmpv4"):
        return "icmp"
    return value or "tcp"


def read_flows(path, include_denied=False):
    """(flows, problems) from a CSV or JSON flow export.

    Rows that cannot be read are reported individually rather than failing the
    file, the same way bulk tagging handles a bad CSV line: one malformed row
    in a ten-thousand-row export should not cost you the other 9,999.
    """
    if not os.path.isfile(path):
        raise ConfigError("Not found: {}".format(path))
    with open(path, newline="", encoding="utf-8-sig") as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            try:
                rows = json.load(f)
            except ValueError as e:
                raise ConfigError(
                    "{} is not valid JSON: {}".format(path, e)) from e
            if not isinstance(rows, list):
                raise ConfigError("{}: expected a list of flows.".format(path))
        elif head == "{":
            raise ConfigError(
                "{}: expected a list of flows, not an object. Export the "
                "rows themselves.".format(path))
        else:
            rows = list(csv.DictReader(f))
    if not rows:
        raise ConfigError("No flows in {}.".format(path))

    flows, problems = [], []
    for index, row in enumerate(rows, 2):
        if not isinstance(row, dict):
            problems.append("line {}: not a record".format(index))
            continue
        source = _pick(row, "source")
        destination = _pick(row, "destination")
        if not source or not destination:
            problems.append(
                "line {}: needs a source and a destination address".format(
                    index))
            continue
        action = _pick(row, "action").lower()
        if action and action not in ALLOWED_ACTIONS and not include_denied:
            # A denied flow is not evidence the rule should exist -- it is
            # usually evidence the segmentation is working.
            continue
        port_text = _pick(row, "port")
        protocol = _normalise_protocol(_pick(row, "protocol"))
        port = None
        if port_text:
            try:
                port = int(str(port_text).split("/")[0])
            except ValueError:
                problems.append("line {}: port {!r} is not a number".format(
                    index, port_text))
                continue
        elif protocol != "icmp":
            problems.append("line {}: no destination port".format(index))
            continue
        try:
            count = int(float(_pick(row, "count") or 1))
        except ValueError:
            count = 1
        flows.append(Flow(source, destination, port, protocol, count, index))
    return flows, problems


# === ENDPOINT RESOLUTION ===
def build_address_index(groups):
    """{address or network: [group path]} from group criteria.

    Only literal addresses and CIDRs declared on a group are used. There is no
    reverse VM-IP lookup here on purpose: an address that resolves to nothing
    is reported as unclassified, which is a finding, whereas guessing at it
    would produce a rule for a workload nobody has actually placed.
    """
    index = {}
    for path, entry in groups.items():
        group = entry[1] if isinstance(entry, tuple) else entry
        for item in (group.get(F_EXPRESSION) or []):
            for raw in (item.get(F_IP_ADDRESSES) or []):
                index.setdefault(str(raw), []).append(path)
    return index


def resolve_address(address, index, vm_addresses=None):
    """Group paths an address belongs to, most specific first.

    Exact match, then containing CIDR, then a VM whose VIF carries the
    address. Anything else is unresolved and says so.
    """
    hits = list(index.get(address, []))
    if not hits:
        try:
            wanted = ipaddress.ip_address(address)
        except ValueError:
            wanted = None
        if wanted is not None:
            for raw, paths in index.items():
                if "/" not in str(raw):
                    continue
                try:
                    network = ipaddress.ip_network(str(raw), strict=False)
                except ValueError:
                    continue
                if wanted in network:
                    hits.extend(paths)
    if not hits and vm_addresses:
        hits.extend(vm_addresses.get(address, []))
    seen, ordered = set(), []
    for path in hits:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered


# === PROPOSAL ===
class Proposal:
    """One proposed rule, plus what it was derived from."""

    __slots__ = ("source_groups", "destination_groups", "protocol", "ports",
                 "flow_count", "source_address", "destination_address")

    def __init__(self, source_groups, destination_groups, protocol, ports,
                 flow_count, source_address="", destination_address=""):
        self.source_groups = list(source_groups)
        self.destination_groups = list(destination_groups)
        self.protocol = protocol
        self.ports = sorted(set(ports))
        self.flow_count = flow_count
        self.source_address = source_address
        self.destination_address = destination_address

    def rule_id(self, prefix="flow"):
        def short(paths):
            return (paths[0].rsplit("/", 1)[-1] if paths else "any")[:24]
        ports = "-".join(str(p) for p in self.ports[:3]) or self.protocol
        return "{}-{}-to-{}-{}".format(prefix, short(self.source_groups),
                                       short(self.destination_groups), ports)

    def row(self):
        return [", ".join(p.rsplit("/", 1)[-1] for p in self.source_groups),
                ", ".join(p.rsplit("/", 1)[-1]
                          for p in self.destination_groups),
                self.protocol,
                ",".join(str(p) for p in self.ports),
                str(self.flow_count)]


class Unresolved:
    """An observed endpoint no group claims. The most useful row in the file."""

    __slots__ = ("address", "side", "flow_count")

    def __init__(self, address, side, flow_count):
        self.address = address
        self.side = side
        self.flow_count = flow_count

    def row(self):
        return [self.address, self.side, str(self.flow_count)]


def propose_rules(flows, groups, max_ports=DEFAULT_MAX_PORTS,
                  vm_addresses=None):
    """(proposals, unresolved, wide) from observed flows.

    `wide` is pairs that talked on more than `max_ports` distinct ports --
    usually a scanner or a monitoring host, and turning that into one rule
    with fifty ports would bury the finding rather than surface it.
    """
    index = build_address_index(groups)
    pairs = {}
    unresolved = {}

    for flow in flows:
        sources = resolve_address(flow.source, index, vm_addresses)
        destinations = resolve_address(flow.destination, index, vm_addresses)
        if not sources:
            entry = unresolved.setdefault(("source", flow.source), 0)
            unresolved[("source", flow.source)] = entry + flow.count
        if not destinations:
            entry = unresolved.setdefault(("destination", flow.destination), 0)
            unresolved[("destination", flow.destination)] = entry + flow.count
        if not sources or not destinations:
            continue
        key = (tuple(sources), tuple(destinations), flow.protocol)
        bucket = pairs.setdefault(key, {"ports": set(), "count": 0,
                                        "src": flow.source,
                                        "dst": flow.destination})
        if flow.port is not None:
            bucket["ports"].add(flow.port)
        bucket["count"] += flow.count

    proposals, wide = [], []
    for (sources, destinations, protocol), bucket in sorted(
            pairs.items(), key=lambda kv: -kv[1]["count"]):
        proposal = Proposal(sources, destinations, protocol, bucket["ports"],
                            bucket["count"], bucket["src"], bucket["dst"])
        if len(proposal.ports) > max_ports:
            wide.append(proposal)
            continue
        proposals.append(proposal)

    unresolved_list = [Unresolved(address, side, count)
                       for (side, address), count in sorted(
                           unresolved.items(), key=lambda kv: -kv[1])]
    return proposals, unresolved_list, wide


def proposals_to_change_file(proposals, policy, action="ALLOW",
                             prefix="flow", services=None):
    """The proposal as an `nsxctl apply` document.

    Emitted as a change file rather than written directly, because a ruleset
    derived from observed traffic is a draft: it needs a person to read it,
    name the rules properly, and decide what the observation window missed.
    """
    rules = []
    for proposal in proposals:
        entry = {
            "id": proposal.rule_id(prefix),
            "policy": policy,
            "source": list(proposal.source_groups),
            "destination": list(proposal.destination_groups),
            "action": action,
            "description": "derived from {} observed flow(s) on {}/{}".format(
                proposal.flow_count, proposal.protocol,
                ",".join(str(p) for p in proposal.ports) or "any"),
        }
        if services:
            entry["services"] = list(services)
        rules.append(entry)
    return {"rules": rules}


def group_display_names(groups):
    return {path: (entry[1] if isinstance(entry, tuple) else entry).get(
        F_DISPLAY_NAME) or (entry[1] if isinstance(entry, tuple)
                            else entry).get(F_ID) or path
            for path, entry in groups.items()}
