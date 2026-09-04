"""NSX API contract.

Every path, query parameter and response field the toolkit depends on is
declared exactly once, here. A future NSX release that renames something
changes ONE constant, not every call site. Use --debug to see the concrete
requests this contract produces against your NSX version.
"""

import re

# --- Bases -----------------------------------------------------------------
API_BASE_LM = "/policy/api/v1/infra"
API_BASE_GM_CANDIDATES = [
    "/global-manager/api/v1/global-infra",
    "/policy/api/v1/global-infra",
]

# --- Policy paths (relative to a base) -------------------------------------
PATH_GROUPS = "/domains/{domain}/groups"
PATH_GROUP = "/domains/{domain}/groups/{gid}"
PATH_GROUP_MEMBERS = "/domains/{domain}/groups/{gid}/members/virtual-machines"
PATH_SEC_POLICIES = "/domains/{domain}/security-policies"
PATH_SEC_POLICY = "/domains/{domain}/security-policies/{pid}"
PATH_SEC_RULES = "/domains/{domain}/security-policies/{pid}/rules"
PATH_SEC_RULE = "/domains/{domain}/security-policies/{pid}/rules/{rid}"

# Service definitions, for turning a rule's service paths into the L4 ports it
# actually matches. NOT domain-scoped.
PATH_SERVICES = "/services"

# Rule hit counters. The per-POLICY form returns statistics for every rule in
# one call; the per-RULE form is the fallback for versions that do not serve
# it. Reaching for the per-rule form first would reintroduce the N+1 that the
# concurrent policy fetch removed.
PATH_POLICY_STATS = "/domains/{domain}/security-policies/{pid}/statistics"
PATH_RULE_STATS = (
    "/domains/{domain}/security-policies/{pid}/rules/{rid}/statistics")
PATH_DOMAINS = "/domains"

# Reverse lookup: groups a VM belongs to, regardless of the group's member
# type (VirtualMachine, VIF, IPAddress, Segment, SegmentPort, ...). This is
# the same index NSX's own group-search UI uses. NOT domain-scoped -- it
# hangs directly off {base}, not {base}/domains/{domain}/...
PATH_VM_GROUP_ASSOC = "/virtual-machine-group-associations"

# --- Manager (non-policy) paths, absolute ----------------------------------
# These hang off the manager root, NOT off a policy base. Traceflow in
# particular exists only on a Local Manager: the Global Manager serves no
# /api/v1/traceflow at all, which is why `nsxctl trace` has to resolve the LM
# that actually hosts the source VM and target that manager specifically.
PATH_FABRIC_VMS = "/api/v1/fabric/virtual-machines"
PATH_FABRIC_VIFS = "/api/v1/fabric/vifs"
PATH_LOGICAL_PORTS = "/api/v1/logical-ports"
PATH_TRACEFLOW = "/api/v1/traceflow"
PATH_TRACEFLOW_ONE = "/api/v1/traceflow/{tid}"
PATH_TRACEFLOW_OBSERVATIONS = "/api/v1/traceflow/{tid}/observations"
PATH_SESSION_CREATE = "/api/session/create"
PATH_NODE_VERSION = "/api/v1/node/version"

# --- Query parameters ------------------------------------------------------
PARAM_CURSOR = "cursor"
PARAM_PAGE_SIZE = "page_size"
PARAM_DISPLAY_NAME = "display_name"
PARAM_ACTION = "action"
PARAM_VM_EXTERNAL_ID = "vm_external_id"
PARAM_OWNER_VM_ID = "owner_vm_id"
PARAM_ATTACHMENT_ID = "attachment_id"
ACTION_UPDATE_TAGS = "update_tags"
PAGE_SIZE = 1000

# --- Response fields -------------------------------------------------------
F_RESULTS, F_CURSOR, F_RESULT_COUNT = "results", "cursor", "result_count"
F_ID, F_DISPLAY_NAME, F_PATH = "id", "display_name", "path"
F_DESCRIPTION, F_EXPRESSION = "description", "expression"
F_TAGS, F_TAG_SCOPE, F_TAG_VALUE = "tags", "scope", "tag"
F_EXTERNAL_ID, F_POWER_STATE = "external_id", "power_state"
F_SOURCE_GROUPS, F_DEST_GROUPS = "source_groups", "destination_groups"
F_SCOPE, F_ACTION_FIELD = "scope", "action"
F_SEQUENCE_NUMBER, F_CATEGORY = "sequence_number", "category"
F_RULES = "rules"
F_SERVICES, F_PROFILES = "services", "profiles"
F_DISABLED, F_LOGGED = "disabled", "logged"
F_DIRECTION, F_IP_PROTOCOL = "direction", "ip_protocol"
F_REVISION = "_revision"

# The realized numeric DFW id NSX assigns a policy rule. This is the join
# between the two halves of `nsxctl trace`: a traceflow observation names the
# rule that dropped the packet as `acl_rule_id`, an integer with no name
# attached, and this is the field on the policy rule that carries the same
# integer back.
F_RULE_ID = "rule_id"

# Service definitions. Only L4PortSetServiceEntry can be reduced to a port
# match; everything else (ICMP, ALG, IP-protocol, nested) is left undecidable
# rather than guessed at -- see trace.py.
F_SERVICE_ENTRIES = "service_entries"
F_L4_PROTOCOL = "l4_protocol"
F_DESTINATION_PORTS = "destination_ports"
RT_L4_PORTSET = "L4PortSetServiceEntry"

# --- VIF, logical port and traceflow fields --------------------------------
F_LPORT_ATTACHMENT_ID = "lport_attachment_id"
F_ATTACHMENT_ID = "attachment_id"
F_ATTACHMENT = "attachment"
F_MAC_ADDRESS = "mac_address"
F_IP_ADDRESS_INFO = "ip_address_info"
F_DEVICE_KEY = "device_key"
F_DEVICE_NAME = "device_name"
F_OWNER_VM_ID = "owner_vm_id"
F_OPERATION_STATE = "operation_state"
F_ACL_RULE_ID = "acl_rule_id"
F_COMPONENT_TYPE = "component_type"
F_COMPONENT_NAME = "component_name"
F_COMPONENT_SUB_TYPE = "component_sub_type"
F_TRANSPORT_NODE_NAME = "transport_node_name"
F_SEQUENCE_NO = "sequence_no"
F_REASON = "reason"
F_LPORT_ID = "lport_id"
F_PACKET = "packet"

# Traceflow round-trip states. A traceflow object is created, polled, and then
# deleted -- it is a real object on the manager, not a query.
TF_IN_PROGRESS, TF_FINISHED = "IN_PROGRESS", "FINISHED"
TF_FAILED, TF_TIMEOUT = "FAILED", "TIMEOUT"
TF_TERMINAL_STATES = (TF_FINISHED, TF_FAILED, TF_TIMEOUT)

# Observation resource types. Only Delivered and Dropped are verdicts; the
# rest are the path the packet took to get there.
OBS_DELIVERED = "TraceflowObservationDelivered"
OBS_DROPPED = "TraceflowObservationDropped"
OBS_DROPPED_LOGICAL = "TraceflowObservationDroppedLogical"
OBS_FORWARDED = "TraceflowObservationForwarded"
OBS_FORWARDED_LOGICAL = "TraceflowObservationForwardedLogical"
OBS_RECEIVED = "TraceflowObservationReceived"
OBS_RECEIVED_LOGICAL = "TraceflowObservationReceivedLogical"
OBS_DROP_TYPES = (OBS_DROPPED, OBS_DROPPED_LOGICAL)
OBS_DELIVERED_TYPES = (OBS_DELIVERED,)

RT_FIELDS_PACKET = "FieldsPacketData"

# IANA protocol numbers for the packet the traceflow injects.
IP_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}

# Statistics. NSX nests them as results[].statistics[], each entry carrying a
# rule_path -- the parser tolerates a flat shape too, because this is the part
# of the contract that varies most between versions.
F_STATISTICS = "statistics"
F_HIT_COUNT, F_BYTE_COUNT, F_PACKET_COUNT = (
    "hit_count", "byte_count", "packet_count")
F_LAST_UPDATE = "last_update_timestamp"
F_RULE_PATH = "rule_path"
F_TARGET_ID = "target_id"
F_TARGET_DISPLAY_NAME = "target_display_name"
F_TARGET_TYPE = "target_type"
F_IS_VALID = "is_valid"
F_NODE_VERSION = "node_version"
F_PRODUCT_VERSION = "product_version"

# --- Expression / criteria types -------------------------------------------
RT = "resource_type"
RT_CONDITION, RT_CONJUNCTION = "Condition", "ConjunctionOperator"
RT_NESTED, RT_IPADDRESS = "NestedExpression", "IPAddressExpression"
RT_PATHEXPR, RT_EXTERNALID = "PathExpression", "ExternalIDExpression"
F_CONJ_OP, F_KEY, F_OPERATOR, F_VALUE = (
    "conjunction_operator", "key", "operator", "value")
F_MEMBER_TYPE, F_EXPRESSIONS = "member_type", "expressions"
F_IP_ADDRESSES, F_PATHS, F_EXTERNAL_IDS = "ip_addresses", "paths", "external_ids"
KEY_TAG, TAG_SCOPE_SEPARATOR = "Tag", "|"

# NSX's wildcard in source_groups / destination_groups / scope. A rule whose
# source and destination are both ANY matches everything.
ANY = "ANY"

# DFW evaluation order across policies. NSX evaluates every rule in an earlier
# category before any rule in a later one, regardless of sequence numbers, so a
# per-policy ordering (which is all rule hygiene needs) is not enough to answer
# "which rule decides this packet". Anything unrecognised sorts last but keeps
# its relative order.
CATEGORY_ORDER = ("Ethernet", "Emergency", "Infrastructure", "Environment",
                  "Application")

# --- Roles and domains -----------------------------------------------------
DEFAULT_DOMAIN = "default"
ROLE_GM, ROLE_LM = "gm", "lm"
ROLE_LABEL = {ROLE_GM: "Global Manager", ROLE_LM: "Local Manager"}

# NSX marks where an object was authored via its path: GM-authored objects
# keep a '/global-infra/...' path even when read back from an LM they've been
# realized onto; LM-native objects use '/infra/...'. This is how we tell "this
# LM rule is actually a GM rule realized locally" apart from a genuinely
# LM-native rule -- used to dedupe GM rules across many LMs.
_GLOBAL_INFRA_PREFIX = "/global-infra/"


def origin_of_path(path):
    if not path:
        return "LM"
    return "GM" if path.startswith(_GLOBAL_INFRA_PREFIX) else "LM"


# --- Path builders ---------------------------------------------------------
def p_groups(base, domain):
    return base + PATH_GROUPS.format(domain=domain)


def p_group(base, domain, gid):
    return base + PATH_GROUP.format(domain=domain, gid=gid)


def p_group_members(base, domain, gid):
    return base + PATH_GROUP_MEMBERS.format(domain=domain, gid=gid)


def p_sec_policies(base, domain):
    return base + PATH_SEC_POLICIES.format(domain=domain)


def p_sec_policy(base, domain, pid):
    return base + PATH_SEC_POLICY.format(domain=domain, pid=pid)


def p_sec_rules(base, domain, pid):
    return base + PATH_SEC_RULES.format(domain=domain, pid=pid)


def p_sec_rule(base, domain, pid, rid):
    return base + PATH_SEC_RULE.format(domain=domain, pid=pid, rid=rid)


def p_services(base):
    return base + PATH_SERVICES


def p_traceflow_one(tid):
    """Absolute: traceflow is a Manager API, not a Policy one."""
    return PATH_TRACEFLOW_ONE.format(tid=tid)


def p_traceflow_observations(tid):
    return PATH_TRACEFLOW_OBSERVATIONS.format(tid=tid)


def p_vm_group_assoc(base):
    return base + PATH_VM_GROUP_ASSOC


def p_policy_stats(base, domain, pid):
    return base + PATH_POLICY_STATS.format(domain=domain, pid=pid)


def p_rule_stats(base, domain, pid, rid):
    return base + PATH_RULE_STATS.format(domain=domain, pid=pid, rid=rid)


def p_domains(base):
    return base + PATH_DOMAINS


def group_id_from_path(path):
    """Last path segment of a group path, which is its id."""
    return path.rsplit("/", 1)[-1] if "/" in str(path) else str(path)


def policy_path_prefix(base):
    """The policy-path prefix an object read from this base will carry.

    An object's API URL and its NSX `path` are not the same string: the URL
    is '/policy/api/v1/infra/domains/...' while the path NSX stores, and that
    rules reference, is '/infra/domains/...'. Every declared base has the
    shape '<something>/api/v1<prefix>', so the prefix is what follows the
    version segment. Needed to predict the path of an object that does not
    exist yet -- a rule in a change file may reference a group the same file
    creates.
    """
    _, _, tail = str(base or "").partition("/api/v1")
    return tail or API_BASE_LM


def policy_id_from_rule_path(path):
    """The policy id out of .../security-policies/<pid>/rules/<rid>."""
    parts = str(path or "").split("/security-policies/", 1)
    return parts[1].split("/")[0] if len(parts) > 1 else ""


def category_rank(category):
    """Where a policy's category sits in DFW evaluation order."""
    try:
        return CATEGORY_ORDER.index(category)
    except ValueError:
        return len(CATEGORY_ORDER)


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)")


def parse_version(text):
    """('4.1.2.0') -> (4, 1). Returns None when unparseable -- callers treat
    that as 'assume the conservative path'."""
    m = _VERSION_RE.match(str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None
