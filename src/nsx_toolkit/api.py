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
PATH_GROUP_MEMBERS = "/domains/{domain}/groups/{gid}/members/virtual-machines"
PATH_SEC_POLICIES = "/domains/{domain}/security-policies"
PATH_SEC_RULES = "/domains/{domain}/security-policies/{pid}/rules"

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
PATH_FABRIC_VMS = "/api/v1/fabric/virtual-machines"
PATH_SESSION_CREATE = "/api/session/create"
PATH_NODE_VERSION = "/api/v1/node/version"

# --- Query parameters ------------------------------------------------------
PARAM_CURSOR = "cursor"
PARAM_PAGE_SIZE = "page_size"
PARAM_DISPLAY_NAME = "display_name"
PARAM_ACTION = "action"
PARAM_VM_EXTERNAL_ID = "vm_external_id"
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


def p_group_members(base, domain, gid):
    return base + PATH_GROUP_MEMBERS.format(domain=domain, gid=gid)


def p_sec_policies(base, domain):
    return base + PATH_SEC_POLICIES.format(domain=domain)


def p_sec_rules(base, domain, pid):
    return base + PATH_SEC_RULES.format(domain=domain, pid=pid)


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


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)")


def parse_version(text):
    """('4.1.2.0') -> (4, 1). Returns None when unparseable -- callers treat
    that as 'assume the conservative path'."""
    m = _VERSION_RE.match(str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None
