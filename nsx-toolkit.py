#!/usr/bin/env python3
"""
nsx-toolkit.py -- NSX Zero Trust Segmentation Toolkit

GENERATED FILE -- do not edit directly.
Built from src/nsx_toolkit/ by tools/build_single_file.py.
Edit the package and rebuild; CI fails if this file is out of date.

Single file, no install required. Works with the 'requests' library when it is
present and falls back to the Python standard library when it is not.

    python3 nsx-toolkit.py              guided setup, then interactive menu
    python3 nsx-toolkit.py --help       every non-interactive flag
    python3 nsx-toolkit.py --dashboard  taxonomy compliance posture

DESIGN NOTES
  - API CONTRACT: every path, parameter and field is declared once, in the
    API CONTRACT section. A future NSX release changes ONE constant.
  - Credentials resolve before anything else runs, and are never printed.
  - Scope follows the action: tag ops = LMs only; group/rule ops = GM + LMs.
  - Writes are audit-logged with before/after state, and are undoable.
  - Console listings truncate for readability; exports never do.
"""


from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import base64
import csv
import datetime
import getpass
import hashlib
import html
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.sax.saxutils as saxutils


# ==========================================================================
# version.py  --  Tool identity. Single source of truth for name and version strings.
# ==========================================================================

VERSION = "4.0.0"
VERSION_DATE = "2026-09-03"
TOOL_NAME = "NSX Toolkit"
TOOL_TAGLINE = "Zero Trust Segmentation · Groups, Tags & DFW"


# ==========================================================================
# errors.py  --  Exception types shared across the toolkit.
# ==========================================================================

class NsxError(Exception):
    """Any failure talking to (or interpreting a response from) NSX."""


class NsxHttpError(NsxError):
    """An NSX response with a status code worth acting on.

    A subclass rather than a new type so every existing `except NsxError`
    keeps catching it. The status matters in exactly one place today:
    NSX answers 412 when a write carries a stale `_revision`, which is
    "somebody else changed this object since you read it" -- a different
    outcome from a request that was merely malformed.
    """

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class UserAbort(Exception):
    """The operator backed out of a prompt ('b', Ctrl-C, or EOF)."""


class ConfigError(Exception):
    """Inventory, taxonomy, or credential configuration is unusable."""


# ==========================================================================
# paths.py  --  Filesystem locations and time helpers.
# ==========================================================================

def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z")


def utc_now_stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def local_stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


DATA_DIR = os.path.join(os.path.expanduser("~"), ".nsx_toolkit")
DEFAULT_INVENTORY_NAME = "inventory.json"
DEFAULT_TAXONOMY_NAMES = ("taxonomy.yaml", "taxonomy.yml", "taxonomy.json")
DEFAULT_CREDS_FILE = os.path.join(DATA_DIR, "credentials.env")
DEFAULT_AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")

# Audit log rotates at this size so it never grows without bound.
AUDIT_MAX_BYTES = 5 * 1024 * 1024
AUDIT_KEEP = 3


def _default_export_base():
    """Windows -> Documents\\nsxtoolkit ; Linux/Mac -> ~/nsxtoolkit"""
    home = os.path.expanduser("~")
    if os.name == "nt":
        docs = os.path.join(home, "Documents")
        base = docs if os.path.isdir(docs) else home
        return os.path.join(base, "nsxtoolkit")
    return os.path.join(home, "nsxtoolkit")


DEFAULT_EXPORT_DIR = os.path.join(_default_export_base(), "exports")
DEFAULT_TICKET_DIR = os.path.join(_default_export_base(), "change_plans")
DEFAULT_SNAPSHOT_DIR = os.path.join(_default_export_base(), "snapshots")


def config_search_dirs():
    """Where we look for inventory.json / taxonomy.yaml, in priority order.

    Current directory first so a per-project inventory wins, then the
    per-user data dir so a personal default always exists.
    """
    return [os.getcwd(), DATA_DIR]


# ==========================================================================
# output.py  --  Console output: color, tables, spinners, prompts, and run-mode state.
# ==========================================================================

W = 76
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


# === RUN MODE ===
def _enable_ansi_windows():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_ulong()
        k.GetConsoleMode(h, ctypes.byref(m))
        k.SetConsoleMode(h, m.value | 0x0004)
        return True
    except Exception:
        return False


_color_enabled = (sys.stdout.isatty() and "NO_COLOR" not in os.environ
                  and _enable_ansi_windows())
_json_mode = False
_interactive = sys.stdin.isatty()
_assume_yes = False
_debug = False

# When buffering, say() collects instead of printing, so a caller that later
# discovers the run found nothing new can drop the whole report before it
# reaches stdout. That is what makes a nightly cron job silent on a quiet
# night -- and errors are deliberately never buffered.
_buffer = None


def set_color(enabled):
    global _color_enabled
    _color_enabled = bool(enabled)


def set_json_mode(enabled):
    """JSON mode implies no color and no prompting: stdout must stay parseable."""
    global _json_mode, _color_enabled, _interactive
    _json_mode = bool(enabled)
    if _json_mode:
        _color_enabled = False
        _interactive = False


def is_json_mode():
    return _json_mode


def set_interactive(enabled):
    global _interactive
    _interactive = bool(enabled)


def is_interactive():
    return _interactive


def set_assume_yes(enabled):
    global _assume_yes
    _assume_yes = bool(enabled)


def assume_yes():
    return _assume_yes


def set_debug(enabled):
    global _debug
    _debug = bool(enabled)


def is_debug():
    return _debug


def start_buffering():
    """Collect console output instead of printing it."""
    global _buffer
    _buffer = []


def is_buffering():
    return _buffer is not None


def flush_buffered():
    """Print everything collected, and stop buffering."""
    global _buffer
    lines, _buffer = _buffer, None
    for line in (lines or []):
        print(line, flush=True)
    return len(lines or [])


def drop_buffered():
    """Discard everything collected, and stop buffering."""
    global _buffer
    dropped, _buffer = _buffer, None
    return len(dropped or [])


# === COLOR ===
def _c(code, text):
    return "\033[{}m{}\033[0m".format(code, text) if _color_enabled else str(text)


def cG(t):
    return _c("32", t)


def cR(t):
    return _c("31", t)


def cY(t):
    return _c("33", t)


def cC(t):
    return _c("36", t)


def cB(t):
    return _c("1", t)


def cD(t):
    return _c("2", t)


def cBG(t):
    return _c("1;32", t)


def cBR(t):
    return _c("1;31", t)


def cBY(t):
    return _c("1;33", t)


def cBC(t):
    return _c("1;36", t)


def strip_ansi(text):
    return _ANSI_RE.sub("", str(text))


# === MESSAGES ===
def say(msg=""):
    if _json_mode:
        return
    if _buffer is not None:
        _buffer.append(msg)
        return
    print(msg, flush=True)


def err(msg):
    print("  {} {}".format(cBR("[ERROR]"), msg), file=sys.stderr, flush=True)


def warn(msg):
    if not _json_mode:
        print("  {}  {}".format(cBY("[WARN]"), msg), flush=True)


def ok_msg(msg):
    if not _json_mode:
        print("  {}    {}".format(cBG("[OK]"), msg), flush=True)


def debug(msg):
    """Diagnostic trace. Goes to stderr so it never pollutes --json stdout."""
    if _debug:
        print("  {} {}".format(cD("[debug]"), msg), file=sys.stderr, flush=True)


def hr(char="-"):
    say(cD(char * W))


def section(title):
    say("\n{}\n  {}\n{}".format(cBC("=" * W), cB(title), cBC("=" * W)))


def progress_bar(cur, total, width=25):
    if total == 0:
        return "[" + " " * width + "]   0%"
    filled = int(width * cur / total)
    bar = "=" * filled + " " * (width - filled)
    pct = int(100 * cur / total)
    fn = cBG if pct >= 80 else (cBY if pct >= 50 else cBR)
    return "[{}] {}".format(fn(bar), fn("{:3d}%".format(pct)))


def table(headers, rows, indent=2):
    if not rows:
        say(" " * indent + cD("(no data)"))
        return
    widths = [len(h) for h in headers]
    sr = []
    for row in rows:
        cells = [str(c) for c in row]
        while len(cells) < len(headers):
            cells.append("")
        sr.append(cells)
        for i, c in enumerate(cells):
            if i < len(widths):
                widths[i] = max(widths[i], len(strip_ansi(c)))
    pad = " " * indent
    say(pad + "  ".join(cB(h.ljust(widths[i])) for i, h in enumerate(headers)))
    say(pad + "  ".join(cD("-" * widths[i]) for i in range(len(headers))))
    for cells in sr:
        parts = []
        for i, c in enumerate(cells):
            cl = len(strip_ansi(c))
            parts.append(c.ljust(widths[i] + len(c) - cl))
        say(pad + "  ".join(parts))


def more_note(shown, total, where="full set in export"):
    """Console truncation notice. Truncation is display-only -- exports and
    JSON always carry every row."""
    if total > shown:
        say("    {}".format(cD("... +{} more ({})".format(total - shown, where))))


class Spinner:
    FRAMES = ["|", "/", "-", "\\"]

    def __init__(self, label="Working"):
        self._label = label
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if _json_mode or not sys.stdout.isatty():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=2)
            sys.stdout.write("\r" + " " * (len(self._label) + 12) + "\r")
            sys.stdout.flush()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            sys.stdout.write("\r  {} {} ...".format(cC(self.FRAMES[i % 4]), self._label))
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.15)


def parallel_run(items, fn, label="Querying", max_workers=8, key=None):
    """Run fn over items concurrently. Returns {key(item): result_or_Exception}.

    Exceptions are captured per item rather than raised, so one unreachable
    manager never aborts a sweep across the rest.
    """
    results = {}
    n = len(items)
    if n == 0:
        return results
    if key is None:
        def key(x):
            return getattr(x, "name", x)
    with ThreadPoolExecutor(max_workers=min(n, max_workers)) as pool:
        futures = {pool.submit(fn, it): it for it in items}
        done = 0
        for future in as_completed(futures):
            done += 1
            it = futures[future]
            if not _json_mode and sys.stdout.isatty():
                counter = cC("[{}/{}]".format(done, n))
                sys.stdout.write("\r  {} {} ...".format(counter, label))
                sys.stdout.flush()
            try:
                results[key(it)] = future.result()
            except Exception as e:
                results[key(it)] = e
    if not _json_mode and sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
    return results


# === PROMPTS ===
def ask(prompt, default=None, allow_back=True):
    """Prompt for input. In non-interactive mode the default is returned
    rather than blocking on a stdin that will never deliver."""
    if not _interactive:
        if default is not None:
            return default
        raise UserAbort()
    try:
        val = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise UserAbort() from None
    if allow_back and val.lower() == "b":
        raise UserAbort()
    return val if val else (default if default is not None else val)


def confirm(prompt):
    """Yes/no gate. --yes auto-confirms; non-interactive without --yes is a
    refusal, never an assumed yes."""
    if _assume_yes:
        say("{}{}".format(prompt, cG("yes (--yes)")))
        return True
    if not _interactive:
        return False
    return ask(prompt, default="n", allow_back=False).lower() in ("y", "yes")


# ==========================================================================
# api.py  --  NSX API contract.
# ==========================================================================

# --- Bases -----------------------------------------------------------------
API_BASE_LM = "/policy/api/v1/infra"
API_BASE_GM_CANDIDATES = [
    "/global-manager/api/v1/global-infra",
    "/policy/api/v1/global-infra",
]

# NSX Projects (multi-tenancy). A project has its own infra tree, so every
# policy path the toolkit builds hangs off a different base -- which is why
# scoping is a base swap here rather than a filter at each call site. Objects
# in the default infra are simply not visible from inside a project, and vice
# versa, so `--project` genuinely changes what the tool can see.
DEFAULT_ORG = "default"
API_BASE_PROJECT = "/policy/api/v1/orgs/{org}/projects/{project}/infra"
PATH_PROJECTS = "/policy/api/v1/orgs/{org}/projects"

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


def project_base(project, org=DEFAULT_ORG):
    return API_BASE_PROJECT.format(org=org, project=project)


def p_projects(org=DEFAULT_ORG):
    return PATH_PROJECTS.format(org=org)


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


# ==========================================================================
# taxonomy.py  --  Tag taxonomy -- loaded from configuration, not baked into source.
# ==========================================================================

# The scheme the toolkit shipped with before taxonomy was configurable. Used
# when no taxonomy file exists, so behaviour is unchanged out of the box.
DEFAULT_TAXONOMY = {
    "format": r"^[a-z0-9][a-z0-9\-]*$",
    "allow_unknown_scopes": False,
    "scopes": {
        "tenant": {"required": True},
        "app": {"required": True},
        "env": {"required": True,
                "values": ["prod", "uat", "dev", "staging", "dr"]},
        "tier": {"required": True,
                 "values": ["web", "app", "db", "mgmt", "dmz"]},
        "site": {"required": True},
        "server": {"required": True},
        "owner": {"required": False},
        "criticality": {"required": False,
                        "values": ["critical", "high", "medium", "low"]},
        "data-class": {"required": False},
        "managed-by": {"required": False},
    },
}


class Taxonomy:
    def __init__(self, spec=None, source="built-in default"):
        spec = spec or DEFAULT_TAXONOMY
        self.source = source
        scopes = spec.get("scopes") or {}
        if not isinstance(scopes, dict):
            raise ConfigError("taxonomy 'scopes' must be an object")
        self.allow_unknown_scopes = bool(spec.get("allow_unknown_scopes", False))
        try:
            self.format_re = re.compile(
                spec.get("format") or DEFAULT_TAXONOMY["format"])
        except re.error as e:
            raise ConfigError(
                "taxonomy 'format' is not a valid regex: {}".format(e)) from e
        self.mandatory = []
        self.conditional = []
        self.values = {}
        for name, cfg in scopes.items():
            cfg = cfg or {}
            if cfg.get("required"):
                self.mandatory.append(name)
            else:
                self.conditional.append(name)
            vals = cfg.get("values")
            self.values[name] = list(vals) if vals else None

    @property
    def all_scopes(self):
        return self.mandatory + self.conditional

    def values_for(self, scope):
        return self.values.get(scope)

    def validate_tag(self, scope, value):
        """Warnings for a single scope=value pair. Empty list means clean."""
        w = []
        if scope and not self.format_re.match(scope):
            w.append("scope '{}' bad format".format(scope))
        if value and not self.format_re.match(value):
            w.append("tag '{}' bad format".format(value))
        if scope and scope not in self.values and not self.allow_unknown_scopes:
            w.append("scope '{}' not in taxonomy".format(scope))
        allowed = self.values.get(scope)
        if allowed is not None and value and value not in allowed:
            w.append("'{}' not allowed for '{}' ({})".format(
                value, scope, ", ".join(allowed)))
        return w

    def validate_vm_tags(self, pairs):
        """(is_clean, issues) for a VM's full tag set."""
        issues = []
        scopes = {s for s, _ in pairs if s}
        for req in self.mandatory:
            if req not in scopes:
                issues.append("mandatory scope '{}' missing".format(req))
        for s, t in pairs:
            issues.extend(self.validate_tag(s, t))
        return (not issues), issues


def _load_mapping(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ConfigError(
                "{} is YAML but PyYAML is not installed. Convert it to JSON "
                "(taxonomy.json) or run: pip install pyyaml".format(path)) from None
        try:
            return yaml.safe_load(text) or {}
        except Exception as e:
            raise ConfigError("Invalid YAML in {}: {}".format(path, e)) from e
    try:
        return json.loads(text)
    except ValueError as e:
        raise ConfigError("Invalid JSON in {}: {}".format(path, e)) from e


def load_taxonomy(explicit_path=None, search_dirs=(), names=()):
    """Resolve a taxonomy file, falling back to the built-in default.

    Returns a Taxonomy. An explicitly requested path that does not exist is an
    error; an absent default file simply means 'use the built-in scheme'.
    """
    if explicit_path:
        if not os.path.isfile(explicit_path):
            raise ConfigError("Taxonomy file not found: {}".format(explicit_path))
        return Taxonomy(_load_mapping(explicit_path), source=explicit_path)
    for d in search_dirs:
        for name in names:
            cand = os.path.join(d, name)
            if os.path.isfile(cand):
                return Taxonomy(_load_mapping(cand), source=cand)
    return Taxonomy()


# ==========================================================================
# config.py  --  Inventory loading and validation.
# ==========================================================================

VALID_AUTH_MODES = ("session", "basic", "token", "cert")

PROFILES_KEY = "profiles"
DEFAULT_PROFILE_KEY = "default_profile"
PROFILE_ENV = "NSX_PROFILE"

# The name reported for a flat, single-estate inventory, so output that says
# "which estate am I talking to" has something to print either way.
IMPLICIT_PROFILE = "(default)"


def inventory_candidates(explicit_path=None, search_dirs=()):
    if explicit_path:
        return [explicit_path]
    return [os.path.join(d, DEFAULT_INVENTORY_NAME) for d in search_dirs]


def find_inventory(explicit_path=None, search_dirs=()):
    """First existing candidate path, or None. Never raises."""
    for c in inventory_candidates(explicit_path, search_dirs):
        if c and os.path.isfile(c):
            return c
    return None


def validate_manager(entry, index):
    """Normalize one manager entry in place and return a list of problems."""
    problems = []
    where = entry.get("name") or "manager[{}]".format(index)
    if not entry.get("name"):
        problems.append("{}: missing 'name'".format(where))
    if not entry.get("host"):
        problems.append("{}: missing 'host'".format(where))
    role = (entry.get("role") or "").lower()
    if role not in (ROLE_GM, ROLE_LM):
        problems.append(
            "{}: 'role' must be '{}' or '{}' (got {!r})".format(
                where, ROLE_GM, ROLE_LM, entry.get("role")))
    entry["role"] = role
    auth = (entry.get("auth") or "session").lower()
    if auth not in VALID_AUTH_MODES:
        problems.append("{}: 'auth' must be one of {} (got {!r})".format(
            where, ", ".join(VALID_AUTH_MODES), entry.get("auth")))
    entry["auth"] = auth
    try:
        entry["port"] = int(entry.get("port", 443))
    except (TypeError, ValueError):
        problems.append("{}: 'port' must be a number".format(where))
    return problems


def _read_inventory_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise ConfigError("Invalid JSON in {}: {}".format(path, e)) from e
    except OSError as e:
        raise ConfigError("Cannot read {}: {}".format(path, e)) from e
    if not isinstance(data, dict):
        raise ConfigError("{}: top level must be an object".format(path))
    return data


def list_profiles(path):
    """Profile names in an inventory, newest-format first.

    A flat inventory has none, and says so with an empty list rather than
    inventing one -- callers distinguish "no profiles" from "profile absent".
    """
    data = _read_inventory_file(path)
    profiles = data.get(PROFILES_KEY)
    if not isinstance(profiles, dict):
        return []
    return sorted(profiles)


def resolve_profile(path, requested=None):
    """Which profile a run should use, and why.

    Precedence: --profile, then $NSX_PROFILE, then the file's
    default_profile, then the only profile if there is exactly one. A file
    with several profiles and no default refuses rather than picking, because
    guessing which estate to talk to is the one wrong answer that matters.
    """
    data = _read_inventory_file(path)
    profiles = data.get(PROFILES_KEY)
    if not isinstance(profiles, dict) or not profiles:
        if requested:
            raise ConfigError(
                "{} has no profiles, so --profile {} means nothing. It is a "
                "single-estate inventory.".format(path, requested))
        return None, "single estate"
    wanted = requested or os.environ.get(PROFILE_ENV) or data.get(
        DEFAULT_PROFILE_KEY)
    if not wanted:
        if len(profiles) == 1:
            only = next(iter(profiles))
            return only, "the only profile"
        raise ConfigError(
            "{} defines {} profiles ({}) and no '{}'. Choose one with "
            "--profile, or set {}.".format(
                path, len(profiles), ", ".join(sorted(profiles)),
                DEFAULT_PROFILE_KEY, PROFILE_ENV))
    if wanted not in profiles:
        raise ConfigError(
            "No profile '{}' in {}. Known: {}".format(
                wanted, path, ", ".join(sorted(profiles))))
    source = ("--profile" if requested
              else (PROFILE_ENV if os.environ.get(PROFILE_ENV)
                    else DEFAULT_PROFILE_KEY))
    return wanted, source


def load_inventory(path, profile=None):
    """Read and validate an inventory file. Raises ConfigError on any problem.

    `profile` selects one estate out of a multi-profile file. It is resolved
    by the caller so the chosen name can be reported; passing it again here
    is what actually narrows the managers.
    """
    data = _read_inventory_file(path)
    profiles = data.get(PROFILES_KEY)
    where = path
    if isinstance(profiles, dict) and profiles:
        name = profile
        if name is None:
            name, _why = resolve_profile(path)
        section = profiles.get(name)
        if not isinstance(section, dict):
            raise ConfigError(
                "No profile '{}' in {}. Known: {}".format(
                    name, path, ", ".join(sorted(profiles))))
        managers = section.get("managers")
        where = "{} [profile {}]".format(path, name)
    else:
        if profile:
            raise ConfigError(
                "{} has no profiles, so --profile {} means nothing.".format(
                    path, profile))
        managers = data.get("managers")
    if not managers:
        raise ConfigError("{} has no 'managers'.".format(where))
    if not isinstance(managers, list):
        raise ConfigError("{}: 'managers' must be a list".format(where))
    problems = []
    seen = set()
    for i, entry in enumerate(managers):
        if not isinstance(entry, dict):
            problems.append("manager[{}] is not an object".format(i))
            continue
        problems.extend(validate_manager(entry, i))
        name = entry.get("name")
        if name and name in seen:
            problems.append("duplicate manager name {!r}".format(name))
        seen.add(name)
    if problems:
        raise ConfigError("{}:\n      - {}".format(where,
                                                   "\n      - ".join(problems)))
    return managers


def default_env_names(name):
    """Credential env-var names derived from a manager name, so the wizard
    never has to ask the operator to invent them."""
    slug = "".join(ch.upper() if ch.isalnum() else "_" for ch in str(name))
    return "NSX_{}_USER".format(slug), "NSX_{}_PASS".format(slug)


def write_inventory(path, managers):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"managers": managers}, f, indent=2)
        f.write("\n")
    return path


# ==========================================================================
# creds.py  --  Credential resolution and storage.
# ==========================================================================

KEYRING_SERVICE = "nsx-toolkit"

# "auto" | "keyring" | "plaintext" | "none"
_store_policy = "auto"
_creds_cache = None
_consent_cache = None


def set_store_policy(policy):
    global _store_policy
    _store_policy = policy or "auto"


def creds_file_path():
    return os.environ.get("NSX_TOOLKIT_CREDENTIALS_FILE", DEFAULT_CREDS_FILE)


def reset_cache():
    global _creds_cache, _consent_cache
    _creds_cache = None
    _consent_cache = None


# === KEYRING ===
def _keyring():
    try:
        import keyring
        # A keyring with no usable backend raises only on use, so probe it.
        keyring.get_keyring()
        return keyring
    except Exception:
        return None


def keyring_available():
    return _keyring() is not None


def _keyring_get(var):
    kr = _keyring()
    if not kr:
        return None
    try:
        return kr.get_password(KEYRING_SERVICE, var)
    except Exception:
        return None


def _keyring_set(var, value):
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.set_password(KEYRING_SERVICE, var, value)
        return True
    except Exception:
        return False


# === PLAINTEXT FILE ===
def _secure_file(path):
    """Best-effort lockdown: owner-only on POSIX, single-user ACL on Windows."""
    try:
        if os.name == "nt":
            import subprocess
            user = os.environ.get("USERNAME", "")
            domain = os.environ.get("USERDOMAIN", "")
            subprocess.run(["icacls", path, "/inheritance:r"],
                           capture_output=True, timeout=10)
            if user:
                subprocess.run(
                    ["icacls", path, "/grant:r",
                     "{}\\{}:F".format(domain, user) if domain else "{}:F".format(user)],
                    capture_output=True, timeout=10)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass  # hardening is best-effort; never block a write on it


def _load_creds_file():
    global _creds_cache
    if _creds_cache is not None:
        return _creds_cache
    creds = {}
    path = creds_file_path()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    creds[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            pass
    _creds_cache = creds
    return creds


def _write_creds_file(updates):
    global _creds_cache
    path = creds_file_path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    existing = dict(_load_creds_file())
    existing.update({k: v for k, v in updates.items() if k})
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Managed by nsx-toolkit -- do not edit by hand.\n")
        f.write("# Use --set-credentials to update entries.\n")
        for k, v in existing.items():
            f.write('{}="{}"\n'.format(k, v))
    _secure_file(path)
    _creds_cache = None
    return path


# === RESOLVE / STORE ===
def resolve_secret(var):
    if not var:
        return None
    return (os.environ.get(var)
            or _keyring_get(var)
            or _load_creds_file().get(var))


def _plaintext_consent():
    """Ask once per run whether plaintext storage is acceptable."""
    global _consent_cache
    if _consent_cache is not None:
        return _consent_cache
    if not is_interactive():
        _consent_cache = False
        return False
    say("\n  {} No OS keyring is available on this machine.".format(cD("note:")))
    say("  Credentials can be saved to {} (readable by".format(cC(creds_file_path())))
    say("  your user account only), or not saved at all -- you would then be")
    say("  prompted each run, or set the environment variables yourself.")
    answer = ask("  Save credentials to that file? [y/N]: ",
                 default="n", allow_back=False).lower()
    _consent_cache = answer in ("y", "yes")
    return _consent_cache


def store_secrets(updates):
    """Persist {env_var: value}. Returns a short description of where they went."""
    updates = {k: v for k, v in updates.items() if k and v}
    if not updates or _store_policy == "none":
        return "not saved"
    if _store_policy in ("auto", "keyring"):
        stored = [k for k in updates if _keyring_set(k, updates[k])]
        if len(stored) == len(updates):
            return "saved to OS keyring"
        if _store_policy == "keyring":
            warn("keyring unavailable -- credentials were not saved.")
            return "not saved"
    if _store_policy == "plaintext" or _plaintext_consent():
        path = _write_creds_file(updates)
        return "saved to {}".format(path)
    return "not saved (will prompt again next run)"


def credentials_for(entry, allow_prompt=True):
    """(user, password, source) for one manager entry."""
    name = entry.get("name", "?")
    u_env = entry.get("username_env")
    p_env = entry.get("password_env")
    user, pwd = resolve_secret(u_env), resolve_secret(p_env)
    if user and pwd:
        return user, pwd, "stored"
    if not allow_prompt or not is_interactive():
        raise NsxError(
            "No credentials available for '{}'. Set {} and {}, or run "
            "--set-credentials.".format(name, u_env or "<username_env>",
                                        p_env or "<password_env>"))
    try:
        if not user:
            user = input("    username for {}: ".format(name)).strip()
        if not pwd:
            pwd = getpass.getpass("    password for {}: ".format(name))
    except (EOFError, KeyboardInterrupt):
        raise UserAbort() from None
    if not (user and pwd):
        raise NsxError("Credentials not provided for '{}'.".format(name))
    where = store_secrets({u_env: user, p_env: pwd})
    return user, pwd, "prompted, {}".format(where)


def force_set_credentials(managers, only=None):
    """--set-credentials: always prompt and overwrite whatever is stored."""
    targets = [m for m in managers if not only or m.get("name") in only]
    if not targets:
        err("No matching managers in inventory.")
        return 2
    if not is_interactive():
        err("--set-credentials needs an interactive terminal.")
        return 2
    say("\n  {} ({} manager(s)) ...".format(
        cB("Updating stored credentials"), len(targets)))
    updated = 0
    for m in targets:
        name = m.get("name", "?")
        u_env, p_env = m.get("username_env"), m.get("password_env")
        if not (u_env or p_env):
            warn("{}: no username_env/password_env in inventory, skipped.".format(name))
            continue
        try:
            user = input("    username for {}: ".format(name)).strip()
            pwd = getpass.getpass("    password for {}: ".format(name))
        except (EOFError, KeyboardInterrupt):
            raise UserAbort() from None
        if not (user and pwd):
            warn("{}: empty input, skipped.".format(name))
            continue
        where = store_secrets({u_env: user, p_env: pwd})
        ok_msg("{}: {}.".format(name, where))
        updated += 1
    say("\n  {} of {} updated.".format(cG(str(updated)), len(targets)))
    return 0


# ==========================================================================
# http.py  --  NSX transport and session.
# ==========================================================================

RETRY_STATUS = (429, 500, 502, 503, 504)
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.0
MAX_BACKOFF = 20.0

_tls_warnings_suppressed = False
_suppress_lock = threading.Lock()


def _suppress_tls_warnings():
    """Silence 'unverified HTTPS' noise -- only ever called when a manager is
    actually configured with verify_ssl false, never globally at import."""
    global _tls_warnings_suppressed
    with _suppress_lock:
        if _tls_warnings_suppressed:
            return
        _tls_warnings_suppressed = True
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass


def have_requests():
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False


class TransportError(Exception):
    """Connection-level failure (DNS, refused, reset, timeout)."""


class Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise NsxError("Response was not valid JSON: {}".format(e)) from e

    def text(self, limit=400):
        try:
            return self.body.decode("utf-8", "replace")[:limit]
        except Exception:
            return ""


class RequestsTransport:
    name = "requests"

    def __init__(self, pool_size=16):
        import requests
        from requests.adapters import HTTPAdapter
        self._requests = requests
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size,
                              pool_maxsize=pool_size, max_retries=0)
        self.s.mount("https://", adapter)
        self.s.mount("http://", adapter)

    def request(self, method, url, headers, body, timeout, verify, cert):
        try:
            r = self.s.request(method, url, headers=headers, data=body,
                               timeout=timeout, verify=verify, cert=cert,
                               allow_redirects=False)
        except self._requests.exceptions.RequestException as e:
            raise TransportError(str(e)) from e
        return Response(r.status_code, dict(r.headers), r.content)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


class UrllibTransport:
    """Stdlib fallback. Same interface, no third-party dependency."""

    name = "urllib"

    def __init__(self, pool_size=16):
        self._cookies = {}
        self._lock = threading.Lock()

    def _context(self, verify):
        if verify is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if isinstance(verify, str):
            return ssl.create_default_context(cafile=verify)
        return ssl.create_default_context()

    def request(self, method, url, headers, body, timeout, verify, cert):
        if cert:
            raise NsxError(
                "Client-certificate auth needs the 'requests' library "
                "(pip install requests).")
        hdrs = dict(headers or {})
        with self._lock:
            if self._cookies:
                hdrs["Cookie"] = "; ".join(
                    "{}={}".format(k, v) for k, v in self._cookies.items())
        if isinstance(body, str):
            body = body.encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(
                    req, timeout=timeout, context=self._context(verify)) as r:
                resp = Response(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            resp = Response(e.code, dict(e.headers or {}), e.read() or b"")
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise TransportError(str(e)) from e
        self._absorb_cookies(resp.headers)
        return resp

    def _absorb_cookies(self, headers):
        raw = headers.get("Set-Cookie") or headers.get("set-cookie")
        if not raw:
            return
        with self._lock:
            for chunk in str(raw).split(","):
                pair = chunk.split(";", 1)[0].strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    if k.strip():
                        self._cookies[k.strip()] = v.strip()

    def close(self):
        pass


def make_transport(pool_size=16):
    return (RequestsTransport(pool_size) if have_requests()
            else UrllibTransport(pool_size))


class Nsx:
    """One authenticated NSX manager."""

    def __init__(self, entry, user, pwd, transport=None, retries=DEFAULT_RETRIES):
        self.entry = entry
        self.name = entry.get("name", "?")
        self.role = (entry.get("role") or "").lower() or None
        host = entry.get("host")
        if not host:
            raise NsxError("'{}' has no 'host'.".format(self.name))
        self.host = host
        # 'scheme' exists for test harnesses and plaintext lab appliances.
        # Production NSX is always https, which is why that is the default.
        scheme = (entry.get("scheme") or "https").lower()
        self.base_url = "{}://{}:{}".format(scheme, host, entry.get("port", 443))
        self.timeout = entry.get("timeout", 30)
        self.retries = retries
        self.auth_mode = (entry.get("auth") or "session").lower()
        self._user, self._pwd = user, pwd
        self._base = entry.get("policy_base")
        # NSX Project scoping. Set, every policy path hangs off the project's
        # own infra tree instead of the default one.
        self.project = entry.get("project")
        self.org = entry.get("org") or DEFAULT_ORG
        self._version = None
        self._vm_index = None
        self._vm_lock = threading.Lock()
        self._base_lock = threading.Lock()
        self._auth_lock = threading.Lock()
        self._session_headers = {}
        self._authenticated = False

        verify = entry.get("verify_ssl", True)
        ca = entry.get("ca_bundle")
        if verify and ca:
            self.verify = ca
        else:
            self.verify = bool(verify)
        if self.verify is False:
            _suppress_tls_warnings()
        self.cert = entry.get("client_cert")
        self.t = transport or make_transport()

    # --- auth --------------------------------------------------------------
    def _basic_header(self):
        raw = "{}:{}".format(self._user, self._pwd).encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

    def _ensure_auth(self):
        """Establish session-token auth once. Falls back to Basic if the
        manager does not offer session create."""
        if self._authenticated:
            return
        with self._auth_lock:
            if self._authenticated:
                return
            if self.auth_mode == "basic":
                self._session_headers = self._basic_header()
            elif self.auth_mode == "token":
                token = self.entry.get("token") or self._pwd
                header = self.entry.get("token_header") or "X-NSX-Auth-Token"
                self._session_headers = {header: token}
            elif self.auth_mode == "cert":
                self._session_headers = {}
            else:
                self._session_headers = self._session_login()
            self._authenticated = True

    def _session_login(self):
        body = urllib.parse.urlencode(
            {"j_username": self._user, "j_password": self._pwd}).encode("utf-8")
        url = self.base_url + PATH_SESSION_CREATE
        try:
            r = self._send("POST", url, {
                "Content-Type": "application/x-www-form-urlencoded"}, body)
        except (TransportError, NsxError) as e:
            debug("{}: session create failed ({}), falling back to Basic".format(
                self.name, e))
            return self._basic_header()
        if r.status >= 400:
            debug("{}: session create HTTP {}, falling back to Basic".format(
                self.name, r.status))
            return self._basic_header()
        headers = {}
        xsrf = r.headers.get("x-xsrf-token") or r.headers.get("X-XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = xsrf
        cookie = r.headers.get("Set-Cookie") or r.headers.get("set-cookie")
        if cookie:
            jar = [c.split(";", 1)[0].strip() for c in str(cookie).split(",")
                   if "=" in c.split(";", 1)[0]]
            if jar:
                headers["Cookie"] = "; ".join(jar)
        if not headers:
            debug("{}: session create returned no token, using Basic".format(self.name))
            return self._basic_header()
        debug("{}: authenticated via session token".format(self.name))
        return headers

    # --- request plumbing --------------------------------------------------
    def _send(self, method, url, headers, body):
        return self.t.request(method, url, headers, body, self.timeout,
                              self.verify, self.cert)

    def _sleep_for(self, attempt, response):
        if response is not None:
            ra = (response.headers or {}).get("Retry-After")
            if ra:
                try:
                    return min(float(ra), MAX_BACKOFF)
                except ValueError:
                    pass
        return min(DEFAULT_BACKOFF * (2 ** attempt), MAX_BACKOFF) * (
            0.5 + random.random() / 2.0)

    def _req(self, method, path, body=None, params=None):
        self._ensure_auth()
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        headers = dict(self._session_headers)
        headers.setdefault("Accept", "application/json")
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")

        last_exc = None
        for attempt in range(self.retries + 1):
            started = time.time()
            try:
                r = self._send(method, url, headers, payload)
            except TransportError as e:
                last_exc = NsxError("[{}] {} {} -> {}".format(
                    self.name, method, url, e))
                debug("{} {} -> transport error: {} (attempt {}/{})".format(
                    method, url, e, attempt + 1, self.retries + 1))
                if attempt < self.retries:
                    time.sleep(self._sleep_for(attempt, None))
                    continue
                raise last_exc from e
            elapsed = (time.time() - started) * 1000
            debug("{} {} -> {} ({:.0f}ms)".format(method, url, r.status, elapsed))
            if r.status in RETRY_STATUS and attempt < self.retries:
                wait = self._sleep_for(attempt, r)
                debug("  retrying after {:.1f}s (HTTP {})".format(wait, r.status))
                time.sleep(wait)
                continue
            if r.status >= 400:
                raise NsxHttpError("[{}] {} {} -> HTTP {}: {}".format(
                    self.name, method, url, r.status, r.text()), r.status)
            return r.json()
        raise last_exc or NsxError("[{}] {} {} -> exhausted retries".format(
            self.name, method, url))

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, body=None, params=None):
        return self._req("POST", path, body=body, params=params)

    def patch(self, path, body=None, params=None):
        return self._req("PATCH", path, body=body, params=params)

    def put(self, path, body=None, params=None):
        """Full-object write. PUT rather than PATCH for anything carrying a
        `_revision`: NSX only enforces the optimistic-concurrency check when
        the whole object is sent, and that check is the entire safety
        mechanism behind authoring."""
        return self._req("PUT", path, body=body, params=params)

    def delete(self, path, params=None):
        return self._req("DELETE", path, params=params)

    def get_all(self, path, params=None):
        """Follow NSX's opaque cursor pagination to completion."""
        out, cursor = [], None
        while True:
            p = dict(params or {})
            p.setdefault(PARAM_PAGE_SIZE, PAGE_SIZE)
            if cursor:
                p[PARAM_CURSOR] = cursor
            data = self.get(path, params=p)
            out.extend(data.get(F_RESULTS, []))
            cursor = data.get(F_CURSOR)
            if not cursor:
                break
        return out

    # --- capability detection ---------------------------------------------
    def base(self, domain=DEFAULT_DOMAIN, verbose=False):
        """Policy API base. GM answers on one of two paths depending on
        version, so probe rather than guess."""
        if self._base:
            return self._base
        with self._base_lock:
            if self._base:
                return self._base
            if self.project:
                # A project's tree is the same on either role, so no probe.
                self._base = project_base(self.project, self.org)
                if verbose:
                    say("    project scope: {}".format(cG(self._base)))
                return self._base
            if self.role != ROLE_GM:
                self._base = API_BASE_LM
                return self._base
            notes = []
            for cand in API_BASE_GM_CANDIDATES:
                try:
                    self.get(p_groups(cand, domain), params={PARAM_PAGE_SIZE: 1})
                    self._base = cand
                    if verbose:
                        say("    GM answers on: {}".format(cG(cand)))
                    return self._base
                except NsxError as e:
                    notes.append(str(e)[:160])
            raise NsxError("GM did not answer on any known base.\n" +
                           "\n".join("      {}".format(n) for n in notes))

    def version(self):
        """(major, minor) of the manager, or None if it cannot be read."""
        if self._version is not None:
            return self._version or None
        try:
            d = self.get(PATH_NODE_VERSION)
            raw = d.get(F_NODE_VERSION) or d.get(F_PRODUCT_VERSION)
            self._version = parse_version(raw) or ()
        except NsxError:
            self._version = ()
        return self._version or None

    # --- VM inventory ------------------------------------------------------
    def all_vms(self, refresh=False):
        """Full VM inventory, fetched at most once per session.

        This is the fix for bulk tagging: resolving 500 CSV rows previously
        triggered up to 500 full inventory sweeps per manager.
        """
        with self._vm_lock:
            if self._vm_index is None or refresh:
                self._vm_index = self.get_all(PATH_FABRIC_VMS)
            return self._vm_index

    def invalidate_vms(self):
        with self._vm_lock:
            self._vm_index = None

    def find_vms(self, needle, exact=False):
        """VMs whose display name matches. Tries the server-side exact filter
        first (cheap), then falls back to the cached index for substrings."""
        if not needle:
            return []
        try:
            hits = self.get(PATH_FABRIC_VMS,
                            params={PARAM_DISPLAY_NAME: needle}).get(F_RESULTS, [])
            if hits:
                return hits
        except NsxError:
            pass
        n = str(needle).lower()
        vms = self.all_vms()
        if exact:
            return [v for v in vms if str(v.get(F_DISPLAY_NAME, "")).lower() == n]
        return [v for v in vms if n in str(v.get(F_DISPLAY_NAME, "")).lower()]

    def get_vm_by_external_id(self, ext_id):
        for v in self.all_vms():
            if v.get(F_EXTERNAL_ID) == ext_id:
                return v
        return None

    def refresh_vm(self, vm):
        """Re-read one VM straight from NSX, bypassing the cache. Used
        immediately before a write so a stale plan cannot clobber someone
        else's concurrent change."""
        ext = vm.get(F_EXTERNAL_ID)
        name = vm.get(F_DISPLAY_NAME, "")
        try:
            hits = self.get(PATH_FABRIC_VMS,
                            params={PARAM_DISPLAY_NAME: name}).get(F_RESULTS, [])
            for h in hits:
                if h.get(F_EXTERNAL_ID) == ext:
                    return h
        except NsxError:
            pass
        for v in self.all_vms(refresh=True):
            if v.get(F_EXTERNAL_ID) == ext:
                return v
        return None

    def update_vm_tags(self, vm, pairs):
        ext = vm.get(F_EXTERNAL_ID)
        if not ext:
            raise NsxError("VM has no external_id.")
        self.post(PATH_FABRIC_VMS,
                  body={F_EXTERNAL_ID: ext,
                        F_TAGS: [{F_TAG_SCOPE: s, F_TAG_VALUE: t} for s, t in pairs]},
                  params={PARAM_ACTION: ACTION_UPDATE_TAGS})
        self.invalidate_vms()

    def close(self):
        try:
            self.t.close()
        except Exception:
            pass


# ==========================================================================
# audit.py  --  Append-only audit log of every write, with before/after state for undo.
# ==========================================================================

def current_user():
    return (os.environ.get("USERNAME") or os.environ.get("USER") or "unknown")


# What an entry describes. Tag entries predate the field and are inferred.
OBJ_VM_TAGS = "vm_tags"
OBJ_GROUP = "group"
OBJ_RULE = "rule"
OBJ_POLICY = "policy"

ENTRY_VERSION = 2


def _tag_pairs(entries):
    return [(t.get("scope", ""), t.get("tag", "")) for t in (entries or [])]


def normalise_entry(entry):
    """One shape for an audit entry, whichever era wrote it.

    Returns a dict with object_type, object_path, object_name, before and
    after always present. For a tag entry `before`/`after` are lists of
    (scope, tag) pairs; for an object entry they are the NSX bodies.
    """
    common = {
        "timestamp": entry.get("timestamp", ""),
        "user": entry.get("user", ""),
        "manager": entry.get("manager", ""),
        "action": entry.get("action", ""),
        "status": entry.get("status", ""),
        "detail": entry.get("detail", ""),
        "raw": entry,
    }
    object_type = entry.get("object_type")
    if object_type in (None, OBJ_VM_TAGS) and "vm_display_name" in entry:
        # Pre-authoring entry, or a tag entry written since: both carry the
        # VM fields, and undo reads them from here.
        common.update({
            "object_type": OBJ_VM_TAGS,
            "object_path": entry.get("object_path")
                           or "vm:{}".format(entry.get("vm_external_id", "")),
            "object_name": entry.get("vm_display_name", "?"),
            "before": _tag_pairs(entry.get("tags_before")),
            "after": _tag_pairs(entry.get("tags_after")),
        })
        return common
    common.update({
        "object_type": object_type or "unknown",
        "object_path": entry.get("object_path", ""),
        "object_name": entry.get("object_name", ""),
        "before": entry.get("before"),
        "after": entry.get("after"),
    })
    return common


def summarise_entry(normalised):
    """A one-line 'what changed' for the listing, per object type."""
    if normalised["object_type"] == OBJ_VM_TAGS:
        before = normalised["before"] or []
        after = normalised["after"] or []
        added = [p for p in after if p not in before]
        removed = [p for p in before if p not in after]
        return added, removed
    return [], []


class AuditLog:
    def __init__(self, path=None, max_bytes=AUDIT_MAX_BYTES, keep=AUDIT_KEEP):
        self.path = path or DEFAULT_AUDIT_FILE
        self.max_bytes = max_bytes
        self.keep = keep
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)

    def _rotate_if_needed(self):
        try:
            if not os.path.isfile(self.path):
                return
            if os.path.getsize(self.path) < self.max_bytes:
                return
            oldest = "{}.{}".format(self.path, self.keep)
            if os.path.exists(oldest):
                os.remove(oldest)
            for i in range(self.keep - 1, 0, -1):
                src = "{}.{}".format(self.path, i)
                if os.path.exists(src):
                    os.replace(src, "{}.{}".format(self.path, i + 1))
            os.replace(self.path, "{}.1".format(self.path))
        except OSError as e:
            err("audit rotation failed: {}".format(e))

    def _append(self, entry):
        self._rotate_if_needed()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            err("audit write failed: {}".format(e))
        return entry

    def _envelope(self, action, manager, status, detail):
        return {
            "timestamp": utc_now_iso(),
            "user": current_user(),
            "host": platform.node(),
            "manager": manager,
            "action": action,
            "status": status,
            "detail": detail,
            "entry_version": ENTRY_VERSION,
        }

    def log(self, action, manager, vm_name, vm_ext_id, tags_before, tags_after,
            status="success", detail=""):
        """A VM tag change.

        Keeps writing `vm_display_name` / `tags_before` / `tags_after`
        verbatim -- an undo path and a log file written by an earlier release
        both read those, and neither should have to care that object entries
        now exist alongside them. The general fields are added, not swapped in.
        """
        entry = self._envelope(action, manager, status, detail)
        entry.update({
            "object_type": OBJ_VM_TAGS,
            "object_path": "vm:{}".format(vm_ext_id or ""),
            "object_name": vm_name,
            "vm_display_name": vm_name,
            "vm_external_id": vm_ext_id,
            "tags_before": [{"scope": s, "tag": t} for s, t in tags_before],
            "tags_after": [{"scope": s, "tag": t} for s, t in tags_after],
        })
        return self._append(entry)

    def log_change(self, action, manager, object_type, object_path,
                   object_name, before_body, after_body, status="success",
                   detail=""):
        """A change to a policy object: a group, a rule or a policy.

        `before_body` is None for a create and `after_body` is None for a
        delete, which is exactly what undo needs to know which direction to
        go without a separate flag to get out of step with reality.
        """
        entry = self._envelope(action, manager, status, detail)
        entry.update({
            "object_type": object_type,
            "object_path": object_path,
            "object_name": object_name,
            "before": before_body,
            "after": after_body,
        })
        return self._append(entry)

    def _tail_lines(self, n):
        """Last n non-empty lines without reading the whole file."""
        if not os.path.isfile(self.path):
            return []
        chunk = 8192
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                data = b""
                while size > 0 and data.count(b"\n") <= n:
                    step = min(chunk, size)
                    size -= step
                    f.seek(size)
                    data = f.read(step) + data
        except OSError:
            return []
        text = data.decode("utf-8", "replace")
        return [ln for ln in text.splitlines() if ln.strip()][-n:]

    def last_n(self, n=20):
        entries = []
        for line in self._tail_lines(n):
            try:
                entries.append(json.loads(line))
            except ValueError:
                pass
        return entries

    def last_n_normalised(self, n=20):
        """The same entries in one shape, whichever era wrote them."""
        return [normalise_entry(e) for e in self.last_n(n)]


# ==========================================================================
# export.py  --  Result staging and export.
# ==========================================================================

class ResultSet:
    __slots__ = ("label", "headers", "rows")

    def __init__(self, label, headers, rows):
        self.label = label
        self.headers = headers
        self.rows = rows

    def as_dicts(self):
        return [{self.headers[i]: (row[i] if i < len(row) else "")
                 for i in range(len(self.headers))} for row in self.rows]


class Exporter:
    def __init__(self, export_dir=None):
        self.export_dir = export_dir or DEFAULT_EXPORT_DIR
        self._sets = []
        # Findings are a second channel alongside rows: rows are "here is the
        # data", findings are "here is what is wrong with it". CSV and JSON
        # want the first; JUnit, SARIF, metrics and a webhook want the second.
        self._findings = []

    def stage(self, label, headers, rows):
        """Add a result set. Empty sets are still recorded so --json reports
        'this action ran and found nothing' rather than staying silent."""
        self._sets.append(ResultSet(label, list(headers), list(rows)))

    @property
    def sets(self):
        return list(self._sets)

    def stage_findings(self, label, findings):
        """Record machine-readable findings for this run."""
        for item in findings:
            entry = dict(item)
            entry.setdefault("suite", label)
            self._findings.append(entry)

    @property
    def findings(self):
        return list(self._findings)

    def findings_by_suite(self):
        suites = {}
        for item in self._findings:
            suites.setdefault(item.get("suite", "nsxctl"), []).append(item)
        return suites

    def has_findings(self):
        return bool(self._findings)

    def has_staged(self):
        return any(rs.rows for rs in self._sets)

    def clear(self):
        self._sets = []
        self._findings = []

    def _ensure_dir(self, path):
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)

    def _gen(self, label, ext):
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", label or "export")[:40]
        return os.path.join(self.export_dir,
                            "{}_{}.{}".format(safe, local_stamp(), ext))

    def _target(self, base_path, rs, index, total, ext):
        """One file per result set. With several sets the label is appended so
        nothing is silently overwritten."""
        if not base_path:
            return self._gen(rs.label, ext)
        if total == 1:
            return base_path
        root, dot_ext = os.path.splitext(base_path)
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", rs.label or str(index))[:40]
        return "{}_{}{}".format(root, safe, dot_ext or "." + ext)

    def to_csv(self, path=None):
        written = []
        sets = [rs for rs in self._sets if rs.rows]
        for i, rs in enumerate(sets):
            target = self._target(path, rs, i, len(sets), "csv")
            self._ensure_dir(target)
            with open(target, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(rs.headers)
                w.writerows(rs.rows)
            written.append(target)
        return written

    def to_json(self, path=None):
        written = []
        sets = [rs for rs in self._sets if rs.rows]
        if path and len(sets) > 1:
            # One JSON file can hold every set, so keep them together.
            self._ensure_dir(path)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"exported": utc_now_iso(),
                           "results": [{"label": rs.label,
                                        "count": len(rs.rows),
                                        "records": rs.as_dicts()} for rs in sets]},
                          f, indent=2, ensure_ascii=False)
            return [path]
        for i, rs in enumerate(sets):
            target = self._target(path, rs, i, len(sets), "json")
            self._ensure_dir(target)
            with open(target, "w", encoding="utf-8") as f:
                json.dump({"exported": utc_now_iso(), "label": rs.label,
                           "count": len(rs.rows), "records": rs.as_dicts()},
                          f, indent=2, ensure_ascii=False)
            written.append(target)
        return written

    def json_payload(self):
        return [{"label": rs.label, "count": len(rs.rows),
                 "records": rs.as_dicts()} for rs in self._sets]


def offer_export(exporter):
    """Interactive post-action export prompt. A no-op in JSON mode, where the
    results are emitted in the envelope instead."""
    if is_json_mode() or not exporter.has_staged():
        return
    total = sum(len(rs.rows) for rs in exporter.sets)
    say("\n  {} record(s) available.".format(cC(str(total))))
    c = ask("  Export? [c]sv / [j]son / [n]o: ",
            default="n", allow_back=False).lower()
    if c in ("c", "csv"):
        for p in exporter.to_csv():
            ok_msg("Saved: {}".format(p))
    elif c in ("j", "json"):
        for p in exporter.to_json():
            ok_msg("Saved: {}".format(p))
    exporter.clear()


# ==========================================================================
# render.py  --  Shared formatting for tags and group membership criteria.
# ==========================================================================

def tags_of(obj):
    return [(t.get(F_TAG_SCOPE, ""), t.get(F_TAG_VALUE, ""))
            for t in (obj.get(F_TAGS) or [])]


def fmt_tags(pairs):
    if not pairs:
        return cD("(none)")
    return ", ".join("{}={}".format(cC(s), t) if s else t
                     for s, t in sorted(pairs))


def fmt_tags_plain(pairs):
    if not pairs:
        return "(none)"
    return ", ".join("{}={}".format(s, t) if s else t for s, t in sorted(pairs))


def describe_expression(expr):
    """Human-readable lines for a group's membership criteria."""
    if not expr:
        return [cD("(no criteria)")]
    lines = []
    for item in expr:
        rt = item.get(RT)
        if rt == RT_CONJUNCTION:
            lines.append("  {}".format(cB(item.get(F_CONJ_OP, "?"))))
        elif rt == RT_CONDITION:
            key = item.get(F_KEY, "?")
            op = item.get(F_OPERATOR, "?")
            val = item.get(F_VALUE, "")
            mt = item.get(F_MEMBER_TYPE, "")
            if key == KEY_TAG and TAG_SCOPE_SEPARATOR in str(val):
                s, _, t = str(val).partition(TAG_SCOPE_SEPARATOR)
                lines.append("  {} Tag {} {}={}".format(mt, op, cC(s), cG(t)))
            else:
                lines.append("  {} {} {} '{}'".format(mt, key, op, val))
        elif rt == RT_NESTED:
            lines.append("  ( nested:")
            for sub in describe_expression(item.get(F_EXPRESSIONS, [])):
                lines.append("  {}".format(sub))
            lines.append("  )")
        elif rt == RT_IPADDRESS:
            ips = item.get(F_IP_ADDRESSES, [])
            lines.append("  IPs ({}): {}{}".format(
                len(ips), ", ".join(map(str, ips[:8])),
                " ..." if len(ips) > 8 else ""))
        elif rt == RT_PATHEXPR:
            paths = item.get(F_PATHS, [])
            lines.append("  Paths ({}):".format(len(paths)))
            for p in paths[:10]:
                lines.append("    {}".format(p))
        else:
            lines.append("  {}: {}".format(rt or "unknown", json.dumps(item)[:160]))
    return lines


def criteria_summary(expr, parts=3):
    """Flat one-line version of the criteria, for CSV columns."""
    lines = describe_expression(expr)
    return "; ".join(strip_ansi(ln).strip() for ln in lines[:parts])


# ==========================================================================
# policy.py  --  Shared security-policy and rule traversal.
# ==========================================================================

class RuleRecord:
    """One DFW rule, with the manager and policy it was read from."""

    __slots__ = ("nsx", "policy", "rule", "origin")

    def __init__(self, nsx, policy, rule, origin):
        self.nsx = nsx
        self.policy = policy
        self.rule = rule
        self.origin = origin

    @property
    def policy_id(self):
        return self.policy.get(F_ID, "?")

    @property
    def policy_name(self):
        return self.policy.get(F_DISPLAY_NAME, self.policy_id)

    @property
    def rule_id(self):
        return self.rule.get(F_ID, "?")

    @property
    def rule_name(self):
        return self.rule.get(F_DISPLAY_NAME, self.rule_id)

    @property
    def path(self):
        return self.rule.get(F_PATH, "")

    def group_refs(self):
        """Every group path this rule mentions, in any position."""
        return set(self.rule.get(F_SOURCE_GROUPS, [])
                   + self.rule.get(F_DEST_GROUPS, [])
                   + self.rule.get(F_SCOPE, []))

    def directions_for(self, group_paths):
        """Which positions of the rule reference the given groups."""
        dirs = []
        if set(self.rule.get(F_SOURCE_GROUPS, [])) & group_paths:
            dirs.append("source")
        if set(self.rule.get(F_DEST_GROUPS, [])) & group_paths:
            dirs.append("dest")
        if set(self.rule.get(F_SCOPE, [])) & group_paths:
            dirs.append("applied_to")
        return dirs


def fetch_rules_for(nsx, domain, policies):
    """Rules for every policy on one manager, fetched concurrently.

    Serially this was an N+1: one round trip per policy per manager, so eight
    LMs with 200 policies each meant 1,600 sequential requests.
    """
    if not policies:
        return []
    results = parallel_run(
        policies,
        lambda pol: nsx.get_all(p_sec_rules(nsx.base(domain), domain,
                                            pol.get(F_ID, "?"))),
        label="Rules on {}".format(nsx.name),
        key=lambda pol: pol.get(F_ID, "?"))
    out = []
    for pol in policies:
        rules = results.get(pol.get(F_ID, "?"))
        if isinstance(rules, Exception):
            continue
        for rule in (rules or []):
            out.append((pol, rule))
    return out


def policies_for(nsx, domain):
    """Security policies on one manager, or [] when it cannot be reached."""
    try:
        base = nsx.base(domain)
    except NsxError:
        return []
    with Spinner("Policies on {}".format(nsx.name)):
        try:
            return nsx.get_all(p_sec_policies(base, domain))
        except NsxError:
            return []


def listed_values(rule, field):
    """A rule's list-valued field with empties dropped."""
    return [v for v in (rule.get(field) or []) if v]


def is_wildcard(values):
    """NSX writes the wildcard as ["ANY"]; an empty list means the same.

    Shared rather than duplicated: rule hygiene and trace evaluation both turn
    on this exact question, and two copies would eventually disagree about
    what "matches everything" means.
    """
    return not values or list(values) == [ANY]


def rule_sequence(record):
    """A rule's evaluation position, as an int. NSX omits or stringifies it on
    some versions, so this never raises."""
    try:
        return int(record.rule.get(F_SEQUENCE_NUMBER) or 0)
    except (TypeError, ValueError):
        return 0


def ordered_sessions(sessions):
    """Global Managers first. The dedup below depends on this order."""
    gm = [s for s in sessions if s.role == ROLE_GM]
    lm = [s for s in sessions if s.role == ROLE_LM]
    return gm, lm


def sweep_rules(sessions, domain):
    """Every DFW rule across every manager, deduplicated by rule path.

    A rule with no path is never deduplicated -- we cannot prove two such
    rules are the same object, and silently dropping one would under-report.
    """
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    seen_paths = set()
    records = []
    for nsx in gm_sessions + lm_sessions:
        policies = policies_for(nsx, domain)
        for policy, rule in fetch_rules_for(nsx, domain, policies):
            path = rule.get(F_PATH, "")
            if path:
                if path in seen_paths:
                    continue
                seen_paths.add(path)
            if nsx.role == ROLE_GM:
                origin = "GM"
            else:
                origin = origin_of_path(path)
                if origin == "GM" and not gm_sessions:
                    origin = "GM (via LM)"
            records.append(RuleRecord(nsx, policy, rule, origin))
    return records


def group_inventory(sessions, domain):
    """{group path: (nsx, group)} across every manager, GM first.

    Used to tell "this rule references a group that does not exist" apart from
    "this rule references a group that exists but is empty" -- two findings
    with very different meanings.
    """
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    by_path = {}
    for nsx in gm_sessions + lm_sessions:
        try:
            base = nsx.base(domain)
            groups = nsx.get_all(p_groups(base, domain))
        except NsxError:
            continue
        for group in groups:
            path = group.get(F_PATH, "")
            if path and path not in by_path:
                by_path[path] = (nsx, group)
    return by_path


# ==========================================================================
# trace.py  --  Can A reach B, and which rule decided it.
# ==========================================================================

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


# ==========================================================================
# baseline.py  --  Rule hit-count baselines.
# ==========================================================================

BASELINE_HEADERS = ["status", "manager", "policy", "rule", "hits_then",
                    "hits_now", "delta", "detail"]

# Outcomes, worst-news-first for reporting.
STATUS_ORDER = ("counter_reset", "unused_since_baseline", "active",
                "added", "removed", "unknown")


def default_baseline_path(domain="default"):
    return os.path.join(
        DEFAULT_SNAPSHOT_DIR,
        "hit-baseline_{}_{}.json".format(domain, local_stamp()))


def build_hit_baseline(records, stats, domain="default"):
    """A serialisable snapshot of every rule's counter."""
    rules = {}
    for record in records:
        path = record.path
        if not path:
            continue
        entry = stats.get(path) or {}
        hits = entry.get(F_HIT_COUNT)
        rules[path] = {
            "manager": record.nsx.name,
            "policy": record.policy_name,
            "rule": record.rule_name,
            "hit_count": hits,
            "last_update": entry.get(F_LAST_UPDATE),
        }
    return {"taken": utc_now_iso(), "tool_version": VERSION,
            "domain": domain, "rule_count": len(rules), "rules": rules}


def save_hit_baseline(snapshot, path=None, domain="default"):
    path = path or default_baseline_path(domain)
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


def load_hit_baseline(path):
    if not os.path.isfile(path):
        raise NsxError("Baseline not found: {}".format(path))
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise NsxError("Baseline is not valid JSON ({}): {}".format(
            path, e)) from e
    if not isinstance(data, dict) or "rules" not in data:
        raise NsxError(
            "{} does not look like a hit baseline (no 'rules').".format(path))
    return data


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compare_hit_baselines(before, after):
    """Per-rule comparison of two snapshots.

    Returns a list of dicts with a `status` from STATUS_ORDER. Rules present
    in only one snapshot are reported as added/removed rather than dropped --
    a rule that disappeared between reads is information, not noise.
    """
    old_rules = before.get("rules") or {}
    new_rules = after.get("rules") or {}
    results = []

    for path in sorted(set(old_rules) | set(new_rules)):
        old = old_rules.get(path)
        new = new_rules.get(path)
        meta = new or old or {}
        base = {"path": path,
                "manager": meta.get("manager", ""),
                "policy": meta.get("policy", ""),
                "rule": meta.get("rule", ""),
                "hits_then": None, "hits_now": None, "delta": None}

        if old is None:
            base.update(status="added",
                        hits_now=_as_int(new.get("hit_count")),
                        detail="rule did not exist when the baseline "
                               "was taken")
            results.append(base)
            continue
        if new is None:
            base.update(status="removed",
                        hits_then=_as_int(old.get("hit_count")),
                        detail="rule existed in the baseline but not now")
            results.append(base)
            continue

        then = _as_int(old.get("hit_count"))
        now = _as_int(new.get("hit_count"))
        base["hits_then"], base["hits_now"] = then, now
        if then is None or now is None:
            base.update(status="unknown",
                        detail="hit counters unavailable in one or both reads")
            results.append(base)
            continue

        delta = now - then
        base["delta"] = delta
        if delta < 0:
            base.update(
                status="counter_reset",
                detail="counter went backwards ({} -> {}) -- it was reset, so "
                       "this window proves nothing".format(then, now))
        elif delta == 0:
            base.update(
                status="unused_since_baseline",
                detail="no traffic matched between {} and {}".format(
                    before.get("taken", "?"), after.get("taken", "?")))
        else:
            base.update(status="active",
                        detail="{} hit(s) in the window".format(delta))
        results.append(base)

    results.sort(key=lambda r: (STATUS_ORDER.index(r["status"]),
                                r["policy"], r["rule"]))
    return results


def hit_baseline_rows(results):
    return [[r["status"], r["manager"], r["policy"], r["rule"],
             "" if r["hits_then"] is None else str(r["hits_then"]),
             "" if r["hits_now"] is None else str(r["hits_now"]),
             "" if r["delta"] is None else str(r["delta"]),
             r["detail"]] for r in results]


def hit_baseline_summary(results):
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    return counts


# ==========================================================================
# snapshot.py  --  Configuration snapshots: capture NSX config as a git-friendly tree.
# ==========================================================================

MANIFEST = "manifest.json"

# Fields NSX changes on its own. Stripped from the compared body: leaving any
# of them in makes every snapshot differ from the last one.
VOLATILE_FIELDS = frozenset({
    "_revision",
    "_create_time",
    "_create_user",
    "_last_modified_time",
    "_last_modified_user",
    "_system_owned",
    "_protection",
    "realization_id",
    "unique_id",
    "parent_path",
    "relative_path",
    "marked_for_delete",
    "overridden",
    "origin_site_id",
    "owner_id",
    "remote_path",
    "children",
})
# Deliberately NOT stripped: `resource_type`. It looks like metadata, but
# inside a group's `expression` it is the discriminator that tells a Condition
# from an IPAddressExpression. Strip it and two different criteria compare
# equal.

# Kept out of the comparison, but carried alongside it: this is the
# "who changed it" evidence the drift report exists to surface.
PROVENANCE_FIELDS = ("_last_modified_user", "_last_modified_time",
                     "_create_user", "_revision")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _safe(component):
    """A path component safe on every filesystem, from an NSX id."""
    cleaned = _SAFE_NAME.sub("_", str(component or "unknown"))
    return cleaned[:120] or "unknown"


def normalise_object(obj):
    """(body, provenance). Body is what gets compared; provenance is context.

    Recurses, because nested structures carry the same volatile fields.
    """
    provenance = {key: obj.get(key) for key in PROVENANCE_FIELDS
                  if obj.get(key) is not None}
    return _strip(obj), provenance


def _strip(value):
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items()
                if k not in VOLATILE_FIELDS}
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


# === CAPTURE ===
def capture_snapshot(sessions, domain, with_tags=False):
    """Read the current configuration into an in-memory snapshot.

    Uses the same deduplicated GM/LM traversal as reverse lookup and rule
    hygiene, so a GM-authored rule realized onto eight Local Managers is
    captured once, under the manager that owns it.
    """
    objects = {}
    provenance = {}
    counts = {"groups": 0, "policies": 0, "rules": 0, "tags": 0}

    def record(kind, manager, path, obj, extra=None):
        body, prov = normalise_object(obj)
        if extra:
            body.update(extra)
        objects[path] = {"kind": kind, "manager": manager, "body": body}
        if prov:
            provenance[path] = prov
        counts[kind] = counts.get(kind, 0) + 1

    with Spinner("Reading groups"):
        groups = group_inventory(sessions, domain)
    for path, (nsx, group) in groups.items():
        record("groups", nsx.name, path, group)

    with Spinner("Reading policies and rules"):
        records = sweep_rules(sessions, domain)

    # Evaluation order lives on the policy rather than in rule filenames, so a
    # reorder shows as one precise change instead of N deletes plus N adds.
    by_policy = {}
    for rec in records:
        key = (rec.nsx.name, rec.policy.get(F_PATH, ""))
        by_policy.setdefault(key, []).append(rec)

    for (manager, policy_path), rules in by_policy.items():
        ordered = sorted(rules, key=rule_sequence)
        policy = ordered[0].policy
        record("policies", manager, policy_path, policy,
               extra={"order": [r.rule_id for r in ordered]})
        for rec in ordered:
            if rec.path:
                record("rules", manager, rec.path, rec.rule)

    if with_tags:
        lms = [s for s in sessions if s.role == ROLE_LM]
        fetched = parallel_run(lms, lambda s: s.all_vms(),
                               label="Reading VM tags")
        for nsx in lms:
            vms = fetched.get(nsx.name)
            if isinstance(vms, Exception):
                continue
            for vm in (vms or []):
                ext = vm.get(F_EXTERNAL_ID)
                if not ext:
                    continue
                path = "vm:{}".format(ext)
                objects[path] = {
                    "kind": "tags", "manager": nsx.name,
                    "body": {"display_name": vm.get(F_DISPLAY_NAME, ""),
                             "external_id": ext,
                             "tags": sorted("{}={}".format(s, t)
                                            for s, t in tags_of(vm))}}
                counts["tags"] += 1

    return {
        "manifest": {
            "taken": utc_now_iso(),
            "tool_version": VERSION,
            "domain": domain,
            "managers": sorted(s.name for s in sessions),
            "with_tags": bool(with_tags),
            "counts": counts,
        },
        "objects": objects,
        "provenance": provenance,
    }


# === STORAGE ===
def _write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def _object_file(root, entry, path):
    """Where one object's file lives in the tree."""
    kind = entry["kind"]
    manager = _safe(entry["manager"])
    body = entry["body"]
    if kind == "groups":
        return os.path.join(root, "groups", manager,
                            _safe(body.get(F_ID) or path) + ".json")
    if kind == "policies":
        return os.path.join(root, "policies", manager,
                            _safe(body.get(F_ID) or path), "_policy.json")
    if kind == "rules":
        # .../security-policies/<pid>/rules/<rid>
        parts = path.split("/security-policies/", 1)
        policy_id = parts[1].split("/")[0] if len(parts) > 1 else "unknown"
        return os.path.join(root, "policies", manager, _safe(policy_id),
                            "rules", _safe(body.get(F_ID) or path) + ".json")
    if kind == "tags":
        return os.path.join(root, "tags", manager,
                            _safe(body.get("external_id") or path) + ".json")
    return os.path.join(root, "other", manager, _safe(path) + ".json")


def default_snapshot_name(domain="default"):
    return "{}_{}".format(_safe(domain), local_stamp())


def save_snapshot(snapshot, name=None, root_dir=None):
    """Write the tree. Returns its root directory."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    name = _safe(name or default_snapshot_name(
        snapshot["manifest"].get("domain", "default")))
    root = os.path.join(root_dir, name)

    manifest = dict(snapshot["manifest"])
    manifest["name"] = name
    manifest["paths"] = {}

    for path, entry in snapshot["objects"].items():
        target = _object_file(root, entry, path)
        # Only the config goes in the object file. Provenance rides in the
        # manifest instead: _revision and _last_modified_time move when nothing
        # real changed, and putting them here would make every `git diff` noisy
        # -- the exact failure this whole design exists to avoid.
        _write_json(target, entry["body"])
        record = {"kind": entry["kind"], "manager": entry["manager"],
                  "file": os.path.relpath(target, root).replace(os.sep, "/")}
        prov = snapshot.get("provenance", {}).get(path)
        if prov:
            record["provenance"] = prov
        manifest["paths"][path] = record

    _write_json(os.path.join(root, MANIFEST), manifest)
    return root


def load_snapshot(root):
    """Read a tree back into the same shape capture_snapshot produces."""
    manifest_path = os.path.join(root, MANIFEST)
    if not os.path.isfile(manifest_path):
        raise NsxError(
            "{} is not a snapshot (no {}).".format(root, MANIFEST))
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except ValueError as e:
        raise NsxError("{} is corrupt: {}".format(manifest_path, e)) from e

    objects, provenance = {}, {}
    for path, meta in (manifest.get("paths") or {}).items():
        target = os.path.join(root, meta["file"].replace("/", os.sep))
        if not os.path.isfile(target):
            raise NsxError(
                "snapshot {} is incomplete: {} is missing".format(
                    root, meta["file"]))
        with open(target, encoding="utf-8") as f:
            payload = json.load(f)
        objects[path] = {"kind": meta["kind"], "manager": meta["manager"],
                         "body": payload}
        if meta.get("provenance"):
            provenance[path] = meta["provenance"]
    return {"manifest": manifest, "objects": objects, "provenance": provenance}


def list_snapshots(root_dir=None):
    """Every snapshot under root_dir, newest first."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    if not os.path.isdir(root_dir):
        return []
    found = []
    for name in sorted(os.listdir(root_dir)):
        candidate = os.path.join(root_dir, name)
        manifest_path = os.path.join(candidate, MANIFEST)
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
        except (ValueError, OSError):
            continue
        found.append({"name": name, "root": candidate,
                      "taken": manifest.get("taken", ""),
                      "domain": manifest.get("domain", ""),
                      "counts": manifest.get("counts", {}),
                      "managers": manifest.get("managers", [])})
    found.sort(key=lambda item: item["taken"], reverse=True)
    return found


def resolve_snapshot(name_or_path, root_dir=None):
    """Accept a snapshot name or a directory path. Newest wins for None."""
    root_dir = root_dir or DEFAULT_SNAPSHOT_DIR
    if name_or_path:
        if os.path.isdir(name_or_path):
            return name_or_path
        candidate = os.path.join(root_dir, _safe(name_or_path))
        if os.path.isdir(candidate):
            return candidate
        raise NsxError("No snapshot named '{}' in {}".format(
            name_or_path, root_dir))
    existing = list_snapshots(root_dir)
    if not existing:
        raise NsxError(
            "No snapshots yet in {}. Take one first: nsxctl snapshot "
            "save".format(root_dir))
    return existing[0]["root"]


def describe_snapshot(snapshot):
    manifest = snapshot["manifest"]
    counts = manifest.get("counts", {})
    say("  Taken    : {}".format(manifest.get("taken", "?")))
    say("  Domain   : {}".format(manifest.get("domain", "?")))
    say("  Managers : {}".format(", ".join(manifest.get("managers", []))))
    say("  Objects  : {}".format(", ".join(
        "{} {}".format(v, k) for k, v in sorted(counts.items()) if v)))


# ==========================================================================
# sinks.py  --  Machine-readable outputs, and the state that makes a scheduled run quiet.
# ==========================================================================

STATE_DIR = os.path.join(DATA_DIR, "state")

# Every severity vocabulary in the toolkit, mapped onto the two that machine
# formats understand. Anything unrecognised is a warning: under-reporting a
# finding is worse than over-reporting one.
SARIF_LEVELS = {
    "critical": "error", "high": "error", "security": "error",
    "missing": "error", "medium": "warning", "degraded": "warning",
    "low": "note", "cosmetic": "note", "ok": "none", "n/a": "none",
}
FAILING_SEVERITIES = frozenset({"critical", "high", "security", "missing",
                                "medium", "degraded"})

WEBHOOK_TIMEOUT = 10.0


def sarif_level(severity):
    return SARIF_LEVELS.get(str(severity).lower(), "warning")


def is_failing(severity):
    return str(severity).lower() in FAILING_SEVERITIES


# === FINDINGS ===
def make_finding(check, severity, message, where="", passed=False, detail=""):
    """One machine-readable finding. A plain dict on purpose: it is written to
    four formats and posted to a fifth, and none of them want an object."""
    return {"check": str(check), "severity": str(severity),
            "message": str(message), "where": str(where),
            "passed": bool(passed), "detail": str(detail)}


def summarise_findings(findings):
    counts = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return counts


# === JUNIT ===
def _xml_attr(value):
    return saxutils.quoteattr(str(value))


def _xml_text(value):
    return saxutils.escape(str(value))


def render_junit(suites):
    """suites: {suite name: [finding, ...]}.

    A passing check still emits a testcase. A suite with no testcases at all
    reads in most CI UIs as "did not run", which is exactly the wrong thing to
    show for a clean estate.
    """
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>"]
    for name in sorted(suites):
        items = suites[name]
        failures = sum(1 for f in items if not f["passed"])
        parts.append(
            '  <testsuite name={} tests="{}" failures="{}" timestamp={}>'
            .format(_xml_attr(name), len(items) or 1, failures,
                    _xml_attr(utc_now_iso())))
        if not items:
            parts.append(
                '    <testcase classname={} name="no findings"/>'.format(
                    _xml_attr(name)))
        for item in items:
            case = '    <testcase classname={} name={}'.format(
                _xml_attr(name),
                _xml_attr("{}: {}".format(item["check"], item["where"])
                          if item["where"] else item["check"]))
            if item["passed"]:
                parts.append(case + "/>")
                continue
            parts.append(case + ">")
            parts.append(
                '      <failure type={} message={}>{}</failure>'.format(
                    _xml_attr(item["severity"]), _xml_attr(item["message"]),
                    _xml_text(item["detail"] or item["message"])))
            parts.append("    </testcase>")
        parts.append("  </testsuite>")
    parts.append("</testsuites>")
    return "\n".join(parts) + "\n"


# === SARIF ===
def render_sarif(findings, tool_name=TOOL_NAME, version=VERSION):
    """SARIF 2.1.0. Rules are deduplicated by check name so a UI groups them."""
    rules, seen = [], {}
    for item in findings:
        if item["check"] in seen:
            continue
        seen[item["check"]] = len(rules)
        rules.append({
            "id": item["check"],
            "shortDescription": {"text": item["check"].replace("_", " ")},
            "defaultConfiguration": {"level": sarif_level(item["severity"])},
        })
    results = []
    for item in findings:
        if item["passed"]:
            continue
        results.append({
            "ruleId": item["check"],
            "ruleIndex": seen[item["check"]],
            "level": sarif_level(item["severity"]),
            "message": {"text": item["detail"] or item["message"]},
            "properties": {"severity": item["severity"],
                           "object": item["where"]},
            # NSX objects are not files, so the "location" is the object path.
            # Emitting a fake file location would make a UI offer to open it.
            "locations": [{"logicalLocations": [
                {"fullyQualifiedName": item["where"] or item["check"],
                 "kind": "resource"}]}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": version,
                                "rules": rules}},
            "results": results,
        }],
    }, indent=2) + "\n"


# === PROMETHEUS ===
def _metric_name(text):
    cleaned = "".join(c if c.isalnum() else "_" for c in str(text).lower())
    return cleaned.strip("_") or "unknown"


def render_metrics(command, findings, extra=None, prefix="nsxctl"):
    """Prometheus textfile format, for a node_exporter collector directory.

    One gauge per severity plus a run timestamp, which is what an alert rule
    needs: "critical findings above zero" and "this check has not run today"
    are both real alerts, and the second one is the one people forget.
    """
    counts = summarise_findings([f for f in findings if not f["passed"]])
    lines = [
        "# HELP {}_findings Findings by severity from the last run.".format(
            prefix),
        "# TYPE {}_findings gauge".format(prefix),
    ]
    for severity in sorted(counts):
        lines.append('{}_findings{{command="{}",severity="{}"}} {}'.format(
            prefix, _metric_name(command), _metric_name(severity),
            counts[severity]))
    if not counts:
        lines.append('{}_findings{{command="{}",severity="none"}} 0'.format(
            prefix, _metric_name(command)))
    lines.extend([
        "# HELP {}_last_run_timestamp_seconds When this command last "
        "completed.".format(prefix),
        "# TYPE {}_last_run_timestamp_seconds gauge".format(prefix),
        '{}_last_run_timestamp_seconds{{command="{}"}} {}'.format(
            prefix, _metric_name(command), int(time.time())),
    ])
    for key, value in sorted((extra or {}).items()):
        lines.extend([
            "# TYPE {}_{} gauge".format(prefix, _metric_name(key)),
            '{}_{}{{command="{}"}} {}'.format(
                prefix, _metric_name(key), _metric_name(command), value),
        ])
    return "\n".join(lines) + "\n"


# === WRITING ===
def write_text(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Written whole then moved, so a collector never reads half a file.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    return path


# === WEBHOOK ===
def post_webhook(url, payload, timeout=WEBHOOK_TIMEOUT):
    """POST a JSON summary. Returns the status code.

    Deliberately stdlib-only and deliberately not retried: a notification that
    silently retries into a chat channel is how one failing check becomes
    forty messages. One attempt, and the failure is reported.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NsxError(
            "Webhook URL must be http or https (got {!r}).".format(url))
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "{}/{}".format(TOOL_NAME.replace(" ", "-"),
                                              VERSION)})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as e:
        raise NsxError("Webhook returned HTTP {}.".format(e.code)) from e
    except (urllib.error.URLError, OSError) as e:
        raise NsxError("Webhook could not be reached: {}".format(e)) from e


def webhook_payload(command, findings, changed, profile=None, project=None):
    counts = summarise_findings([f for f in findings if not f["passed"]])
    worst = ""
    for severity in ("critical", "security", "missing", "high", "medium",
                     "degraded", "low", "cosmetic"):
        if counts.get(severity):
            worst = severity
            break
    return {
        "tool": TOOL_NAME, "version": VERSION, "command": command,
        "timestamp": utc_now_iso(), "profile": profile or "",
        "project": project or "", "changed_since_last_run": bool(changed),
        "total": sum(counts.values()), "worst_severity": worst,
        "counts": counts,
        "findings": [f for f in findings if not f["passed"]][:50],
    }


# === RUN STATE ===
def fingerprint(findings):
    """A stable hash of what the run found.

    Sorted and built only from what a finding *is*, never from when it ran or
    how long it took -- otherwise every run differs from the last and
    "quiet unless changed" is never quiet.
    """
    material = sorted(
        "{}|{}|{}|{}".format(f["check"], f["severity"], f["where"],
                             f["message"])
        for f in findings if not f["passed"])
    digest = hashlib.sha256("\n".join(material).encode("utf-8")).hexdigest()
    return digest


def state_path(command, profile=None, project=None, root=None):
    safe = "".join(c if c.isalnum() else "_"
                   for c in "{}_{}_{}".format(command, profile or "default",
                                              project or "infra"))
    return os.path.join(root or STATE_DIR, safe[:100] + ".json")


def load_state(command, profile=None, project=None, root=None):
    try:
        with open(state_path(command, profile, project, root),
                  encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(command, digest, counts, profile=None, project=None, root=None):
    path = state_path(command, profile, project, root)
    try:
        write_text(path, json.dumps({
            "command": command, "fingerprint": digest, "counts": counts,
            "last_run": utc_now_iso()}, indent=2, sort_keys=True) + "\n")
    except OSError as e:
        debug("could not write run state {}: {}".format(path, e))
        return None
    return path


def changed_since_last(command, findings, profile=None, project=None,
                       root=None):
    """(changed, previous_state). A first run always counts as changed."""
    digest = fingerprint(findings)
    previous = load_state(command, profile, project, root)
    if not previous:
        return True, {}
    return previous.get("fingerprint") != digest, previous


# ==========================================================================
# diff.py  --  Comparing two configuration snapshots.
# ==========================================================================

# Membership matters; order does not.
SET_LIKE_FIELDS = frozenset({
    "source_groups", "destination_groups", "services", "scope", "profiles",
})

# The only fields whose change cannot alter what traffic is permitted.
COSMETIC_FIELDS = frozenset({"display_name", "description", "notes"})

DRIFT_LEVELS = ("security", "cosmetic")

DRIFT_HEADERS = ["status", "impact", "kind", "manager", "object", "field",
                 "before", "after", "changed_by", "changed_at"]


class FieldChange:
    __slots__ = ("field", "before", "after", "kind")

    def __init__(self, field, before, after, kind="changed"):
        self.field = field
        self.before = before
        self.after = after
        self.kind = kind

    @property
    def impact(self):
        """security or cosmetic, decided by the outermost field name."""
        root = self.field.split(".", 1)[0].split("[", 1)[0]
        return "cosmetic" if root in COSMETIC_FIELDS else "security"

    def __repr__(self):
        return "FieldChange({!r}, {!r} -> {!r})".format(
            self.field, self.before, self.after)


class ObjectChange:
    __slots__ = ("status", "path", "kind", "manager", "name", "fields",
                 "provenance")

    def __init__(self, status, path, kind, manager, name, fields=(),
                 provenance=None):
        self.status = status          # added | removed | modified
        self.path = path
        self.kind = kind
        self.manager = manager
        self.name = name
        self.fields = list(fields)
        self.provenance = provenance or {}

    @property
    def impact(self):
        """An added or removed object is always security-relevant: it changes
        what rules exist. A modified one inherits the worst of its fields."""
        if self.status in ("added", "removed"):
            return "security"
        return ("security" if any(f.impact == "security" for f in self.fields)
                else "cosmetic")

    @property
    def changed_by(self):
        return self.provenance.get("_last_modified_user", "")

    @property
    def changed_at(self):
        return self.provenance.get("_last_modified_time", "")


def fmt_diff_value(value):
    """One field value as a single line, for a table cell."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return "; ".join("{}={}".format(k, value[k]) for k in sorted(value))
    return str(value)


def _diff_set(field, before, after):
    """Membership comparison: report what joined and what left."""
    a, b = set(map(str, before)), set(map(str, after))
    if a == b:
        return []
    changes = []
    added, removed = sorted(b - a), sorted(a - b)
    if added:
        changes.append(FieldChange(field, None, added, "added"))
    if removed:
        changes.append(FieldChange(field, removed, None, "removed"))
    return changes


def _diff_sequence(field, before, after):
    """Order-sensitive comparison, recursing into nested objects."""
    changes = []
    for index in range(max(len(before), len(after))):
        item_field = "{}[{}]".format(field, index)
        if index >= len(before):
            changes.append(FieldChange(item_field, None, after[index], "added"))
        elif index >= len(after):
            changes.append(FieldChange(item_field, before[index], None,
                                       "removed"))
        else:
            changes.extend(_diff_value(item_field, None, before[index],
                                       after[index]))
    return changes


def _diff_value(field, key, before, after):
    if isinstance(before, dict) and isinstance(after, dict):
        return diff_objects(before, after, prefix=field)
    if isinstance(before, list) and isinstance(after, list):
        if key in SET_LIKE_FIELDS:
            return _diff_set(field, before, after)
        return _diff_sequence(field, before, after)
    if before != after:
        return [FieldChange(field, before, after, "changed")]
    return []


def diff_objects(before, after, prefix=""):
    """Field-level changes between two objects, recursing into nesting."""
    changes = []
    for key in sorted(set(before) | set(after)):
        field = "{}.{}".format(prefix, key) if prefix else key
        if key not in before:
            changes.append(FieldChange(field, None, after[key], "added"))
        elif key not in after:
            changes.append(FieldChange(field, before[key], None, "removed"))
        else:
            changes.extend(_diff_value(field, key, before[key], after[key]))
    return changes


def diff_snapshots(before, after):
    """Every object that differs between two snapshots.

    Unchanged objects are omitted: the caller gets counts from
    summarise_diff() and does not need a row per identical rule.
    """
    old_objects = before.get("objects") or {}
    new_objects = after.get("objects") or {}
    new_provenance = after.get("provenance") or {}
    old_provenance = before.get("provenance") or {}

    changes = []
    for path in sorted(set(old_objects) | set(new_objects)):
        old = old_objects.get(path)
        new = new_objects.get(path)
        entry = new or old
        name = (entry["body"].get(F_DISPLAY_NAME)
                or entry["body"].get("id") or path)

        if old is None:
            changes.append(ObjectChange(
                "added", path, entry["kind"], entry["manager"], name,
                provenance=new_provenance.get(path)))
        elif new is None:
            changes.append(ObjectChange(
                "removed", path, entry["kind"], entry["manager"], name,
                provenance=old_provenance.get(path)))
        else:
            fields = diff_objects(old["body"], new["body"])
            if fields:
                changes.append(ObjectChange(
                    "modified", path, entry["kind"], entry["manager"], name,
                    fields=fields, provenance=new_provenance.get(path)))

    # Security-relevant first, then by kind and name: the reader should meet
    # the dangerous change before the renamed policy.
    changes.sort(key=lambda c: (c.impact != "security", c.status, c.kind,
                                str(c.name)))
    return changes


def summarise_diff(changes):
    counts = {"added": 0, "removed": 0, "modified": 0,
              "security": 0, "cosmetic": 0}
    for change in changes:
        counts[change.status] = counts.get(change.status, 0) + 1
        counts[change.impact] = counts.get(change.impact, 0) + 1
    return counts


def diff_rows(changes):
    """Export rows: one per changed field, one per added/removed object."""
    rows = []
    for change in changes:
        if not change.fields:
            rows.append([change.status, change.impact, change.kind,
                         change.manager, change.name, "", "", "",
                         change.changed_by, str(change.changed_at)])
            continue
        for field in change.fields:
            rows.append([change.status, field.impact, change.kind,
                         change.manager, change.name, field.field,
                         fmt_diff_value(field.before), fmt_diff_value(field.after),
                         change.changed_by, str(change.changed_at)])
    return rows


def drift_findings(changes):
    """Object changes as machine-readable findings.

    Severity is the impact the diff engine already computed, so a scheduled
    drift check reports a new any-any rule as an error and a rename as a note
    without a second classification anybody could get out of step.
    """
    out = []
    for change in changes:
        fields = ", ".join(sorted({f.field for f in change.fields})) or \
            change.status
        out.append(make_finding(
            "drift_{}".format(change.status), change.impact,
            "{} {} {}".format(change.status, change.kind, change.name),
            where="{}/{}".format(change.manager, change.name),
            detail="{}  changed by {} {}".format(
                fields, change.changed_by or "unknown",
                change.changed_at or "")))
    return out


def at_impact(changes, level):
    """Changes at or above an impact level, for --fail-on-drift."""
    if level == "any":
        return list(changes)
    if level == "security":
        return [c for c in changes if c.impact == "security"]
    return []


# ==========================================================================
# authoring.py  --  Creating and changing groups, policies and rules.
# ==========================================================================

# What a planned write does. `delete` carries a before-body and no after;
# `create` carries an after and no before. Undo reads the direction off that
# rather than a separate flag that could get out of step.
OP_CREATE, OP_MODIFY, OP_DELETE = "create", "modify", "delete"

KIND_GROUP, KIND_RULE, KIND_POLICY = "group", "rule", "policy"

# NSX answers this when the _revision sent does not match the stored one.
HTTP_PRECONDITION_FAILED = 412

RULE_ACTIONS = ("ALLOW", "DROP", "REJECT", "JUMP_TO_APPLICATION")
RULE_DIRECTIONS = ("IN", "OUT", "IN_OUT")


# === CRITERIA MINI-LANGUAGE ===
#   tag:env=prod                 Tag env equals prod
#   tag:env~pro                  Tag env contains pro
#   name=web-01                  VM name equals
#   name~web                     VM name contains
#   ip:10.0.0.0/8,10.1.2.3       an IP address set
# joined by AND or OR.
CRITERIA_HELP = (
    "criteria syntax:\n"
    "  tag:SCOPE=VALUE     tag equals          tag:env=prod\n"
    "  tag:SCOPE~VALUE     tag contains        tag:owner~platform\n"
    "  name=VALUE          VM name equals      name=web-prod-01\n"
    "  name~VALUE          VM name contains    name~web-\n"
    "  ip:A[,B...]         IP addresses/CIDRs  ip:10.0.0.0/8\n"
    "joined with AND or OR, e.g.\n"
    "  'tag:env=prod AND tag:tier=web'")

OP_EQUALS, OP_CONTAINS = "EQUALS", "CONTAINS"
MEMBER_VM = "VirtualMachine"


def _condition(key, operator, value):
    return {RT: RT_CONDITION, "member_type": MEMBER_VM, "key": key,
            "operator": operator, "value": value}


def _parse_term(term):
    """One criteria term into an NSX expression element."""
    text = term.strip()
    if not text:
        raise ConfigError("Empty criteria term.\n" + CRITERIA_HELP)
    lowered = text.lower()

    if lowered.startswith("ip:"):
        addresses = [a.strip() for a in text[3:].split(",") if a.strip()]
        if not addresses:
            raise ConfigError("ip: needs at least one address.\n" + CRITERIA_HELP)
        return {RT: RT_IPADDRESS, "ip_addresses": addresses}

    if lowered.startswith("tag:"):
        body = text[4:]
        scope, operator, value = _split_operator(body, "tag:")
        # NSX stores a scoped tag as "<scope>|<tag>" in a single Condition
        # value, which is why the toolkit renders it that way everywhere.
        return _condition(KEY_TAG, operator,
                          "{}{}{}".format(scope, TAG_SCOPE_SEPARATOR, value))

    if lowered.startswith("name"):
        _, operator, value = _split_operator("name" + text[4:], "name")
        return _condition("Name", operator, value)

    raise ConfigError(
        "Could not read criteria term '{}'.\n{}".format(term, CRITERIA_HELP))


def _split_operator(body, label):
    """('env', 'EQUALS', 'prod') from 'env=prod'."""
    for token, operator in (("~", OP_CONTAINS), ("=", OP_EQUALS)):
        if token in body:
            left, _, right = body.partition(token)
            left = left.strip()
            right = right.strip()
            if label == "name":
                left = ""
            if not right or (label != "name" and not left):
                break
            return left, operator, right
    raise ConfigError(
        "'{}' needs an = or ~ and a value.\n{}".format(body, CRITERIA_HELP))


def _tokenise_criteria(text):
    """Split on AND/OR, keeping the operators."""
    tokens, current = [], []
    for word in str(text).split():
        if word.upper() in ("AND", "OR"):
            tokens.append(" ".join(current).strip())
            tokens.append(word.upper())
            current = []
        else:
            current.append(word)
    tokens.append(" ".join(current).strip())
    return tokens


def parse_criteria(text):
    """A criteria string into an NSX `expression` list.

    Refuses a mixed AND/OR expression rather than sending it: NSX evaluates a
    single conjunction operator per expression level, and a silently
    reinterpreted expression selects the wrong workloads -- which for a
    firewall group is the whole ballgame.
    """
    if not str(text or "").strip():
        raise ConfigError("No criteria given.\n" + CRITERIA_HELP)
    tokens = _tokenise_criteria(text)
    expression = []
    conjunctions = set()
    expect_term = True
    for token in tokens:
        if token in ("AND", "OR"):
            if expect_term:
                raise ConfigError(
                    "'{}' where a criteria term was expected.\n{}".format(
                        token, CRITERIA_HELP))
            conjunctions.add(token)
            expression.append({RT: RT_CONJUNCTION,
                               "conjunction_operator": token})
            expect_term = True
            continue
        if not expect_term:
            raise ConfigError(
                "Two criteria terms with no AND or OR between them, at "
                "'{}'.\n{}".format(token, CRITERIA_HELP))
        expression.append(_parse_term(token))
        expect_term = False
    if expect_term:
        raise ConfigError("Criteria ends with a conjunction.\n" + CRITERIA_HELP)
    if len(conjunctions) > 1:
        raise ConfigError(
            "Criteria mixes AND and OR. NSX applies one conjunction operator "
            "per expression, so this would not mean what it reads as. Split "
            "it into two groups, or use one operator throughout.")
    return expression


def describe_criteria(expression):
    """The inverse, near enough for an echo of what was parsed."""
    parts = []
    for item in expression or []:
        kind = item.get(RT)
        if kind == RT_CONJUNCTION:
            parts.append(item.get("conjunction_operator", "?"))
        elif kind == RT_IPADDRESS:
            parts.append("ip:" + ",".join(item.get("ip_addresses", [])))
        elif kind == RT_CONDITION:
            token = "~" if item.get("operator") == OP_CONTAINS else "="
            value = str(item.get("value", ""))
            if item.get("key") == KEY_TAG and TAG_SCOPE_SEPARATOR in value:
                scope, _, tag = value.partition(TAG_SCOPE_SEPARATOR)
                parts.append("tag:{}{}{}".format(scope, token, tag))
            else:
                parts.append("name{}{}".format(token, value))
        else:
            parts.append(str(kind))
    return " ".join(parts)


# === REFERENCE RESOLUTION ===
def reference_index(objects):
    """{name, id and path -> path} so a user can name a group any of those ways."""
    index = {}
    for path, body in objects.items():
        for key in (body.get(F_DISPLAY_NAME), body.get(F_ID), path):
            if key:
                index.setdefault(str(key).lower(), path)
    return index


def resolve_reference(index, ref, what="group"):
    """One user-supplied group or service name into an NSX path."""
    text = str(ref).strip()
    if text.upper() == ANY:
        return ANY
    hit = index.get(text.lower())
    if hit:
        return hit
    raise NsxError(
        "No {} called '{}'. Check the name, or pass its path.".format(
            what, ref))


def resolve_references(index, refs, what="group"):
    if not refs:
        return [ANY]
    return [resolve_reference(index, ref, what) for ref in refs]


def service_inventory(sessions, domain):
    """{service path: service} across every manager, GM first."""
    gm_sessions, lm_sessions = ordered_sessions(sessions)
    index = {}
    for nsx in gm_sessions + lm_sessions:
        try:
            for service in nsx.get_all(p_services(nsx.base(domain))):
                path = service.get(F_PATH)
                if path and path not in index:
                    index[path] = service
        except NsxError:
            continue
    return index


# === BODY CONSTRUCTION ===
def build_group_body(group_id, display_name, expression, description=None,
                     existing=None):
    """A group body, preserving whatever of the live object we do not set.

    Starting from the live body rather than an empty dict is what stops a
    modify from silently dropping fields this release does not know about --
    a PUT replaces the object, so anything omitted is deleted.
    """
    body = dict(existing or {})
    body[F_ID] = group_id
    body[F_DISPLAY_NAME] = display_name or group_id
    if expression is not None:
        body[F_EXPRESSION] = expression
    if description is not None:
        body["description"] = description
    return body


def build_rule_body(rule_id, display_name=None, sources=None, destinations=None,
                    services=None, action=None, scope=None, direction=None,
                    disabled=None, logged=None, sequence_number=None,
                    description=None, existing=None):
    """A rule body, same preserve-what-we-do-not-set rule as groups."""
    body = dict(existing or {})
    body[F_ID] = rule_id
    if display_name is not None or not body.get(F_DISPLAY_NAME):
        body[F_DISPLAY_NAME] = display_name or rule_id
    if sources is not None:
        body[F_SOURCE_GROUPS] = list(sources)
    if destinations is not None:
        body[F_DEST_GROUPS] = list(destinations)
    if services is not None:
        body[F_SERVICES] = list(services)
    if scope is not None:
        body[F_SCOPE] = list(scope)
    if action is not None:
        body[F_ACTION_FIELD] = action
    if direction is not None:
        body["direction"] = direction
    if disabled is not None:
        body["disabled"] = bool(disabled)
    if logged is not None:
        body["logged"] = bool(logged)
    if sequence_number is not None:
        body[F_SEQUENCE_NUMBER] = int(sequence_number)
    if description is not None:
        body["description"] = description
    body.setdefault(F_SOURCE_GROUPS, [ANY])
    body.setdefault(F_DEST_GROUPS, [ANY])
    body.setdefault(F_SERVICES, [ANY])
    body.setdefault(F_SCOPE, [ANY])
    body.setdefault(F_ACTION_FIELD, "ALLOW")
    return body


def validate_action(action):
    if action and str(action).upper() not in RULE_ACTIONS:
        raise ConfigError("action must be one of {} (got {!r}).".format(
            " | ".join(RULE_ACTIONS), action))
    return str(action).upper() if action else None


def validate_direction(direction):
    if direction and str(direction).upper() not in RULE_DIRECTIONS:
        raise ConfigError("direction must be one of {} (got {!r}).".format(
            " | ".join(RULE_DIRECTIONS), direction))
    return str(direction).upper() if direction else None


# === PLANNED WRITES ===
class PlannedWrite:
    """One create, modify or delete, with both sides of it."""

    __slots__ = ("op", "kind", "nsx", "url", "path", "object_id", "policy_id",
                 "name", "before", "after")

    def __init__(self, op, kind, nsx, url, object_id, name, before=None,
                 after=None, policy_id=None, path=""):
        self.op = op
        self.kind = kind
        self.nsx = nsx
        self.url = url
        self.object_id = object_id
        self.policy_id = policy_id
        self.name = name
        self.before = before
        self.after = after
        self.path = path or (before or after or {}).get(F_PATH, "")

    @property
    def manager(self):
        return self.nsx.name if self.nsx is not None else ""

    def describe(self):
        return "{} {} '{}'".format(self.op, self.kind, self.name)


def object_url(nsx, domain, kind, object_id, policy_id=None):
    base = nsx.base(domain)
    if kind == KIND_GROUP:
        return p_group(base, domain, object_id)
    if kind == KIND_POLICY:
        return p_sec_policy(base, domain, object_id)
    if kind == KIND_RULE:
        return p_sec_rule(base, domain, policy_id, object_id)
    raise NsxError("Unknown object kind '{}'.".format(kind))


def read_object(nsx, domain, kind, object_id, policy_id=None):
    """The live object, or None when it does not exist yet."""
    try:
        return nsx.get(object_url(nsx, domain, kind, object_id,
                                  policy_id=policy_id))
    except NsxHttpError as e:
        if e.status == 404:
            return None
        raise


def apply_write(change, domain, force=False):
    """Execute one planned write, with NSX's own concurrency check.

    The `_revision` read at plan time rides back with the body. NSX rejects a
    stale one with 412, which is the difference between "your write failed"
    and "somebody else changed this while you were looking at it" -- and only
    the second one is worth a specific message.
    """
    nsx = change.nsx
    if change.op == OP_DELETE:
        nsx.delete(change.url)
        return None
    body = dict(change.after or {})
    revision = (change.before or {}).get(F_REVISION)
    if revision is not None and not force:
        body[F_REVISION] = revision
    else:
        body.pop(F_REVISION, None)
    try:
        return nsx.put(change.url, body=body)
    except NsxHttpError as e:
        if e.status == HTTP_PRECONDITION_FAILED:
            raise NsxError(
                "{} changed on NSX since the plan was built, so the write was "
                "refused rather than overwriting somebody else's change. "
                "Re-run to plan against the current state, or pass --force to "
                "write anyway.".format(change.describe())) from e
        raise


# === SEQUENCE NUMBERS ===
def sequence_for_move(records, target, before=True):
    """A sequence number that puts a rule immediately before or after another.

    Refuses rather than renumbering the policy: rewriting every rule's
    sequence number to make room is a much bigger change than the one that
    was asked for, and on a shared policy it is other people's diff too.
    """
    ordered = sorted(records, key=rule_sequence)
    index = next((i for i, r in enumerate(ordered)
                  if r.rule_id == target.rule_id), None)
    if index is None:
        raise NsxError("'{}' is not in this policy.".format(target.rule_name))
    target_seq = rule_sequence(target)
    if before:
        neighbour = rule_sequence(ordered[index - 1]) if index > 0 else \
            target_seq - 20
        low, high = neighbour, target_seq
    else:
        neighbour = (rule_sequence(ordered[index + 1])
                     if index + 1 < len(ordered) else target_seq + 20)
        low, high = target_seq, neighbour
    candidate = (low + high) // 2
    if candidate <= low or candidate >= high:
        raise NsxError(
            "No sequence number is free between {} and {}. The policy needs "
            "renumbering first -- this will not rewrite every rule's sequence "
            "to make room.".format(low, high))
    return candidate


# === DECLARATIVE CHANGE FILES ===
CHANGE_SECTIONS = ("groups", "rules")
STATE_PRESENT, STATE_ABSENT = "present", "absent"


def load_change_file(path):
    """A declarative change file. JSON always; YAML when PyYAML is installed.

    Same rule as the taxonomy: JSON is used everywhere so nothing needs
    installing, and YAML is accepted if it happens to be available.
    """
    if not os.path.isfile(path):
        raise ConfigError("Not found: {}".format(path))
    with open(path, encoding="utf-8") as f:
        text = f.read()
    data = None
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise ConfigError(
                "{} is YAML and PyYAML is not installed. Convert it to JSON, "
                "or pip install PyYAML.".format(path)) from None
        try:
            data = yaml.safe_load(text)
        except Exception as e:
            raise ConfigError("{} is not valid YAML: {}".format(path, e)) from e
    else:
        try:
            data = json.loads(text)
        except ValueError as e:
            raise ConfigError("{} is not valid JSON: {}".format(path, e)) from e

    if not isinstance(data, dict):
        raise ConfigError(
            "{} must be a mapping with 'groups' and/or 'rules'.".format(path))
    unknown = set(data) - set(CHANGE_SECTIONS)
    if unknown:
        raise ConfigError("{}: unknown section(s) {}. Expected {}.".format(
            path, ", ".join(sorted(unknown)), " and ".join(CHANGE_SECTIONS)))
    for section in CHANGE_SECTIONS:
        raw = data.get(section)
        if raw is not None and not isinstance(raw, list):
            raise ConfigError("{}: '{}' must be a list.".format(path, section))
        entries = raw or []
        for index, entry in enumerate(entries, 1):
            if not isinstance(entry, dict):
                raise ConfigError("{}: {}[{}] must be a mapping.".format(
                    path, section, index))
            if not entry.get("id"):
                raise ConfigError("{}: {}[{}] has no 'id'.".format(
                    path, section, index))
            state = str(entry.get("state", STATE_PRESENT)).lower()
            if state not in (STATE_PRESENT, STATE_ABSENT):
                raise ConfigError(
                    "{}: {}[{}] state must be {} or {}.".format(
                        path, section, index, STATE_PRESENT, STATE_ABSENT))
    return data


# ==========================================================================
# flows.py  --  Observed flows into a proposed ruleset.
# ==========================================================================

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


# ==========================================================================
# namecache.py  --  Cached object names, so shell completion never blocks on NSX.
# ==========================================================================

CACHE_DIR = os.path.join(DATA_DIR, "completion")

# Kinds of name worth completing. Each maps to one argument the CLI takes.
KIND_GROUP = "groups"
KIND_POLICY = "policies"
KIND_SERVICE = "services"
KIND_RULE = "rules"
KIND_MANAGER = "managers"
KIND_PROFILE = "profiles"

CACHE_KINDS = (KIND_GROUP, KIND_POLICY, KIND_SERVICE, KIND_RULE,
               KIND_MANAGER, KIND_PROFILE)

# Beyond this the cache is reported as stale. Nothing refuses to use it --
# stale names are still better than no completion -- but `completion cache`
# and `doctor` can say so.
STALE_AFTER_SECONDS = 24 * 3600

_SAFE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."


def _slug(text):
    cleaned = "".join(c if c in _SAFE else "_" for c in str(text or "default"))
    return cleaned[:60] or "default"


def cache_path(profile=None, project=None, root=None):
    """One cache file per estate and tenant.

    Keyed that way because a group name in production and the same name in DR
    are different objects, and completing one into the other is a mistake the
    shell would make silently.
    """
    name = "{}__{}.json".format(_slug(profile or "default"),
                                _slug(project or "infra"))
    return os.path.join(root or CACHE_DIR, name)


def load_cache(profile=None, project=None, root=None):
    """The cached names, or an empty cache. Never raises.

    Completion runs inside a shell hook where a traceback would be printed
    over the user's prompt, so every failure here is silent and empty.
    """
    path = cache_path(profile, project, root)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"written": 0, "names": {}}
    if not isinstance(data, dict):
        return {"written": 0, "names": {}}
    names = data.get("names")
    if not isinstance(names, dict):
        names = {}
    return {"written": data.get("written", 0), "names": names}


def save_cache(names, profile=None, project=None, root=None):
    """Write the cache. Returns the path, or None if it could not be written.

    A failure here is never fatal: completion degrades to nothing, and the
    command the user actually ran still succeeded.
    """
    path = cache_path(profile, project, root)
    payload = {"written": int(time.time()),
               "profile": profile or "", "project": project or "",
               "names": {k: sorted(set(v)) for k, v in names.items() if v}}
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except OSError:
        return None
    return path


def update_cache(kind, values, profile=None, project=None, root=None):
    """Merge one kind of name into the cache, leaving the others alone.

    Merge rather than replace, because `nsxctl group list --contains web` is a
    filtered view: replacing would shrink the cache to whatever the last
    filtered command happened to return.
    """
    values = [str(v) for v in values if v]
    if not values:
        return None
    cache = load_cache(profile, project, root)
    names = dict(cache["names"])
    names[kind] = sorted(set(names.get(kind, [])) | set(values))
    return save_cache(names, profile, project, root)


def cached_names(kind, profile=None, project=None, root=None):
    return load_cache(profile, project, root)["names"].get(kind, [])


def cache_age(profile=None, project=None, root=None):
    """Seconds since the cache was written, or None if there isn't one."""
    written = load_cache(profile, project, root)["written"]
    if not written:
        return None
    return max(0, int(time.time()) - int(written))


def is_stale(profile=None, project=None, root=None):
    age = cache_age(profile, project, root)
    return age is None or age > STALE_AFTER_SECONDS


def describe_age(seconds):
    if seconds is None:
        return "never written"
    if seconds < 90:
        return "{}s ago".format(seconds)
    if seconds < 5400:
        return "{}m ago".format(seconds // 60)
    if seconds < 172800:
        return "{}h ago".format(seconds // 3600)
    return "{}d ago".format(seconds // 86400)


def refresh_from_nsx(sessions, domain, profile=None, project=None, root=None):
    """Rebuild the cache from live NSX. Returns (path, {kind: count}).

    The one place in this module that touches the network, and it is never
    called from a completion hook -- only from `nsxctl completion cache`, which
    a person ran deliberately.
    """
    names = {KIND_MANAGER: [s.name for s in sessions]}

    groups = group_inventory(sessions, domain)
    names[KIND_GROUP] = sorted({
        str(g.get(F_ID) or "") for _n, g in groups.values()} | {
        str(g.get(F_DISPLAY_NAME) or "") for _n, g in groups.values()})

    gm_sessions, lm_sessions = ordered_sessions(sessions)
    policy_names = set()
    for nsx in gm_sessions + lm_sessions:
        for policy in policies_for(nsx, domain):
            policy_names.add(str(policy.get(F_ID) or ""))
            policy_names.add(str(policy.get(F_DISPLAY_NAME) or ""))
    names[KIND_POLICY] = sorted(policy_names)

    services = service_inventory(sessions, domain)
    names[KIND_SERVICE] = sorted({
        str(s.get(F_ID) or "") for s in services.values()} | {
        str(s.get(F_DISPLAY_NAME) or "") for s in services.values()})

    rule_names = set()
    for record in sweep_rules(sessions, domain):
        rule_names.add(str(record.rule_id or ""))
        rule_names.add(str(record.rule_name or ""))
    names[KIND_RULE] = sorted(rule_names)

    names = {k: [v for v in vals if v] for k, vals in names.items()}
    path = save_cache(names, profile, project, root)
    return path, {k: len(v) for k, v in names.items()}


# ==========================================================================
# report.py  --  Self-contained HTML reports.
# ==========================================================================

STYLE = """
:root {
  --ink: #1a1d21; --muted: #5b6570; --rule: #dfe3e8; --bg: #ffffff;
  --panel: #f6f8fa; --critical: #b3261e; --high: #a5590a;
  --medium: #7a6100; --low: #57606a; --ok: #1a7f37;
}
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; background: var(--bg); color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  Helvetica, Arial, sans-serif; }
.wrap { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 32px 0 10px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--muted); }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
.meta code { background: var(--panel); padding: 1px 5px; border-radius: 3px; }
.notes { background: var(--panel); border-left: 3px solid var(--rule);
  padding: 12px 16px; margin: 0 0 24px; border-radius: 0 4px 4px 0; }
.notes p { margin: 0 0 6px; } .notes p:last-child { margin: 0; }
.tiles { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
.tile { border: 1px solid var(--rule); border-radius: 6px; padding: 12px 18px;
  min-width: 120px; }
.tile .n { font-size: 24px; font-weight: 600; line-height: 1.1; }
.tile .k { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em;
  color: var(--muted); margin-top: 2px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--rule);
  vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--muted); border-bottom: 2px solid var(--rule); white-space: nowrap; }
tbody tr:nth-child(even) { background: var(--panel); }
td.mono, th.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; }
.sev { font-weight: 600; text-transform: uppercase; font-size: 11px;
  letter-spacing: 0.05em; white-space: nowrap; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); }
.soft { color: var(--muted); font-size: 11px; }
.empty { color: var(--ok); font-weight: 600; }
footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--rule);
  color: var(--muted); font-size: 12px; }
@media print {
  body { padding: 0; font-size: 11px; }
  .tile { break-inside: avoid; } tr { break-inside: avoid; }
}
"""

SEVERITY_CLASSES = ("critical", "high", "medium", "low")


def _esc(value):
    return html.escape("" if value is None else str(value))


def _cell(column, value):
    text = _esc(value)
    if column == "severity" and value in SEVERITY_CLASSES:
        return '<td class="sev sev-{}">{}</td>'.format(value, text)
    if column == "confidence" and value == "soft":
        return '<td class="soft">soft</td>'
    if column in ("rule", "policy", "path", "manager"):
        return '<td class="mono">{}</td>'.format(text)
    return "<td>{}</td>".format(text)


def _table(headers, rows):
    if not rows:
        return '<p class="empty">Nothing to report.</p>'
    out = ['<div class="scroll"><table><thead><tr>']
    out.extend("<th>{}</th>".format(_esc(h.replace("_", " "))) for h in headers)
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for i, header in enumerate(headers):
            out.append(_cell(header, row[i] if i < len(row) else ""))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _tiles(counts):
    if not counts:
        return ""
    out = ['<div class="tiles">']
    for key, value in counts:
        out.append('<div class="tile"><div class="n">{}</div>'
                   '<div class="k">{}</div></div>'.format(
                       _esc(value), _esc(key)))
    out.append("</div>")
    return "".join(out)


def write_report(path, title, subtitle="", notes=(), tiles=(), sections=()):
    """Write a standalone HTML report.

    sections: iterable of (heading, headers, rows).
    tiles:    iterable of (label, value) summary counters.
    notes:    iterable of caveat strings shown before the data.
    """
    body = ['<div class="wrap">',
            "<h1>{}</h1>".format(_esc(title))]
    if subtitle:
        body.append('<div class="meta">{}</div>'.format(subtitle))
    if notes:
        body.append('<div class="notes">')
        body.extend("<p>{}</p>".format(_esc(n)) for n in notes)
        body.append("</div>")
    body.append(_tiles(list(tiles)))
    for heading, headers, rows in sections:
        body.append("<h2>{}</h2>".format(_esc(heading)))
        body.append(_table(headers, rows))
    body.append(
        "<footer>Generated by {} v{} &middot; {}</footer>".format(
            _esc(TOOL_NAME), _esc(VERSION), _esc(utc_now_stamp())))
    body.append("</div>")

    document = (
        "<!doctype html>\n<html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>{}</title><style>{}</style></head><body>{}</body></html>\n"
    ).format(_esc(title), STYLE, "".join(body))

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(document)
    return path


# ==========================================================================
# actions/groups.py  --  Group search: criteria, and optionally VM members.
# ==========================================================================

CONSOLE_MEMBER_LIMIT = 30

GROUPS_HEADERS = ["manager", "group_id", "display_name", "path", "criteria",
                  "members"]


def act_groups(sessions, domain, needle, show_members, exporter,
               cache_key=None):
    rows = []
    for nsx in sessions:
        try:
            base = nsx.base(domain)
        except NsxError as e:
            err(str(e))
            continue
        section("{}  [{}]".format(nsx.name, ROLE_LABEL.get(nsx.role, "?")))
        with Spinner("Fetching groups from {}".format(nsx.name)):
            try:
                groups = nsx.get_all(p_groups(base, domain))
            except NsxError as e:
                err(str(e))
                continue
        say("  {} group(s).".format(len(groups)))
        if needle:
            n = needle.lower()
            groups = [g for g in groups
                      if n in str(g.get(F_DISPLAY_NAME, "")).lower()
                      or n in str(g.get(F_ID, "")).lower()]
            say("  {} match '{}'.".format(cC(str(len(groups))), needle))
        for g in sorted(groups, key=lambda x: str(x.get(F_DISPLAY_NAME, "")).lower()):
            gid = g.get(F_ID, "?")
            dname = g.get(F_DISPLAY_NAME, gid)
            hr()
            say("  Group        : {}".format(cB(dname)))
            if gid != dname:
                say("  id           : {}   {}".format(gid, cBY("[id != name]")))
            else:
                say("  id           : {}".format(gid))
            say("  path         : {}".format(cD(g.get(F_PATH, "?"))))
            if g.get(F_DESCRIPTION):
                say("  description  : {}".format(g[F_DESCRIPTION]))
            say("  criteria     :")
            for line in describe_expression(g.get(F_EXPRESSION)):
                say("    {}".format(line))
            member_count = ""
            if show_members:
                try:
                    vms = nsx.get_all(p_group_members(base, domain, gid))
                    member_count = str(len(vms))
                    say("  VM members ({}):".format(cC(member_count)))
                    for vm in vms[:CONSOLE_MEMBER_LIMIT]:
                        say("    {}".format(vm.get(F_DISPLAY_NAME, vm.get(F_ID, "?"))))
                    more_note(CONSOLE_MEMBER_LIMIT, len(vms), "member count in export")
                except NsxError as e:
                    say("  VM members: {} ({})".format(cR("error"), e))
                    member_count = "error"
            rows.append([nsx.name, gid, dname, g.get(F_PATH, ""),
                         criteria_summary(g.get(F_EXPRESSION)), member_count])
    hr()
    exporter.stage("groups", GROUPS_HEADERS, rows)
    # Keep TAB completion warm off a listing somebody ran anyway.
    remember_names(KIND_GROUP, [r[1] for r in rows] + [r[2] for r in rows],
                   cache_key)


# ==========================================================================
# actions/verify.py  --  Connectivity, authentication and API-base verification.
# ==========================================================================

def act_verify(sessions, domain=DEFAULT_DOMAIN):
    all_ok = True
    for nsx in sessions:
        section("{}  [{}]  {}".format(
            nsx.name, ROLE_LABEL.get(nsx.role, "?"), nsx.base_url))
        say("  {} transport={} auth={} verify_ssl={}".format(
            cD("config:"), nsx.t.name, nsx.auth_mode, nsx.verify))
        if nsx.role == ROLE_GM:
            try:
                base = nsx.base(domain, verbose=True)
            except NsxError as e:
                err(str(e))
                all_ok = False
                continue
            checks = [("groups", p_groups(base, domain)),
                      ("security-policies", p_sec_policies(base, domain))]
        elif nsx.role == ROLE_LM:
            base = nsx.base(domain)
            checks = [("groups", p_groups(base, domain)),
                      ("security-policies", p_sec_policies(base, domain)),
                      ("VM inventory", PATH_FABRIC_VMS)]
        else:
            say("  {}".format(cBR("no role")))
            all_ok = False
            continue
        ver = nsx.version()
        if ver:
            say("  {} NSX {}.{}".format(cD("version:"), ver[0], ver[1]))
        for label, path in checks:
            try:
                d = nsx.get(path, params={PARAM_PAGE_SIZE: 1})
                n = d.get(F_RESULT_COUNT, len(d.get(F_RESULTS, [])))
                say("  {}    {:22s}  {} item(s)".format(cBG("OK"), label, n))
            except NsxError as e:
                say("  {}  {:22s}  {}".format(cBR("FAIL"), label, str(e)[:120]))
                all_ok = False
    hr()
    say("  {}.".format("All " + cBG("OK") if all_ok else cBR("Failures detected")))
    return all_ok


# ==========================================================================
# actions/dashboard.py  --  Taxonomy compliance posture across every Local Manager.
# ==========================================================================

DASHBOARD_HEADERS = ["vm_name", "manager", "tag_count", "mandatory_present",
                  "missing", "status"]


def _pct(part, whole):
    return int(100 * part / whole) if whole else 0


def act_dashboard(sessions, exporter, taxonomy):
    lms = [s for s in sessions if s.role == ROLE_LM]
    if not lms:
        say("  No Local Managers connected -- tags are LM-local objects.")
        exporter.stage("dashboard", DASHBOARD_HEADERS, [])
        return
    section("COMPLIANCE DASHBOARD    {}".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
    say("  Taxonomy: {}".format(cC(taxonomy.source)))
    fetched = parallel_run(lms, lambda s: s.all_vms(),
                           label="Fetching VM inventories")
    vms = []
    for name, result in fetched.items():
        if isinstance(result, Exception):
            err("{}: {}".format(name, result))
            continue
        for vm in (result or []):
            vms.append((name, vm))
    total = len(vms)
    if total == 0:
        say("  No VMs found.")
        exporter.stage("dashboard", DASHBOARD_HEADERS, [])
        return

    mandatory = taxonomy.mandatory
    coverage = dict.fromkeys(mandatory, 0)
    untagged = full = partial = 0
    rows = []
    for mgr, vm in vms:
        pairs = tags_of(vm)
        scopes = {s for s, _ in pairs if s}
        present = [s for s in mandatory if s in scopes]
        missing = [s for s in mandatory if s not in scopes]
        if not pairs:
            untagged += 1
            status = "untagged"
        elif len(present) == len(mandatory):
            full += 1
            status = "complete"
        else:
            partial += 1
            status = "partial"
        for s in present:
            coverage[s] += 1
        rows.append([vm.get(F_DISPLAY_NAME, "?"), mgr, str(len(pairs)),
                     str(len(present)), ", ".join(missing) or "none", status])

    say("\n  {} ({} VMs)\n".format(cB("Scope Coverage"), total))
    table(["Scope", "Coverage", "Progress"],
          [[cC(s), "{}/{}".format(coverage[s], total),
            progress_bar(coverage[s], total)] for s in mandatory], indent=4)

    say("\n  {}".format(cB("Summary")))
    hr()
    say("    Total VMs              : {}".format(cB(str(total))))
    say("    Fully tagged ({}/{})     : {} ({}%)".format(
        len(mandatory), len(mandatory), cBG(str(full)), _pct(full, total)))
    say("    Partially tagged       : {} ({}%)".format(
        cBY(str(partial)), _pct(partial, total)))
    say("    Untagged               : {} ({}%)".format(
        cBR(str(untagged)), _pct(untagged, total)))
    say("    Migration progress     : {}".format(progress_bar(full, total)))

    say("\n  {}".format(cB("Per-Manager")))
    mrows = []
    for nsx in lms:
        mine = [vm for mgr, vm in vms if mgr == nsx.name]
        mt = len(mine)
        mf = sum(1 for v in mine
                 if len({s for s, _ in tags_of(v) if s} & set(mandatory))
                 == len(mandatory))
        mu = sum(1 for v in mine if not tags_of(v))
        mrows.append([cC(nsx.name), str(mt), cG(str(mf)), cR(str(mu)),
                      progress_bar(mf, mt)])
    table(["Manager", "VMs", "Complete", "Untagged", "Progress"], mrows, indent=4)
    hr()
    exporter.stage("dashboard", DASHBOARD_HEADERS, rows)


# ==========================================================================
# actions/tags.py  --  VM tag inspection and interactive add/remove.
# ==========================================================================

CONSOLE_VM_LIMIT = 50
CONSOLE_MATCH_LIMIT = 40

TAGS_HEADERS = ["manager", "vm_name", "external_id", "power_state",
                "tag_scope", "tag_value"]
BY_TAG_HEADERS = ["manager", "vm_name", "external_id", "all_tags"]


def act_vm_tags(sessions, needle, exporter, taxonomy):
    rows = []
    total = 0
    for nsx in sessions:
        section("{}  [{}]".format(nsx.name, ROLE_LABEL.get(nsx.role, "?")))
        with Spinner("Searching VMs on {}".format(nsx.name)):
            try:
                matches = nsx.find_vms(needle)
            except NsxError as e:
                err(str(e))
                continue
        if not matches:
            say("  No VM matching '{}'".format(needle))
            continue
        total += len(matches)
        ordered = sorted(matches,
                         key=lambda v: str(v.get(F_DISPLAY_NAME, "")).lower())
        for i, vm in enumerate(ordered):
            name = vm.get(F_DISPLAY_NAME, "?")
            ext = vm.get(F_EXTERNAL_ID, "?")
            power = vm.get(F_POWER_STATE, "")
            pairs = tags_of(vm)
            # Export every match; only the console listing is capped.
            if pairs:
                for s, t in sorted(pairs):
                    rows.append([nsx.name, name, ext, power, s, t])
            else:
                rows.append([nsx.name, name, ext, power, "", ""])
            if i >= CONSOLE_VM_LIMIT:
                continue
            hr()
            say("  VM           : {}".format(cB(name)))
            say("  external_id  : {}".format(cD(ext)))
            if power:
                say("  power_state  : {}".format(
                    cG(power) if "ON" in power else cY(power)))
            say("  tags ({})    :".format(len(pairs)))
            if pairs:
                for s, t in sorted(pairs):
                    say("    {:30s} = {}".format(cC(s), t))
                clean, issues = taxonomy.validate_vm_tags(pairs)
                say("  taxonomy     : {}".format(
                    cBG("OK") if clean else cBY("{} issue(s)".format(len(issues)))))
                for issue in issues[:5]:
                    warn(issue)
            else:
                say("    {}".format(cD("(none)")))
        more_note(CONSOLE_VM_LIMIT, len(ordered))
    hr()
    say("  {} VM(s) across {} manager(s).".format(cC(str(total)), len(sessions)))
    exporter.stage("vm_tags", TAGS_HEADERS, rows)


def act_vms_by_tag(sessions, scope, tag, exporter):
    crit = " and ".join(x for x in [
        "scope='{}'".format(scope) if scope else "",
        "tag='{}'".format(tag) if tag else ""] if x)
    rows = []
    total = 0
    lms = [s for s in sessions if s.role == ROLE_LM]
    fetched = parallel_run(lms, lambda s: s.all_vms(), label="Scanning inventories")

    def hit(vm):
        for s, t in tags_of(vm):
            if scope and s.lower() != scope.lower():
                continue
            if tag and t.lower() != tag.lower():
                continue
            return True
        return False

    for nsx in lms:
        section(nsx.name)
        vms = fetched.get(nsx.name)
        if isinstance(vms, Exception):
            err(str(vms))
            continue
        if not vms:
            continue
        matches = [v for v in vms if hit(v)]
        total += len(matches)
        say("  {} of {} VM(s) carry {}".format(
            cC(str(len(matches))), len(vms), crit))
        for vm in sorted(matches,
                         key=lambda v: str(v.get(F_DISPLAY_NAME, "")).lower()):
            name = vm.get(F_DISPLAY_NAME, "?")
            say("    {:45s} {}".format(name, fmt_tags(tags_of(vm))))
            rows.append([nsx.name, name, vm.get(F_EXTERNAL_ID, ""),
                         fmt_tags_plain(tags_of(vm))])
    hr()
    say("  {} VM(s) across {} LM(s).".format(cC(str(total)), len(lms)))
    exporter.stage("vms_by_tag", BY_TAG_HEADERS, rows)


def _pick_scope(taxonomy):
    say("\n    {} (* = mandatory):".format(cB("Scopes")))
    scopes = taxonomy.all_scopes
    for i, s in enumerate(scopes, 1):
        mark = cBG("*") if s in taxonomy.mandatory else " "
        vals = taxonomy.values_for(s)
        hint = "  {}".format(cD(", ".join(vals))) if vals else ""
        say("      {:2d}. {} {}{}".format(i, mark, cC(s), hint))
    say("       0. {}".format(cD("custom")))
    c = ask("    Scope [# or name]: ", default="")
    if c.isdigit():
        idx = int(c)
        if idx == 0:
            return ask("    Custom scope: ", default="")
        if 1 <= idx <= len(scopes):
            return scopes[idx - 1]
    return c.lower().strip()


def _pick_value(taxonomy, scope):
    allowed = taxonomy.values_for(scope)
    if not allowed:
        return ask("    Tag value: ")
    say("\n    {} {}:".format(cB("Values for"), cC(scope)))
    for i, v in enumerate(allowed, 1):
        say("      {}. {}".format(i, v))
    say("      0. {}".format(cD("custom")))
    c = ask("    Value [# or name]: ", default="")
    if c.isdigit():
        idx = int(c)
        if idx == 0:
            return ask("    Custom value: ")
        if 1 <= idx <= len(allowed):
            return allowed[idx - 1]
    return c.lower().strip()


def _apply(nsx, vm, new_pairs, old_pairs, audit):
    """Re-read immediately before writing so a concurrent change by another
    operator is detected rather than silently overwritten."""
    fresh = nsx.refresh_vm(vm)
    if fresh is None:
        raise NsxError("VM disappeared from inventory before write.")
    live = sorted(tags_of(fresh))
    if live != sorted(old_pairs):
        raise NsxError(
            "tags changed on NSX since this plan was built "
            "(now: {}). Re-run to pick up the current state.".format(
                fmt_tags_plain(live)))
    nsx.update_vm_tags(fresh, new_pairs)
    audit.log("update_tags", nsx.name, fresh.get(F_DISPLAY_NAME, "?"),
              fresh.get(F_EXTERNAL_ID), old_pairs, new_pairs)


def act_manage_tags(sessions, needle, audit, write_enabled, taxonomy):
    if not write_enabled:
        say("  {}. Toggle with menu 12 or --enable-writes.".format(
            cBY("Writes disabled")))
        return
    if not is_interactive():
        err("Interactive tag management needs a terminal. "
            "Use --bulk-tag for scripted changes.")
        return
    found = []
    for nsx in sessions:
        try:
            for vm in nsx.find_vms(needle):
                found.append((nsx, vm))
        except NsxError as e:
            err(str(e))
    if not found:
        say("  No VM matching '{}'.".format(needle))
        return
    if len(found) == 1:
        nsx, vm = found[0]
    else:
        say("\n  {} matches:".format(len(found)))
        for i, (n, v) in enumerate(found[:CONSOLE_MATCH_LIMIT], 1):
            say("    {}. [{}] {:40s} {}".format(
                i, cC(n.name), v.get(F_DISPLAY_NAME, "?"), fmt_tags(tags_of(v))))
        more_note(CONSOLE_MATCH_LIMIT, len(found), "narrow the search")
        say("    b. back")
        while True:
            c = ask("  Which VM? ")
            if c.isdigit() and 1 <= int(c) <= min(len(found), CONSOLE_MATCH_LIMIT):
                nsx, vm = found[int(c) - 1]
                break
            say("    Invalid.")

    while True:
        current = nsx.refresh_vm(vm) or vm
        pairs = sorted(tags_of(current))
        hr()
        say("  VM  : {}   [{}]".format(
            cB(current.get(F_DISPLAY_NAME, "?")), cC(nsx.name)))
        say("  tags ({}):".format(len(pairs)))
        for i, (s, t) in enumerate(pairs, 1):
            flag = "  {}".format(cBY("!!")) if taxonomy.validate_tag(s, t) else ""
            say("    {:2d}. {:30s} = {}{}".format(i, cC(s), t, flag))
        if not pairs:
            say("      {}".format(cD("(none)")))
        hr()
        say("    1. {}".format(cG("Add")))
        say("    2. {}".format(cR("Remove")))
        say("    b. Back")
        c = ask("  Choice: ", allow_back=False).lower()
        if c == "b":
            return
        if c == "1":
            scope = _pick_scope(taxonomy)
            if not scope:
                say("    Scope required.")
                continue
            value = _pick_value(taxonomy, scope)
            if not value:
                say("    Value required.")
                continue
            warnings = taxonomy.validate_tag(scope, value)
            if warnings:
                for w in warnings:
                    warn(w)
                if not confirm("    Proceed? [y/N]: "):
                    continue
            if (scope, value) in pairs:
                say("    Already has it.")
                continue
            new = pairs + [(scope, value)]
            say("\n    Result ({} tags):".format(len(new)))
            for s, t in sorted(new):
                mark = "  {}".format(cBG("<-- NEW")) if (s, t) == (scope, value) else ""
                say("      {:30s} = {}{}".format(cC(s), t, mark))
            if not confirm("    Apply? [y/N]: "):
                say("    Cancelled.")
                continue
            try:
                _apply(nsx, current, new, pairs, audit)
                ok_msg("Applied.")
            except NsxError as e:
                err(str(e))
        elif c == "2":
            if not pairs:
                say("    No tags.")
                continue
            sel = ask("    Tag # to remove: ")
            if not sel.isdigit() or not (1 <= int(sel) <= len(pairs)):
                say("    Invalid.")
                continue
            victim = pairs[int(sel) - 1]
            new = [p for p in pairs if p != victim]
            say("\n    Removing: {}".format(cR("{}={}".format(*victim))))
            say("    {}: may affect dynamic groups and DFW rules.".format(cBY("NOTE")))
            if not confirm("    Apply? [y/N]: "):
                continue
            try:
                _apply(nsx, current, new, pairs, audit)
                ok_msg("Removed.")
            except NsxError as e:
                err(str(e))


# ==========================================================================
# actions/bulk.py  --  Bulk tagging from CSV.
# ==========================================================================

REQUIRED_COLUMNS = {"vm_name", "scope", "tag", "action"}
VALID_ACTIONS = ("add", "remove")


def read_bulk_csv(path):
    """Rows plus any structural problems. Raises only for unusable files."""
    if not os.path.isfile(path):
        raise NsxError("Not found: {}".format(path))
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise NsxError("CSV empty: {}".format(path))
    missing = REQUIRED_COLUMNS - {k for k in rows[0].keys() if k}
    if missing:
        raise NsxError("CSV missing column(s): {}".format(", ".join(sorted(missing))))
    problems = []
    clean = []
    for i, row in enumerate(rows, 2):  # header is line 1
        name = (row.get("vm_name") or "").strip()
        scope = (row.get("scope") or "").strip()
        tag = (row.get("tag") or "").strip()
        action = (row.get("action") or "").strip().lower()
        if not name:
            problems.append("line {}: empty vm_name".format(i))
            continue
        if action not in VALID_ACTIONS:
            problems.append("line {}: action must be add|remove (got {!r})".format(
                i, row.get("action")))
            continue
        if not scope and not tag:
            problems.append("line {}: needs a scope, a tag, or both".format(i))
            continue
        clean.append({"line": i, "vm_name": name, "scope": scope,
                      "tag": tag, "action": action})
    return clean, problems


def build_vm_index(sessions):
    """{lowercase display name: [(nsx, vm), ...]} from one fetch per manager."""
    fetched = parallel_run(sessions, lambda s: s.all_vms(),
                           label="Indexing VM inventories")
    index = {}
    for nsx in sessions:
        vms = fetched.get(nsx.name)
        if isinstance(vms, Exception):
            err("{}: {}".format(nsx.name, vms))
            continue
        for vm in (vms or []):
            key = str(vm.get(F_DISPLAY_NAME, "")).lower()
            if key:
                index.setdefault(key, []).append((nsx, vm))
    return index


def plan_bulk(sessions, rows):
    """Compute per-VM tag changes without touching NSX beyond the index build.

    Returns (plan, unresolved, ambiguous) where plan entries are
    {nsx, vm, before, after, added, removed, ops}.
    """
    index = build_vm_index(sessions)
    by_vm = {}
    for row in rows:
        by_vm.setdefault(row["vm_name"], []).append(row)

    plan, unresolved, ambiguous = [], [], []
    for name, ops in sorted(by_vm.items()):
        candidates = index.get(name.lower(), [])
        if not candidates:
            unresolved.append(name)
            continue
        if len({n.name for n, _ in candidates}) > 1:
            ambiguous.append((name, sorted({n.name for n, _ in candidates})))
            continue
        nsx, vm = candidates[0]
        before = sorted(tags_of(vm))
        after = list(before)
        for op in ops:
            pair = (op["scope"], op["tag"])
            if op["action"] == "add":
                if pair not in after:
                    after.append(pair)
            else:
                after = [p for p in after if p != pair]
        after = sorted(after)
        plan.append({
            "nsx": nsx, "vm": vm, "before": before, "after": after,
            "added": [p for p in after if p not in before],
            "removed": [p for p in before if p not in after],
            "ops": ops,
        })
    return plan, unresolved, ambiguous


def act_bulk_tag(sessions, csv_path, audit, write_enabled, dry_run=True,
                 taxonomy=None, force=False):
    """Returns a result dict; also prints a human-readable plan/outcome."""
    result = {"applied": 0, "skipped": 0, "failed": 0, "unresolved": 0,
              "unchanged": 0}
    try:
        rows, problems = read_bulk_csv(csv_path)
    except NsxError as e:
        err(str(e))
        return result
    for p in problems:
        warn(p)
    if not rows:
        err("No usable rows in {}.".format(csv_path))
        return result

    if taxonomy:
        for row in rows:
            if row["action"] == "add":
                for w in taxonomy.validate_tag(row["scope"], row["tag"]):
                    warn("line {}: {}".format(row["line"], w))

    if not dry_run and not write_enabled:
        say("  {}. Re-run with --enable-writes.".format(cBY("Writes disabled")))
        return result

    plan, unresolved, ambiguous = plan_bulk(sessions, rows)
    label = cBY("DRY RUN") if dry_run else cBG("APPLYING")
    say("\n  {} -- {} op(s) across {} VM(s)".format(label, len(rows), len(plan)))
    hr()

    for name in unresolved:
        say("  {:45s}  {}".format(name, cR("NOT FOUND")))
        result["unresolved"] += 1
    for name, mgrs in ambiguous:
        say("  {:45s}  {} on {}".format(
            name, cBR("AMBIGUOUS"), ", ".join(mgrs)))
        say("      {}".format(cD("resolve with --manager to pick one")))
        result["skipped"] += 1

    for item in plan:
        name = item["vm"].get(F_DISPLAY_NAME, "?")
        if not item["added"] and not item["removed"]:
            say("  {:45s}  {}".format(name, cD("no change")))
            result["unchanged"] += 1
            continue
        change = []
        if item["added"]:
            change.append(cG("+{}".format(len(item["added"]))))
        if item["removed"]:
            change.append(cR("-{}".format(len(item["removed"]))))
        if dry_run:
            say("  {:45s}  [{}]  would: {}".format(
                name, cC(item["nsx"].name), ", ".join(change)))
            for s, t in item["added"]:
                say("      {}".format(cG("+ {}={}".format(s, t))))
            for s, t in item["removed"]:
                say("      {}".format(cR("- {}={}".format(s, t))))
            result["applied"] += 1
            continue
        try:
            _write_row(item, audit, force)
            say("  {:45s}  [{}]  applied: {}".format(
                name, cC(item["nsx"].name), ", ".join(change)))
            result["applied"] += 1
        except NsxError as e:
            say("  {:45s}  {}".format(name, cBR("FAILED")))
            say("      {}".format(cD(str(e)[:160])))
            result["failed"] += 1

    hr()
    say("  Complete: {} {}, {} unchanged, {} not found, {} failed.".format(
        cG(str(result["applied"])), "planned" if dry_run else "applied",
        cY(str(result["unchanged"])), cR(str(result["unresolved"])),
        cR(str(result["failed"]))))
    return result


def _write_row(item, audit, force):
    nsx, vm = item["nsx"], item["vm"]
    fresh = nsx.refresh_vm(vm)
    if fresh is None:
        raise NsxError("VM disappeared from inventory before write.")
    live = sorted(tags_of(fresh))
    if live != item["before"] and not force:
        raise NsxError(
            "tags changed on NSX since the plan was built (now: {}); "
            "re-run, or pass --force to overwrite.".format(fmt_tags_plain(live)))
    nsx.update_vm_tags(fresh, item["after"])
    audit.log("bulk_update_tags", nsx.name, fresh.get(F_DISPLAY_NAME, "?"),
              fresh.get(F_EXTERNAL_ID), item["before"], item["after"])


# ==========================================================================
# actions/reverse.py  --  Reverse lookup: VM -> groups -> DFW rules impact analysis.
# ==========================================================================

REVERSE_HEADERS = ["vm", "manager", "manager_role", "group_id", "group_name",
                  "group_origin", "policy", "rule", "rule_origin", "action",
                  "direction"]


def _collect_associations(nsx, domain, ext_id):
    base = nsx.base(domain)
    return nsx.get_all(p_vm_group_assoc(base),
                       params={PARAM_VM_EXTERNAL_ID: ext_id})


def act_reverse_lookup(all_sessions, needle, domain, exporter):
    """VM -> groups -> DFW rules impact analysis.

    GROUP MEMBERSHIP: uses NSX's own reverse-association endpoint
    (virtual-machine-group-associations) instead of sweeping every group's
    /members/virtual-machines sub-resource. That sub-resource only returns
    results for groups whose criteria resolves to the VirtualMachine member
    type -- groups matched on VIF, IPAddress, Segment, or SegmentPort criteria
    silently come back empty there even though the VM is an effective member.
    The association endpoint is member-type agnostic: it's the same index NSX's
    own Groups search UI reads, so results match what you see there. Queried on
    the VM's home LM (tags/VMs are LM-local), with a best-effort supplementary
    query on any connected GM.

    DFW RULES: GM-authored security policies are realized read-only on every LM
    registered beneath it, so an LM's own rule listing contains both its native
    rules AND a copy of every GM rule. Scanned across GM + all LMs, that means
    each GM rule would otherwise be reported once per LM (once per site, up to
    8x). Rules are deduped globally by their NSX 'path' -- first-seen wins, GM
    sessions are scanned before LM sessions, so a GM-origin rule is always
    attributed to 'GM' exactly once and never re-listed per LM. Rules with no
    GM session connected (or genuinely LM-native rules) still get counted,
    tagged with the appropriate origin.
    """
    rows = []
    gm_sessions = [s for s in all_sessions if s.role == ROLE_GM]
    lm_sessions = [s for s in all_sessions if s.role == ROLE_LM]

    # Tags/VMs are LM-local objects -- find the VM on whichever LM has it.
    found_vm = None
    for nsx in lm_sessions:
        try:
            hits = nsx.find_vms(needle)
            if hits:
                found_vm = (nsx, hits[0])
                break
        except NsxError:
            continue
    if not found_vm:
        say("  No VM matching '{}' on any Local Manager.".format(needle))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return

    nsx_lm, vm = found_vm
    vname = vm.get(F_DISPLAY_NAME, "?")
    ext_id = vm.get(F_EXTERNAL_ID)
    say("\n  VM      : {}".format(cB(vname)))
    say("  Found on: {}  (Local Manager)".format(cC(nsx_lm.name)))
    say("  tags    : {}".format(fmt_tags(tags_of(vm))))
    if not ext_id:
        say("  {} -- cannot resolve group associations.".format(
            cBR("VM has no external_id")))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return

    # --- Group membership: reverse-association lookup, any member type ---
    section("Group Membership (any member type)")
    matched = {}   # group_id -> (path, display_name, origin)
    with Spinner("Association lookup on {}".format(nsx_lm.name)):
        try:
            assocs = _collect_associations(nsx_lm, domain, ext_id)
        except NsxError as e:
            err("association lookup on {} failed: {}".format(nsx_lm.name, e))
            assocs = []
    for a in assocs:
        gpath = a.get(F_PATH, "")
        gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
        matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                        origin_of_path(gpath))

    # Best-effort supplementary check on any connected GM -- catches the rare
    # case of a Global Group not yet realized onto this specific LM.
    # Non-fatal: GM doesn't hold VM inventory, so this may simply 404.
    for nsx_gm in gm_sessions:
        try:
            g_assocs = _collect_associations(nsx_gm, domain, ext_id)
        except NsxError:
            continue
        for a in g_assocs:
            gpath = a.get(F_PATH, "")
            gid = a.get(F_TARGET_ID) or (group_id_from_path(gpath) if gpath else "?")
            if gid in matched:
                continue
            matched[gid] = (gpath, a.get(F_TARGET_DISPLAY_NAME, gid),
                            origin_of_path(gpath))

    if not matched:
        say("  {}".format(cD("Not a member of any group on any manager.")))
        exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)
        return
    for gid, (_gpath, gname, origin) in sorted(matched.items(),
                                              key=lambda kv: kv[1][1].lower()):
        say("    [{}]  {}  {}".format(
            cC("GM") if origin == "GM" else cD("LM"), cB(gname), cD("id=" + gid)))

    group_paths = ({gp for gp, _, _ in matched.values() if gp}
                   | set(matched.keys()))
    group_lookup = {gid: gname for gid, (_, gname, _) in matched.items()}

    # --- DFW rules: GM scanned first, then LM, deduped by rule path ---
    section("DFW Rules Referencing These Groups")
    say("  Scanning {} GM + {} LM ({}) ...".format(
        len(gm_sessions), len(lm_sessions), cD("deduped by rule path")))
    hit_count = 0
    for record in sweep_rules(all_sessions, domain):
        hits = record.group_refs() & group_paths
        if not hits:
            continue
        hit_count += 1
        dirs = record.directions_for(group_paths)
        act = record.rule.get(F_ACTION_FIELD, "?")
        colour = cG if act == "ALLOW" else cR
        role_lbl = ROLE_LABEL.get(record.nsx.role, "?")
        say("    [{} / {} / {}]  {} / {}   {}   {}".format(
            cC(record.nsx.name), cD(role_lbl), cD(record.origin),
            cB(record.policy_name), record.rule_name,
            colour(act), cC(", ".join(dirs))))
        for gpath in hits:
            gi = group_id_from_path(gpath)
            _, _, gorigin = matched.get(gi, (None, None, "?"))
            rows.append([vname, record.nsx.name, role_lbl, gi,
                         group_lookup.get(gi, gi), gorigin, record.policy_id,
                         record.rule_id, record.origin, act,
                         ", ".join(dirs)])
    if hit_count == 0:
        say("  {} reference these groups on any manager.".format(cG("No DFW rules")))
    hr()
    exporter.stage("reverse_lookup", REVERSE_HEADERS, rows)


# ==========================================================================
# actions/parity.py  --  Static vs dynamic group parity -- the core migration progress check.
# ==========================================================================

CONSOLE_LIMIT = 30
PARITY_HEADERS = ["vm_name", "manager", "in_static", "in_dynamic", "status"]


def _groups_on(nsx, domain):
    base = nsx.base(domain)
    return base, nsx.get_all(p_groups(base, domain))


def _match(groups, name):
    n = name.lower()
    return [g for g in groups
            if str(g.get(F_DISPLAY_NAME, "")).lower() == n
            or str(g.get(F_ID, "")).lower() == n]


def resolve_pair(sessions, domain, static_name, dynamic_name):
    """(nsx, base, static_group, dynamic_group). Both from one manager."""
    candidates = []
    for nsx in sessions:
        try:
            base, groups = _groups_on(nsx, domain)
        except NsxError:
            continue
        s_hits = _match(groups, static_name)
        d_hits = _match(groups, dynamic_name)
        if s_hits and d_hits:
            candidates.append((nsx, base, s_hits[0], d_hits[0]))
    if not candidates:
        # Report which side is the problem rather than a bare "not found".
        found_s, found_d = [], []
        for nsx in sessions:
            try:
                _, groups = _groups_on(nsx, domain)
            except NsxError:
                continue
            if _match(groups, static_name):
                found_s.append(nsx.name)
            if _match(groups, dynamic_name):
                found_d.append(nsx.name)
        if not found_s and not found_d:
            raise NsxError("Neither '{}' nor '{}' found on any manager.".format(
                static_name, dynamic_name))
        if not found_s:
            raise NsxError("Static group '{}' not found on any manager "
                           "(dynamic found on: {}).".format(
                               static_name, ", ".join(found_d) or "none"))
        if not found_d:
            raise NsxError("Dynamic group '{}' not found on any manager "
                           "(static found on: {}).".format(
                               dynamic_name, ", ".join(found_s) or "none"))
        raise NsxError(
            "'{}' and '{}' exist but never on the same manager "
            "(static: {}; dynamic: {}). Comparing across managers would be "
            "meaningless.".format(static_name, dynamic_name,
                                  ", ".join(found_s), ", ".join(found_d)))
    if len(candidates) > 1:
        names = ", ".join(c[0].name for c in candidates)
        say("  {} both groups exist on {} -- using {}. "
            "Use --manager to pick another.".format(
                cBY("note:"), names, cC(candidates[0][0].name)))
    return candidates[0]


def act_parity(sessions, domain, static_name, dynamic_name, exporter):
    rows = []
    try:
        nsx, base, gs, gd = resolve_pair(sessions, domain, static_name, dynamic_name)
    except NsxError as e:
        err(str(e))
        exporter.stage("parity", PARITY_HEADERS, rows)
        return

    section("Parity Validation")
    say("  Manager : {}  [{}]".format(cC(nsx.name), ROLE_LABEL.get(nsx.role, "?")))
    say("  Static  : {}".format(cB(gs.get(F_DISPLAY_NAME, "?"))))
    say("  Dynamic : {}".format(cB(gd.get(F_DISPLAY_NAME, "?"))))
    with Spinner("Fetching members"):
        try:
            static_members = nsx.get_all(p_group_members(base, domain, gs.get(F_ID)))
            dynamic_members = nsx.get_all(p_group_members(base, domain, gd.get(F_ID)))
        except NsxError as e:
            err(str(e))
            exporter.stage("parity", PARITY_HEADERS, rows)
            return

    s_map = {str(m.get(F_DISPLAY_NAME, "")).lower(): m for m in static_members}
    d_map = {str(m.get(F_DISPLAY_NAME, "")).lower(): m for m in dynamic_members}
    only_static = sorted(set(s_map) - set(d_map))
    only_dynamic = sorted(set(d_map) - set(s_map))
    both = sorted(set(s_map) & set(d_map))

    say("\n  Static: {}  Dynamic: {}  Both: {}".format(
        cC(str(len(s_map))), cC(str(len(d_map))), cBG(str(len(both)))))
    say("  Only static: {} (need migration)  Only dynamic: {} (unexpected)".format(
        cBR(str(len(only_static))), cBY(str(len(only_dynamic)))))

    # Console listings are capped; every row is exported.
    if only_static:
        say("\n  {}:".format(cBR("Need migration")))
        for n in only_static[:CONSOLE_LIMIT]:
            say("    {} {}".format(cR("x"), s_map[n].get(F_DISPLAY_NAME, n)))
        more_note(CONSOLE_LIMIT, len(only_static))
    if only_dynamic:
        say("\n  {}:".format(cBY("Unexpected")))
        for n in only_dynamic[:CONSOLE_LIMIT]:
            say("    {} {}".format(cY("?"), d_map[n].get(F_DISPLAY_NAME, n)))
        more_note(CONSOLE_LIMIT, len(only_dynamic))

    for n in only_static:
        rows.append([s_map[n].get(F_DISPLAY_NAME, n), nsx.name, "yes", "no",
                     "needs_migration"])
    for n in only_dynamic:
        rows.append([d_map[n].get(F_DISPLAY_NAME, n), nsx.name, "no", "yes",
                     "unexpected"])
    for n in both:
        rows.append([s_map[n].get(F_DISPLAY_NAME, n), nsx.name, "yes", "yes",
                     "migrated"])

    say("\n  Parity: {}".format(progress_bar(len(both), len(s_map))))
    say("  {}".format(cD("{} row(s) staged for export".format(len(rows)))))
    hr()
    exporter.stage("parity", PARITY_HEADERS, rows)


# ==========================================================================
# actions/change_ticket.py  --  Change plan generation from a bulk-tagging CSV.
# ==========================================================================

TICKET_HEADERS = ["vm_name", "manager", "status", "tags_before", "tags_after",
                  "added", "removed"]


def _rule(char="=", width=70):
    return char * width


def build_plan_lines(csv_path, plan, unresolved, ambiguous, problems, user):
    adds = sum(len(p["added"]) for p in plan)
    removes = sum(len(p["removed"]) for p in plan)
    changing = [p for p in plan if p["added"] or p["removed"]]
    noop = [p for p in plan if not p["added"] and not p["removed"]]

    lines = [_rule(), "  CHANGE PLAN: Tag Migration Batch", _rule(),
             "  Prepared by : {}".format(user),
             "  Date        : {}".format(utc_now_stamp()),
             "  Source      : {}".format(csv_path),
             "  Host        : {}".format(platform.node()), "",
             "  SCOPE", "  " + _rule("-", 40),
             "  VMs changing     : {}".format(len(changing)),
             "  VMs already ok   : {}".format(len(noop)),
             "  VMs not found    : {}".format(len(unresolved)),
             "  VMs ambiguous    : {}".format(len(ambiguous)),
             "  Tags to add      : {}".format(adds),
             "  Tags to remove   : {}".format(removes), ""]

    if problems:
        lines.extend(["  CSV PROBLEMS", "  " + _rule("-", 40)])
        lines.extend("    {}".format(p) for p in problems)
        lines.append("")

    lines.extend(["  CHANGES BY VM  (verified against live NSX)",
                  "  " + _rule("-", 40)])
    for item in sorted(changing, key=lambda p: p["vm"].get(F_DISPLAY_NAME, "")):
        lines.append("  {}   [{}]".format(
            item["vm"].get(F_DISPLAY_NAME, "?"), item["nsx"].name))
        lines.append("    current : {}".format(fmt_tags_plain(item["before"])))
        lines.append("    proposed: {}".format(fmt_tags_plain(item["after"])))
        for s, t in item["added"]:
            lines.append("    + {}={}".format(s, t))
        for s, t in item["removed"]:
            lines.append("    - {}={}".format(s, t))
        lines.append("")

    if noop:
        lines.extend(["  ALREADY IN DESIRED STATE (no action)",
                      "  " + _rule("-", 40)])
        lines.extend("    {}".format(p["vm"].get(F_DISPLAY_NAME, "?")) for p in noop)
        lines.append("")
    if unresolved:
        lines.extend(["  NOT FOUND ON ANY MANAGER (will be skipped)",
                      "  " + _rule("-", 40)])
        lines.extend("    {}".format(n) for n in unresolved)
        lines.append("")
    if ambiguous:
        lines.extend(["  AMBIGUOUS -- same name on several managers",
                      "  " + _rule("-", 40)])
        lines.extend("    {}  ({})".format(n, ", ".join(m)) for n, m in ambiguous)
        lines.append("")

    lines.extend(["  ROLLBACK", "  " + _rule("-", 40),
                  "  Audit-log undo (menu 11) restores per-VM prior state,",
                  "  or apply an inverse CSV with --bulk-tag.", "",
                  "  PRE-CHANGE CHECKLIST", "  " + _rule("-", 40),
                  "  1. --verify   (all managers reachable and authenticated)",
                  "  2. --bulk-tag <file> --dry-run   (preview, no writes)",
                  "  3. Confirm no active maintenance window conflicts",
                  "  4. --bulk-tag <file> --enable-writes --yes", "", _rule()])
    return lines


def act_change_ticket(sessions, csv_path, exporter, out_dir=None):
    try:
        rows, problems = read_bulk_csv(csv_path)
    except NsxError as e:
        err(str(e))
        return None
    plan, unresolved, ambiguous = plan_bulk(sessions, rows)
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    lines = build_plan_lines(csv_path, plan, unresolved, ambiguous, problems, user)

    out_dir = out_dir or DEFAULT_TICKET_DIR
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "change_plan_{}.txt".format(local_stamp()))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    for line in lines:
        if line.startswith("=" * 10):
            say(cBC(line))
        elif "CHANGE PLAN" in line:
            say("  {}".format(cB(line.strip())))
        elif line.strip().startswith("+") and "=" in line:
            say(cG(line))
        elif line.strip().startswith("- ") and "=" in line:
            say(cR(line))
        else:
            say(line)

    export_rows = []
    for item in plan:
        changing = bool(item["added"] or item["removed"])
        export_rows.append([
            item["vm"].get(F_DISPLAY_NAME, "?"), item["nsx"].name,
            "change" if changing else "no_change",
            fmt_tags_plain(item["before"]), fmt_tags_plain(item["after"]),
            fmt_tags_plain(item["added"]), fmt_tags_plain(item["removed"])])
    for name in unresolved:
        export_rows.append([name, "", "not_found", "", "", "", ""])
    for name, mgrs in ambiguous:
        export_rows.append([name, ", ".join(mgrs), "ambiguous", "", "", "", ""])
    exporter.stage("change_plan", TICKET_HEADERS, export_rows)

    if unresolved or ambiguous:
        say("  {} {} row(s) could not be resolved -- see the plan.".format(
            cBY("WARNING:"), len(unresolved) + len(ambiguous)))
    ok_msg("Saved: {}".format(out_path))
    return out_path


# ==========================================================================
# actions/hygiene.py  --  DFW rule hygiene: the "is my policy sane" report.
# ==========================================================================

HYGIENE_CONSOLE_LIMIT = 40

SEVERITIES = ("critical", "high", "medium", "low")

HYGIENE_HEADERS = ["severity", "check", "confidence", "manager", "origin",
                   "policy", "rule", "action", "detail"]

TERMINAL_ACTIONS = ("ALLOW", "DROP", "REJECT")
DENY_ACTIONS = ("DROP", "REJECT")


class Finding:
    __slots__ = ("check", "severity", "confidence", "record", "detail")

    def __init__(self, check, severity, record, detail, confidence="provable"):
        self.check = check
        self.severity = severity
        self.record = record
        self.detail = detail
        self.confidence = confidence

    def row(self):
        rule = self.record.rule
        return [self.severity, self.check, self.confidence,
                self.record.nsx.name, self.record.origin,
                self.record.policy_name, self.record.rule_name,
                rule.get(F_ACTION_FIELD, "?"), self.detail]


# === RULE SHAPE HELPERS ===
def match_key(rule):
    """What makes two rules equivalent, without expanding services.

    Service definitions are compared as opaque paths on purpose: expanding
    them into port ranges is where a shadow analysis starts producing false
    "unreachable" claims.
    """
    return (
        tuple(sorted(listed_values(rule, "source_groups"))),
        tuple(sorted(listed_values(rule, "destination_groups"))),
        tuple(sorted(listed_values(rule, F_SERVICES))),
        tuple(sorted(listed_values(rule, F_SCOPE))),
        rule.get(F_ACTION_FIELD, ""),
        rule.get(F_DIRECTION, ""),
    )


def matches_everything(rule):
    """True when this rule matches all traffic in its policy."""
    return (is_wildcard(listed_values(rule, "source_groups"))
            and is_wildcard(listed_values(rule, "destination_groups"))
            and is_wildcard(listed_values(rule, F_SERVICES))
            and is_wildcard(listed_values(rule, F_SCOPE))
            and rule.get(F_ACTION_FIELD) in TERMINAL_ACTIONS
            and not rule.get(F_DISABLED))


def vm_resolvable(group):
    """Whether a group's criteria can be measured through the VM member API.

    Conservative by design: anything we cannot positively identify as
    VM-resolvable is reported as not measurable rather than guessed at.
    """
    expression = group.get(F_EXPRESSION) or []
    if not expression:
        return False
    for item in expression:
        kind = item.get(RT)
        if kind == RT_CONJUNCTION:
            continue
        if kind == RT_EXTERNALID:
            continue
        if kind == RT_CONDITION:
            if item.get(F_MEMBER_TYPE) == "VirtualMachine":
                continue
            return False
        if kind == RT_NESTED:
            if vm_resolvable({F_EXPRESSION: item.get(F_EXPRESSIONS, [])}):
                continue
            return False
        return False
    return True


# === STATISTICS ===
def _parse_stats(payload):
    """{rule_path: counters} from NSX's results[].statistics[] shape.

    Tolerates a flat results[] too: statistics is the part of the contract
    that varies most between versions, so the parser is permissive and the
    caller degrades rather than failing.
    """
    out = {}
    for result in (payload.get(F_RESULTS) or []):
        entries = result.get(F_STATISTICS)
        if entries is None:
            entries = [result] if result.get(F_RULE_PATH) else []
        for entry in entries:
            path = entry.get(F_RULE_PATH)
            if path:
                out[path] = entry
    return out


def fetch_hit_counts(records, domain):
    """({rule_path: counters}, supported).

    One call per policy, not per rule -- the per-rule endpoint would
    reintroduce the N+1 that the concurrent policy fetch removed. When the
    endpoint is absent the hit checks report unknown and every other check
    still runs.
    """
    targets = {}
    for record in records:
        targets[(record.nsx.name, record.policy_id)] = (record.nsx,
                                                        record.policy_id)
    if not targets:
        return {}, True

    def fetch(item):
        nsx, pid = item
        return nsx.get(p_policy_stats(nsx.base(domain), domain, pid))

    results = parallel_run(list(targets.values()), fetch,
                           label="Rule statistics",
                           key=lambda item: (item[0].name, item[1]))
    stats, failures = {}, 0
    for value in results.values():
        if isinstance(value, Exception):
            failures += 1
            debug("statistics unavailable: {}".format(value))
            continue
        stats.update(_parse_stats(value))
    supported = failures < len(targets)
    return stats, supported


def group_member_counts(groups, domain):
    """{group path: count or None} -- None means not measurable, not empty."""
    measurable = {path: (nsx, group) for path, (nsx, group) in groups.items()
                  if vm_resolvable(group)}
    counts = dict.fromkeys(groups)
    if not measurable:
        return counts

    def fetch(item):
        path, (nsx, group) = item
        members = nsx.get_all(p_group_members(nsx.base(domain), domain,
                                              group.get(F_ID, "?")))
        return len(members)

    results = parallel_run(list(measurable.items()), fetch,
                           label="Group members",
                           key=lambda item: item[0])
    for path, value in results.items():
        counts[path] = None if isinstance(value, Exception) else value
    return counts


# === CONTEXT ===
class HygieneContext:
    def __init__(self, records, groups, stats, stats_supported, member_counts):
        self.records = records
        self.groups = groups
        self.stats = stats
        self.stats_supported = stats_supported
        self.member_counts = member_counts
        self._by_policy = {}
        for record in records:
            key = (record.nsx.name, record.policy_id)
            self._by_policy.setdefault(key, []).append(record)
        for key in self._by_policy:
            self._by_policy[key].sort(key=rule_sequence)

    def earlier_siblings(self, record):
        """Rules ahead of this one in the same policy, in evaluation order."""
        key = (record.nsx.name, record.policy_id)
        siblings = self._by_policy.get(key, [])
        out = []
        for other in siblings:
            if other is record:
                break
            out.append(other)
        return out

    def hits_for(self, record):
        entry = self.stats.get(record.path)
        if entry is None:
            return None
        try:
            return int(entry.get(F_HIT_COUNT))
        except (TypeError, ValueError):
            return None


# === CHECKS ===
def check_any_any(record, ctx):
    rule = record.rule
    if not (is_wildcard(listed_values(rule, "source_groups"))
            and is_wildcard(listed_values(rule, "destination_groups"))):
        return []
    if rule.get(F_DISABLED):
        return []
    action = rule.get(F_ACTION_FIELD, "?")
    if action == "ALLOW":
        return [Finding("any_any_allow", "critical", record,
                        "source and destination are both ANY with ALLOW -- "
                        "permits all traffic in scope")]
    return [Finding("any_any_other", "high", record,
                    "source and destination are both ANY (action {})".format(
                        action))]


def check_broad_applied_to(record, ctx):
    rule = record.rule
    if rule.get(F_DISABLED):
        return []
    if is_wildcard(listed_values(rule, F_SCOPE)):
        return [Finding("broad_applied_to", "high", record,
                        "applied-to is ANY -- enforced on every workload, "
                        "not a scoped set")]
    return []


def check_group_references(record, ctx):
    findings = []
    for ref in sorted(record.group_refs()):
        if ref == ANY:
            continue
        entry = ctx.groups.get(ref)
        if entry is None:
            findings.append(Finding(
                "missing_group", "critical", record,
                "references a group that does not exist: {}".format(ref)))
            continue
        _, group = entry
        name = group.get(F_DISPLAY_NAME, ref)
        if not (group.get(F_EXPRESSION) or []):
            findings.append(Finding(
                "no_criteria_group", "medium", record,
                "group '{}' has no membership criteria -- the rule is "
                "inert".format(name)))
            continue
        count = ctx.member_counts.get(ref)
        if count == 0:
            findings.append(Finding(
                "empty_group", "low", record,
                "group '{}' currently resolves to 0 VM members".format(name),
                confidence="soft"))
    return findings


def check_disabled(record, ctx):
    if record.rule.get(F_DISABLED):
        return [Finding("disabled_rule", "low", record,
                        "disabled -- dead configuration carried in the "
                        "policy")]
    return []


def check_deny_not_logged(record, ctx):
    rule = record.rule
    if rule.get(F_DISABLED):
        return []
    if rule.get(F_ACTION_FIELD) in DENY_ACTIONS and not rule.get(F_LOGGED):
        return [Finding("drop_not_logged", "medium", record,
                        "{} with logging off -- drops leave no forensic "
                        "trail".format(rule.get(F_ACTION_FIELD)))]
    return []


def check_duplicate(record, ctx):
    key = match_key(record.rule)
    for other in ctx.earlier_siblings(record):
        if match_key(other.rule) == key:
            return [Finding("duplicate_rule", "medium", record,
                            "identical match criteria to earlier rule "
                            "'{}' in the same policy".format(other.rule_name))]
    return []


def check_shadowed(record, ctx):
    """Only flags what is provable without port or CIDR arithmetic."""
    if record.rule.get(F_DISABLED):
        return []
    for other in ctx.earlier_siblings(record):
        if matches_everything(other.rule):
            return [Finding(
                "shadowed_by_any_any", "high", record,
                "unreachable: earlier rule '{}' in this policy matches all "
                "traffic with {}".format(
                    other.rule_name, other.rule.get(F_ACTION_FIELD)))]
    return []


def check_unused(record, ctx):
    if not ctx.stats_supported or record.rule.get(F_DISABLED):
        return []
    hits = ctx.hits_for(record)
    if hits is None or hits > 0:
        return []
    entry = ctx.stats.get(record.path) or {}
    stamp = entry.get(F_LAST_UPDATE)
    when = " (counters last updated {})".format(stamp) if stamp else ""
    return [Finding(
        "unused_rule", "medium", record,
        "no hits since counters were last reset{} -- NOT proof the rule is "
        "unused; use `nsxctl rule baseline` for that".format(when),
        confidence="soft")]


CHECKS = (
    check_any_any,
    check_broad_applied_to,
    check_group_references,
    check_disabled,
    check_deny_not_logged,
    check_duplicate,
    check_shadowed,
    check_unused,
)


def evaluate(ctx):
    findings = []
    for record in ctx.records:
        for check in CHECKS:
            findings.extend(check(record, ctx) or [])
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check,
                                 f.record.policy_name, f.record.rule_name))
    return findings


def build_context(sessions, domain, with_members=True):
    records = sweep_rules(sessions, domain)
    groups = group_inventory(sessions, domain)
    stats, supported = fetch_hit_counts(records, domain)
    referenced = {ref for record in records for ref in record.group_refs()
                  if ref != ANY and ref in groups}
    member_counts = {}
    if with_members and referenced:
        member_counts = group_member_counts(
            {path: groups[path] for path in referenced}, domain)
    return HygieneContext(records, groups, stats, supported, member_counts)


# === ACTION ===
def act_hygiene(sessions, domain, exporter, with_members=True):
    """Returns (findings, worst_severity_or_None)."""
    section("DFW RULE HYGIENE")
    ctx = build_context(sessions, domain, with_members=with_members)
    say("  {} rule(s) across {} manager(s), {} group(s) referenced".format(
        cC(str(len(ctx.records))), len(sessions), len(ctx.groups)))
    if not ctx.stats_supported:
        say("  {} hit counters unavailable on this NSX -- unused-rule checks "
            "skipped.".format(cBY("note:")))
    not_measurable = sum(1 for v in ctx.member_counts.values() if v is None)
    if not_measurable:
        say("  {} {} referenced group(s) are not VM-resolvable, so their "
            "member counts are {} -- never reported as empty.".format(
                cD("note:"), not_measurable, cD("not measurable")))
    hr()

    findings = evaluate(ctx)
    rows = [f.row() for f in findings]
    exporter.stage("rule_hygiene", HYGIENE_HEADERS, rows)
    exporter.stage_findings("rule_hygiene", [
        make_finding(f.check, f.severity, f.detail,
                     where="{}/{}".format(f.record.policy_name,
                                          f.record.rule_name),
                     detail="[{}] {}".format(f.confidence, f.detail))
        for f in findings])

    if not findings:
        say("  {} no hygiene problems found.".format(cBG("Clean:")))
        return findings, None

    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    say("  {}".format(cB("Summary")))
    table(["Severity", "Findings"],
          [[_colour(sev)(sev), str(counts[sev])]
           for sev in SEVERITIES if sev in counts], indent=4)

    for severity in SEVERITIES:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        say("\n  {} ({})".format(_colour(severity)(severity.upper()),
                                 len(group)))
        hr()
        for finding in group[:HYGIENE_CONSOLE_LIMIT]:
            soft = "  {}".format(cD("[soft]")) if finding.confidence == "soft" \
                else ""
            say("    {} / {}   {}{}".format(
                cB(finding.record.policy_name), finding.record.rule_name,
                cD(finding.check), soft))
            say("      {}".format(finding.detail))
        more_note(HYGIENE_CONSOLE_LIMIT, len(group))

    hr()
    worst = next(s for s in SEVERITIES if s in counts)
    say("  {} finding(s); worst severity {}.".format(
        cC(str(len(findings))), _colour(worst)(worst)))
    return findings, worst


def _colour(severity):
    return {"critical": cBR, "high": cBY, "medium": cY, "low": cD}.get(
        severity, cD)


def worst_severity(findings):
    present = {f.severity for f in findings}
    for severity in SEVERITIES:
        if severity in present:
            return severity
    return None


def at_or_above(findings, threshold):
    """Findings at or above a severity, for --fail-on."""
    if threshold not in SEVERITIES:
        return []
    limit = SEVERITIES.index(threshold)
    return [f for f in findings if SEVERITIES.index(f.severity) <= limit]


# ==========================================================================
# actions/author.py  --  Authoring groups and rules: plan, preflight, confirm, write, audit.
# ==========================================================================

AUTHOR_HEADERS = ["op", "kind", "manager", "object", "field", "before",
                  "after", "impact"]

OBJECT_TYPE_FOR_KIND = {KIND_GROUP: OBJ_GROUP, KIND_RULE: OBJ_RULE}


class PlanCache:
    """One read of NSX per plan, not one per planned object.

    Planning a rule needs the rule sweep, the group inventory and the service
    inventory. Planning fifty of them from a change file needs those exactly
    once -- doing it per entry is the same N+1 that made bulk tagging sweep
    the VM inventory once per CSV row before Phase 1 fixed it.
    """

    __slots__ = ("sessions", "domain", "_records", "_groups", "_services",
                 "_policies", "planned_paths")

    def __init__(self, sessions, domain):
        self.sessions = sessions
        self.domain = domain
        self._records = None
        self._groups = None
        self._services = None
        self._policies = None
        # Objects an earlier entry in the same plan will create. A change
        # file that creates a group and a rule referencing it is the central
        # use case, and the group does not exist to be looked up yet.
        self.planned_paths = {}

    @property
    def records(self):
        if self._records is None:
            self._records = sweep_rules(self.sessions, self.domain)
        return self._records

    @property
    def groups(self):
        if self._groups is None:
            self._groups = group_inventory(self.sessions, self.domain)
        return self._groups

    @property
    def policies(self):
        """[(nsx, policy)] across every manager, GM first."""
        if self._policies is None:
            gm_sessions, lm_sessions = ordered_sessions(self.sessions)
            self._policies = [(nsx, policy)
                              for nsx in gm_sessions + lm_sessions
                              for policy in policies_for(nsx, self.domain)]
        return self._policies

    @property
    def services(self):
        if self._services is None:
            self._services = service_inventory(self.sessions, self.domain)
        return self._services

    def group_index(self):
        index = reference_index({p: g for p, (_n, g) in self.groups.items()})
        index.update(self.planned_paths)
        return index

    def service_index(self):
        return reference_index(self.services)

    def will_create(self, key, path):
        for alias in key:
            if alias:
                self.planned_paths[str(alias).lower()] = path


class AuthorResult:
    __slots__ = ("planned", "applied", "failed", "blocked", "changes")

    def __init__(self):
        self.planned = 0
        self.applied = 0
        self.failed = 0
        self.blocked = 0
        self.changes = []


# === LOCATING THINGS ===
def find_policy(sessions, domain, ref, cache=None):
    """(nsx, policy) for a security policy named by id or display name."""
    if cache is None:
        cache = PlanCache(sessions, domain)
    needle = str(ref).strip().lower()
    for nsx, policy in cache.policies:
        if needle in (str(policy.get(F_ID, "")).lower(),
                      str(policy.get(F_DISPLAY_NAME, "")).lower()):
            return nsx, policy
    raise NsxError(
        "No security policy called '{}' in domain {}.".format(ref, domain))


def find_rule(sessions, domain, ref, policy_ref=None, cache=None):
    """The RuleRecord for a rule named by id or display name."""
    needle = str(ref).strip().lower()
    records = cache.records if cache is not None else sweep_rules(sessions,
                                                                  domain)
    hits = []
    for record in records:
        if needle not in (str(record.rule_id).lower(),
                          str(record.rule_name).lower()):
            continue
        if policy_ref and str(policy_ref).lower() not in (
                str(record.policy_id).lower(),
                str(record.policy_name).lower()):
            continue
        hits.append(record)
    if not hits:
        raise NsxError("No rule called '{}' in domain {}.".format(ref, domain))
    if len(hits) > 1:
        raise NsxError(
            "'{}' matches {} rules ({}). Narrow it with --policy.".format(
                ref, len(hits),
                ", ".join(sorted({r.policy_name for r in hits}))))
    return hits[0]


def _author_writable(nsx, path, what):
    """Refuse a write to a GM-authored object through a Local Manager.

    NSX realizes Global Manager objects read-only onto each LM. Writing there
    fails inside NSX with a message about realization that reads like a bug in
    this tool, so it is caught here with the reason.
    """
    if path and origin_of_path(path) == "GM" and nsx.role == ROLE_LM:
        raise NsxError(
            "{} was authored on the Global Manager and is realized read-only "
            "onto {}. Change it on the GM, not here.".format(what, nsx.name))


# === PLAN RENDERING ===
def plan_rows(changes):
    """Export rows: one per changed field, one per create/delete."""
    rows = []
    for change in changes:
        if change.op == OP_MODIFY:
            for field in diff_objects(change.before or {}, change.after or {}):
                rows.append([change.op, change.kind, change.manager,
                             change.name, field.field,
                             fmt_diff_value(field.before),
                             fmt_diff_value(field.after), field.impact])
            continue
        rows.append([change.op, change.kind, change.manager, change.name, "",
                     "", "", "security"])
    return rows


def _author_op_colour(op):
    return {OP_CREATE: cG, OP_MODIFY: cBY, OP_DELETE: cR}.get(op, cD)


def print_plan(changes):
    """The preview, rendered exactly the way `nsxctl drift` renders a change."""
    for change in changes:
        say("  {} {} {}   [{}]".format(
            _author_op_colour(change.op)(change.op.upper()),
            cD(change.kind), cB(str(change.name)), cC(change.manager)))
        if change.op == OP_MODIFY:
            fields = diff_objects(change.before or {}, change.after or {})
            fields = [f for f in fields if _author_is_real_change(f)]
            if not fields:
                say("      {}".format(cD("no change")))
                continue
            for field in fields:
                marker = cBR("[security]") if field.impact == "security" \
                    else cD("[cosmetic]")
                say("      {} {}: {} -> {}".format(
                    marker, field.field,
                    fmt_diff_value(field.before) or cD("(unset)"),
                    fmt_diff_value(field.after) or cD("(unset)")))
        elif change.op == OP_CREATE:
            for line in _author_body_lines(change.kind, change.after or {}):
                say("      {}".format(line))
        else:
            for line in _author_body_lines(change.kind, change.before or {}):
                say("      {}".format(cD(line)))


def _author_is_real_change(field):
    """Volatile NSX bookkeeping is not a change worth showing in a plan."""
    root = field.field.split(".", 1)[0].split("[", 1)[0]
    return not root.startswith("_") and root not in (
        "realization_id", "unique_id", "parent_path", "relative_path",
        "marked_for_delete", "overridden", "path", "resource_type")


def _author_body_lines(kind, body):
    if kind == KIND_GROUP:
        return ["criteria: {}".format(
            describe_criteria(body.get(F_EXPRESSION)) or "(none)")]
    return [
        "source      : {}".format(", ".join(body.get(F_SOURCE_GROUPS) or [ANY])),
        "destination : {}".format(", ".join(body.get(F_DEST_GROUPS) or [ANY])),
        "services    : {}".format(", ".join(body.get(F_SERVICES) or [ANY])),
        "applied to  : {}".format(", ".join(body.get(F_SCOPE) or [ANY])),
        "action      : {}  seq {}".format(body.get(F_ACTION_FIELD, "?"),
                                          body.get(F_SEQUENCE_NUMBER, "?")),
    ]


# === PREFLIGHT ===
def preflight_findings(change, sessions, domain, cache=None):
    """The 2B hygiene checks, run against a rule before it is written.

    A HygieneContext is assembled from the proposed rule plus its real
    siblings, so shadowing and duplicate detection work against what the
    policy will actually look like -- not just against the rule in isolation.
    Statistics are marked unsupported because there are none for a rule that
    does not exist yet; every static check still runs.
    """
    if change.kind != KIND_RULE or change.op == OP_DELETE:
        return []
    if cache is None:
        cache = PlanCache(sessions, domain)
    policy = {F_ID: change.policy_id, F_DISPLAY_NAME: change.policy_id}
    siblings = []
    for record in cache.records:
        if record.policy_id != change.policy_id:
            continue
        if record.rule_id == change.object_id:
            policy = record.policy
            continue
        siblings.append(record)
        policy = record.policy
    proposed = RuleRecord(change.nsx, policy, change.after or {},
                          origin_of_path(change.path))
    ctx = HygieneContext(siblings + [proposed], cache.groups, {}, False, {})
    return [f for f in evaluate(ctx) if f.record is proposed]


def print_preflight(findings):
    if not findings:
        return
    say("\n  {} the proposed change would be reported by "
        "`nsxctl rule hygiene`:".format(cBY("PREFLIGHT:")))
    for finding in findings:
        say("    {} {}".format(
            cBR(finding.severity) if finding.severity in ("critical", "high")
            else cBY(finding.severity), cD(finding.check)))
        say("      {}".format(finding.detail))


# === EXECUTION ===
def execute_plan(changes, audit, write_enabled, dry_run=True, force=False,
                 sessions=None, domain="default", exporter=None,
                 preflight=True, cache=None):
    """Preview, confirm and apply a set of planned writes."""
    result = AuthorResult()
    result.changes = list(changes)
    result.planned = len(changes)

    label = cBY("DRY RUN") if dry_run else cBG("APPLYING")
    say("\n  {} -- {} change(s)".format(label, len(changes)))
    hr()
    if not changes:
        say("  {}".format(cD("Nothing to do: NSX already matches.")))
        if exporter is not None:
            exporter.stage("authoring", AUTHOR_HEADERS, [])
        return result
    print_plan(changes)

    if preflight and sessions:
        # One cache for every change: preflighting fifty rules must not sweep
        # the estate fifty times.
        cache = cache or PlanCache(sessions, domain)
        for change in changes:
            print_preflight(preflight_findings(change, sessions, domain,
                                               cache=cache))

    if exporter is not None:
        exporter.stage("authoring", AUTHOR_HEADERS, plan_rows(changes))

    if dry_run:
        hr()
        say("  {} nothing was written. Re-run with {} to apply.".format(
            cD("Dry run:"), cC("--enable-writes")))
        return result
    if not write_enabled:
        say("  {}. Re-run with --enable-writes.".format(cBY("Writes disabled")))
        result.blocked = len(changes)
        return result
    if not confirm("\n  {} [y/N]: ".format(cB("Apply these changes?"))):
        say("  Cancelled.")
        result.blocked = len(changes)
        return result

    hr()
    for change in changes:
        try:
            after = apply_write(change, domain, force=force)
            audit.log_change(
                "author_" + change.op, change.manager,
                OBJECT_TYPE_FOR_KIND.get(change.kind, change.kind),
                change.path or change.url, str(change.name),
                change.before, after if change.op != OP_DELETE else None,
                detail=change.describe())
            ok_msg("{}  [{}]".format(change.describe(), change.manager))
            result.applied += 1
        except NsxError as e:
            say("  {} {}".format(cBR("FAILED"), change.describe()))
            say("      {}".format(cD(str(e)[:400])))
            audit.log_change(
                "author_" + change.op, change.manager,
                OBJECT_TYPE_FOR_KIND.get(change.kind, change.kind),
                change.path or change.url, str(change.name),
                change.before, None, status="failed", detail=str(e)[:400])
            result.failed += 1
    hr()
    say("  Complete: {} applied, {} failed.".format(
        cG(str(result.applied)), cR(str(result.failed))))
    return result


# === TAXONOMY ===
def warn_off_taxonomy(expression, taxonomy):
    """Criteria that names a tag your taxonomy does not allow."""
    if not taxonomy:
        return
    for item in expression or []:
        if item.get(RT) != RT_CONDITION or item.get("key") != KEY_TAG:
            continue
        value = str(item.get("value", ""))
        if TAG_SCOPE_SEPARATOR not in value:
            continue
        scope, _, tag = value.partition(TAG_SCOPE_SEPARATOR)
        for message in taxonomy.validate_tag(scope, tag):
            warn(message)


# === GROUP ACTIONS ===
def plan_group(sessions, domain, group_id, criteria=None, display_name=None,
               description=None, delete=False, manager=None, taxonomy=None,
               cache=None):
    """One planned write for a group."""
    cache = cache or PlanCache(sessions, domain)
    groups = cache.groups
    index = cache.group_index()
    existing_path = index.get(str(group_id).lower())
    nsx = None
    existing = None
    if existing_path:
        nsx, existing = groups[existing_path]
        group_id = existing.get(F_ID, group_id)
        _author_writable(nsx, existing_path, "Group '{}'".format(group_id))
    if manager:
        nsx = next((s for s in sessions if s.name == manager), None)
        if nsx is None:
            raise NsxError("'{}' is not a connected manager.".format(manager))
    if nsx is None:
        gm_sessions, lm_sessions = ordered_sessions(sessions)
        nsx = (gm_sessions + lm_sessions)[0]

    url = object_url(nsx, domain, KIND_GROUP, group_id)
    if delete:
        if existing is None:
            raise NsxError("No group called '{}' to delete.".format(group_id))
        return [PlannedWrite(OP_DELETE, KIND_GROUP, nsx, url, group_id,
                             existing.get(F_DISPLAY_NAME, group_id),
                             before=existing, path=existing_path)]

    expression = parse_criteria(criteria) if criteria is not None else None
    if expression is not None:
        warn_off_taxonomy(expression, taxonomy)
    if existing is None and expression is None:
        raise NsxError(
            "Creating a group needs --criteria. See `nsxctl group create "
            "--help` for the syntax.")
    after = build_group_body(group_id, display_name or (
        existing or {}).get(F_DISPLAY_NAME) or group_id, expression,
        description=description, existing=existing)
    op = OP_MODIFY if existing is not None else OP_CREATE
    if op == OP_MODIFY and not [
            f for f in diff_objects(existing, after)
            if _author_is_real_change(f)]:
        return []
    path = existing_path or "{}/domains/{}/groups/{}".format(
        policy_path_prefix(nsx.base(domain)), domain, group_id)
    if op == OP_CREATE:
        # A rule later in the same plan may reference this group by any of
        # its names, and it does not exist to be looked up yet.
        cache.will_create((group_id, after.get(F_DISPLAY_NAME)), path)
    return [PlannedWrite(op, KIND_GROUP, nsx, url, group_id,
                         after.get(F_DISPLAY_NAME, group_id), before=existing,
                         after=after, path=path)]


# === RULE ACTIONS ===
def plan_rule(sessions, domain, rule_id, policy_ref=None, sources=None,
              destinations=None, services=None, action=None, scope=None,
              direction=None, display_name=None, description=None,
              disabled=None, logged=None, sequence_number=None, delete=False,
              move_before=None, move_after=None, cache=None):
    """One planned write for a DFW rule."""
    cache = cache or PlanCache(sessions, domain)
    record = None
    if policy_ref is None or not delete:
        try:
            record = find_rule(sessions, domain, rule_id,
                               policy_ref=policy_ref, cache=cache)
        except NsxError:
            record = None
    if record is None and delete:
        raise NsxError("No rule called '{}' to delete.".format(rule_id))

    if record is not None:
        nsx, policy = record.nsx, record.policy
        existing = record.rule
        rule_id = existing.get(F_ID, rule_id)
        _author_writable(nsx, record.path, "Rule '{}'".format(rule_id))
    else:
        if not policy_ref:
            raise NsxError(
                "Creating a rule needs --policy to say where it goes.")
        nsx, policy = find_policy(sessions, domain, policy_ref, cache=cache)
        existing = None
        _author_writable(nsx, policy.get(F_PATH, ""),
                         "Policy '{}'".format(policy.get(F_DISPLAY_NAME)))

    policy_id = policy.get(F_ID, policy_ref)
    url = object_url(nsx, domain, KIND_RULE, rule_id, policy_id=policy_id)
    if delete:
        return [PlannedWrite(OP_DELETE, KIND_RULE, nsx, url, rule_id,
                             existing.get(F_DISPLAY_NAME, rule_id),
                             before=existing, policy_id=policy_id,
                             path=record.path)]

    siblings = [r for r in cache.records if r.policy_id == policy_id]
    if move_before or move_after:
        target = find_rule(sessions, domain, move_before or move_after,
                           policy_ref=policy_id, cache=cache)
        sequence_number = sequence_for_move(siblings, target,
                                            before=bool(move_before))
    elif existing is None and sequence_number is None:
        highest = max([int(r.rule.get(F_SEQUENCE_NUMBER) or 0)
                       for r in siblings] or [0])
        sequence_number = highest + 10

    group_index = cache.group_index()
    service_index = cache.service_index()

    after = build_rule_body(
        rule_id, display_name=display_name,
        sources=resolve_references(group_index, sources) if sources else None,
        destinations=(resolve_references(group_index, destinations)
                      if destinations else None),
        services=(resolve_references(service_index, services, what="service")
                  if services else None),
        scope=resolve_references(group_index, scope) if scope else None,
        action=validate_action(action), direction=validate_direction(direction),
        disabled=disabled, logged=logged, sequence_number=sequence_number,
        description=description, existing=existing)

    op = OP_MODIFY if existing is not None else OP_CREATE
    if op == OP_MODIFY and not [
            f for f in diff_objects(existing, after)
            if _author_is_real_change(f)]:
        return []
    return [PlannedWrite(op, KIND_RULE, nsx, url, rule_id,
                         after.get(F_DISPLAY_NAME, rule_id), before=existing,
                         after=after, policy_id=policy_id,
                         path=record.path if record else "")]


# === DECLARATIVE APPLY ===
def plan_change_file(sessions, domain, path, taxonomy=None, cache=None):
    """Every planned write a declarative change file asks for.

    Groups are planned before rules, and share one cache, so a rule may
    reference a group the same file creates -- which is the whole reason to
    write one file instead of two commands.
    """
    data = load_change_file(path)
    cache = cache or PlanCache(sessions, domain)
    changes = []
    for entry in (data.get("groups") or []):
        absent = str(entry.get("state", "")).lower() == STATE_ABSENT
        changes.extend(plan_group(
            sessions, domain, entry["id"], criteria=entry.get("criteria"),
            display_name=entry.get("display_name"),
            description=entry.get("description"), delete=absent,
            manager=entry.get("manager"), taxonomy=taxonomy, cache=cache))
    for entry in (data.get("rules") or []):
        absent = str(entry.get("state", "")).lower() == STATE_ABSENT
        changes.extend(plan_rule(
            sessions, domain, entry["id"], policy_ref=entry.get("policy"),
            sources=_author_as_list(entry.get("source")),
            destinations=_author_as_list(entry.get("destination")),
            services=_author_as_list(entry.get("services")),
            scope=_author_as_list(entry.get("applied_to")),
            action=entry.get("action"), direction=entry.get("direction"),
            display_name=entry.get("display_name"),
            description=entry.get("description"),
            disabled=entry.get("disabled"), logged=entry.get("logged"),
            sequence_number=entry.get("sequence_number"), delete=absent,
            cache=cache))
    return changes


def _author_as_list(value):
    if value is None:
        return None
    return [value] if isinstance(value, str) else list(value)


# === TOP-LEVEL ACTIONS ===
def act_group_write(ctx, group_id, criteria=None, display_name=None,
                    description=None, delete=False, dry_run=True, force=False):
    section("GROUP {}".format("DELETE" if delete else "WRITE"))
    cache = PlanCache(ctx.sessions, ctx.domain)
    changes = plan_group(ctx.sessions, ctx.domain, group_id, criteria=criteria,
                         display_name=display_name, description=description,
                         delete=delete, taxonomy=ctx.taxonomy, cache=cache)
    return execute_plan(changes, ctx.audit, ctx.write_enabled, dry_run=dry_run,
                        force=force, sessions=ctx.sessions, domain=ctx.domain,
                        exporter=ctx.exporter, cache=cache)


def act_rule_write(ctx, rule_id, dry_run=True, force=False, **kwargs):
    section("RULE {}".format("DELETE" if kwargs.get("delete") else "WRITE"))
    cache = PlanCache(ctx.sessions, ctx.domain)
    changes = plan_rule(ctx.sessions, ctx.domain, rule_id, cache=cache,
                        **kwargs)
    return execute_plan(changes, ctx.audit, ctx.write_enabled, dry_run=dry_run,
                        force=force, sessions=ctx.sessions, domain=ctx.domain,
                        exporter=ctx.exporter, cache=cache)


def act_apply_file(ctx, path, dry_run=True, force=False):
    section("APPLY {}".format(path))
    cache = PlanCache(ctx.sessions, ctx.domain)
    changes = plan_change_file(ctx.sessions, ctx.domain, path,
                               taxonomy=ctx.taxonomy, cache=cache)
    return execute_plan(changes, ctx.audit, ctx.write_enabled, dry_run=dry_run,
                        force=force, sessions=ctx.sessions, domain=ctx.domain,
                        exporter=ctx.exporter, cache=cache)


# === SNAPSHOT RESTORE ===
def plan_restore(sessions, domain, snapshot, cache=None, prune=False,
                 kinds=(KIND_GROUP, KIND_RULE)):
    """Planned writes that bring live NSX back to a snapshot.

    Deliberately per-object through the same engine as every other write, not
    a bulk push of a whole tree: each object gets a field-level diff you can
    read, a `_revision` check that refuses to clobber a concurrent edit, and
    its own audit entry. A blind whole-DFW restore is a different class of
    risk, and this is not that.

    **Deleting is opt-in.** An object that exists live and not in the snapshot
    is left alone unless `prune` is set: a snapshot is a record of what was
    there, not an assertion that nothing else may exist, and something created
    legitimately since is not drift to be erased.
    """
    cache = cache or PlanCache(sessions, domain)
    changes = []
    objects = snapshot.get("objects") or {}
    live_groups = cache.groups
    live_rules = {r.path: r for r in cache.records if r.path}

    for path, entry in sorted(objects.items()):
        kind_name = entry.get("kind")
        body = dict(entry.get("body") or {})
        if kind_name == "groups" and KIND_GROUP in kinds:
            changes.extend(_restore_group(sessions, domain, cache, path, body,
                                          live_groups))
        elif kind_name == "rules" and KIND_RULE in kinds:
            changes.extend(_restore_rule(cache, path, body, live_rules,
                                         domain))

    if prune:
        changes.extend(_prune_extras(cache, objects, live_groups, live_rules,
                                     domain, kinds))
    return [c for c in changes if c is not None]


def _restore_group(sessions, domain, cache, path, body, live_groups):
    group_id = body.get(F_ID) or path.rsplit("/", 1)[-1]
    existing_entry = live_groups.get(path)
    if existing_entry is None:
        # Match on id as well: a group recreated by hand has a new path.
        for live_path, (nsx, group) in live_groups.items():
            if group.get(F_ID) == group_id:
                existing_entry = (nsx, group)
                path = live_path
                break
    if existing_entry is not None:
        nsx, existing = existing_entry
    else:
        gm_sessions, lm_sessions = ordered_sessions(sessions)
        if not gm_sessions + lm_sessions:
            return []
        nsx, existing = (gm_sessions + lm_sessions)[0], None
    _author_writable(nsx, path, "Group '{}'".format(group_id))
    after = dict(existing or {})
    after.update(body)
    if existing is not None and not [
            f for f in diff_objects(existing, after)
            if _author_is_real_change(f)]:
        return []
    url = object_url(nsx, domain, KIND_GROUP, group_id)
    return [PlannedWrite(OP_MODIFY if existing else OP_CREATE, KIND_GROUP,
                         nsx, url, group_id,
                         after.get(F_DISPLAY_NAME, group_id),
                         before=existing, after=after, path=path)]


def _restore_rule(cache, path, body, live_rules, domain):
    record = live_rules.get(path)
    rule_id = body.get(F_ID) or path.rsplit("/", 1)[-1]
    policy_id = policy_id_from_rule_path(path)
    if record is None:
        # The rule is gone. Recreating it needs a manager that still has the
        # policy; without one there is nothing to restore it into.
        for candidate in cache.records:
            if candidate.policy_id == policy_id:
                record = candidate
                break
        if record is None:
            return []
        nsx, existing = record.nsx, None
    else:
        nsx, existing = record.nsx, record.rule
    _author_writable(nsx, path, "Rule '{}'".format(rule_id))
    after = dict(existing or {})
    after.update(body)
    if existing is not None and not [
            f for f in diff_objects(existing, after)
            if _author_is_real_change(f)]:
        return []
    url = object_url(nsx, domain, KIND_RULE, rule_id, policy_id=policy_id)
    return [PlannedWrite(OP_MODIFY if existing else OP_CREATE, KIND_RULE, nsx,
                         url, rule_id, after.get(F_DISPLAY_NAME, rule_id),
                         before=existing, after=after, policy_id=policy_id,
                         path=path)]


def _prune_extras(cache, objects, live_groups, live_rules, domain, kinds):
    """Objects that exist live but not in the snapshot. Only with --prune."""
    changes = []
    snapshot_ids = {(e.get("kind"), (e.get("body") or {}).get(F_ID))
                    for e in objects.values()}
    if KIND_RULE in kinds:
        for path, record in sorted(live_rules.items()):
            if ("rules", record.rule_id) in snapshot_ids or path in objects:
                continue
            if origin_of_path(path) == "GM" and record.nsx.role == ROLE_LM:
                continue
            changes.append(PlannedWrite(
                OP_DELETE, KIND_RULE, record.nsx,
                object_url(record.nsx, domain, KIND_RULE, record.rule_id,
                           policy_id=record.policy_id),
                record.rule_id, record.rule_name, before=record.rule,
                policy_id=record.policy_id, path=path))
    if KIND_GROUP in kinds:
        for path, (nsx, group) in sorted(live_groups.items()):
            gid = group.get(F_ID)
            if ("groups", gid) in snapshot_ids or path in objects:
                continue
            if origin_of_path(path) == "GM" and nsx.role == ROLE_LM:
                continue
            changes.append(PlannedWrite(
                OP_DELETE, KIND_GROUP, nsx,
                object_url(nsx, domain, KIND_GROUP, gid), gid,
                group.get(F_DISPLAY_NAME, gid), before=group, path=path))
    return changes


def act_restore(ctx, snapshot, dry_run=True, force=False, prune=False):
    section("RESTORE FROM SNAPSHOT")
    manifest = snapshot.get("manifest", {})
    say("  Snapshot taken : {}".format(manifest.get("taken", "?")))
    say("  Domain         : {}".format(manifest.get("domain", "?")))
    if prune:
        say("  {} objects not in the snapshot will be DELETED.".format(
            cBR("--prune:")))
    else:
        say("  {}".format(cD(
            "Objects that exist now but not in the snapshot are left alone. "
            "Pass --prune to delete them.")))
    cache = PlanCache(ctx.sessions, ctx.domain)
    changes = plan_restore(ctx.sessions, ctx.domain, snapshot, cache=cache,
                           prune=prune)
    return execute_plan(changes, ctx.audit, ctx.write_enabled,
                        dry_run=dry_run, force=force, sessions=ctx.sessions,
                        domain=ctx.domain, exporter=ctx.exporter, cache=cache)


# === UNDO ===
def undo_object_entry(entry, sessions, domain, audit, force=False):
    """Reverse one audited object write.

    Asymmetric on purpose, and the messages say which case they are in:
    undoing a create is a delete and undoing a modify is a PUT of the
    before-body, both exact; undoing a delete recreates an object whose
    references may have been cleaned up underneath it, which cannot be
    guaranteed and says so.
    """
    kind = KIND_GROUP if entry["object_type"] == OBJ_GROUP else KIND_RULE
    path = entry.get("object_path") or ""
    nsx = next((s for s in sessions if s.name == entry.get("manager")), None)
    if nsx is None:
        raise NsxError("Manager '{}' is not in this session.".format(
            entry.get("manager")))

    object_id = path.rsplit("/", 1)[-1]
    policy_id = None
    if kind == KIND_RULE:
        policy_id = policy_id_from_rule_path(path)
    url = object_url(nsx, domain, kind, object_id, policy_id=policy_id)
    live = read_object(nsx, domain, kind, object_id, policy_id=policy_id)

    before, after = entry.get("before"), entry.get("after")
    if before is None and after is not None:
        if live is None:
            raise NsxError("Already gone -- nothing to undo.")
        change = PlannedWrite(OP_DELETE, kind, nsx, url, object_id,
                              entry.get("object_name", object_id),
                              before=live, policy_id=policy_id, path=path)
    elif before is not None and after is None:
        say("  {} recreating a deleted object cannot be guaranteed: anything "
            "that referenced it may have been cleaned up in the "
            "meantime.".format(cBY("note:")))
        say("  {}".format(cD(
            "A snapshot restore is the reliable way back from a delete.")))
        change = PlannedWrite(OP_CREATE, kind, nsx, url, object_id,
                              entry.get("object_name", object_id),
                              after=before, policy_id=policy_id, path=path)
    else:
        if live is None:
            raise NsxError(
                "The object no longer exists on {}, so a modify cannot be "
                "reversed. Recreate it, or restore from a snapshot.".format(
                    nsx.name))
        change = PlannedWrite(OP_MODIFY, kind, nsx, url, object_id,
                              entry.get("object_name", object_id),
                              before=live, after=before, policy_id=policy_id,
                              path=path)
    print_plan([change])
    if not confirm("\n  {} [y/N]: ".format(cB("Apply this undo?"))):
        say("  Cancelled.")
        return False
    result = apply_write(change, domain, force=force)
    audit.log_change("undo_" + change.op, nsx.name, entry["object_type"],
                     path, str(change.name), change.before,
                     result if change.op != OP_DELETE else None,
                     detail="undo of {}".format(entry.get("timestamp", "?")))
    ok_msg("Undo applied.")
    return True


def author_menu(ctx):
    """Interactive entry: menu 18.

    Deliberately narrow. Authoring has far more surface than a numbered menu
    can carry safely, so this covers the two everyday shapes and points at
    the command line for the rest.
    """
    say("\n  1. Create or edit a group")
    say("  2. Apply a declarative change file")
    choice = ask("  Choice: ")
    try:
        if choice == "1":
            group_id = ask("  Group id: ")
            if not group_id:
                return
            say("  {}".format(cD(CRITERIA_HELP)))
            criteria = ask("  Criteria: ")
            if not criteria:
                return
            act_group_write(ctx, group_id, criteria=criteria,
                            dry_run=not ctx.write_enabled)
        elif choice == "2":
            path = ask("  Change file path: ")
            if path:
                act_apply_file(ctx, path, dry_run=not ctx.write_enabled)
        else:
            say("  Not a valid choice.")
    except (NsxError, ConfigError) as e:
        err(str(e))


# ==========================================================================
# actions/inspect.py  --  Reading rules, policies and services.
# ==========================================================================

RULE_HEADERS = ["manager", "origin", "category", "policy", "seq", "rule",
                "action", "direction", "source", "destination", "service",
                "applied_to", "state", "rule_id"]
POLICY_HEADERS = ["manager", "origin", "category", "seq", "id", "name",
                  "rules", "applied_to"]
SERVICE_HEADERS = ["id", "name", "protocol", "ports", "kind"]

LIST_CONSOLE_LIMIT = 60


def _short_refs(paths, limit=2):
    """Group paths as short ids, because a full NSX path is 60 characters of
    prefix and 8 of meaning."""
    values = [p for p in (paths or []) if p]
    if not values or values == [ANY]:
        return ANY
    names = [group_id_from_path(p) for p in values]
    if len(names) <= limit:
        return ", ".join(names)
    return "{}, +{}".format(", ".join(names[:limit]), len(names) - limit)


def _state(rule):
    return "disabled" if rule.get(F_DISABLED) else "enabled"


def _rule_action_colour(action):
    return {"ALLOW": cG, "DROP": cR, "REJECT": cR}.get(action, cY)


def rule_row(record):
    rule = record.rule
    return [record.nsx.name, record.origin,
            str(record.policy.get(F_CATEGORY, "")),
            record.policy_name, str(rule.get(F_SEQUENCE_NUMBER, "")),
            record.rule_name, rule.get(F_ACTION_FIELD, "?"),
            rule.get(F_DIRECTION, ""),
            _short_refs(rule.get(F_SOURCE_GROUPS)),
            _short_refs(rule.get(F_DEST_GROUPS)),
            _short_refs(rule.get(F_SERVICES)),
            _short_refs(rule.get(F_SCOPE)),
            _state(rule), str(rule.get(F_RULE_ID, ""))]


def _matches(record, needle, policy_ref, action, disabled_only):
    if needle and needle not in "{} {}".format(
            record.rule_name, record.rule_id).lower():
        return False
    if policy_ref and policy_ref not in "{} {}".format(
            record.policy_name, record.policy_id).lower():
        return False
    if action and str(record.rule.get(F_ACTION_FIELD, "")).upper() != action:
        return False
    if disabled_only and not record.rule.get(F_DISABLED):
        return False
    return True


def remember_names(kind, values, cache_key=None):
    """Refresh part of the completion cache, never fatally.

    A listing that succeeded must not fail because a cache file could not be
    written -- the user asked for a list, not for a cache.
    """
    if not cache_key:
        return
    try:
        update_cache(kind, values, *cache_key)
    except Exception:  # noqa: BLE001 - never break a read over a cache write
        pass


def act_rule_list(sessions, domain, exporter, contains=None, policy_ref=None,
                  action=None, disabled_only=False, cache_key=None):
    """Every DFW rule, in NSX evaluation order.

    Evaluation order rather than fetch order, because the order rules are
    listed in is the order they decide traffic in -- and a listing sorted any
    other way invites exactly the mistake `nsxctl trace` exists to catch.
    """
    section("DFW RULES")
    records = evaluation_order(sweep_rules(sessions, domain))
    needle = (contains or "").lower() or None
    policy_needle = (policy_ref or "").lower() or None
    wanted_action = (action or "").upper() or None
    hits = [r for r in records
            if _matches(r, needle, policy_needle, wanted_action, disabled_only)]

    say("  {} rule(s) across {} manager(s){}".format(
        cC(str(len(hits))), len(sessions),
        "" if len(hits) == len(records)
        else cD("  ({} total before filtering)".format(len(records)))))
    say("  {}".format(cD("listed in NSX evaluation order: category, then "
                         "policy and rule sequence")))
    hr()

    rows = [rule_row(r) for r in hits]
    exporter.stage("rules", RULE_HEADERS, rows)
    # Keep TAB completion warm off work somebody was doing anyway.
    remember_names(KIND_RULE, [r.rule_name for r in records]
                   + [r.rule_id for r in records], cache_key)
    remember_names(KIND_POLICY, [r.policy_name for r in records]
                   + [r.policy_id for r in records], cache_key)
    if not hits:
        say("  {}".format(cD("(nothing matches)")))
        return rows

    current = None
    shown = 0
    for record in hits:
        if shown >= LIST_CONSOLE_LIMIT:
            break
        key = (record.nsx.name, record.policy_id)
        if key != current:
            current = key
            category = record.policy.get(F_CATEGORY)
            say("\n  {}{}   [{}/{}]".format(
                cB(record.policy_name),
                cD("  ({})".format(category)) if category else "",
                cC(record.nsx.name), cD(record.origin)))
        rule = record.rule
        flag = cD("  [disabled]") if rule.get(F_DISABLED) else ""
        say("    {:>5}  {:26s} {:7s} {} -> {}   svc {}   applied {}{}".format(
            str(rule.get(F_SEQUENCE_NUMBER, "")),
            str(record.rule_name)[:26],
            _rule_action_colour(rule.get(F_ACTION_FIELD))(
                str(rule.get(F_ACTION_FIELD, "?"))),
            _short_refs(rule.get(F_SOURCE_GROUPS)),
            _short_refs(rule.get(F_DEST_GROUPS)),
            _short_refs(rule.get(F_SERVICES)),
            _short_refs(rule.get(F_SCOPE)), flag))
        shown += 1
    more_note(LIST_CONSOLE_LIMIT, len(hits))
    hr()
    return rows


def act_rule_show(sessions, domain, exporter, ref, policy_ref=None):
    """One rule in full, with every field spelled out rather than shortened."""
    section("RULE")
    record = find_rule(sessions, domain, ref, policy_ref=policy_ref)
    rule = record.rule
    say("  {}   {}".format(cB(record.rule_name),
                           cD(rule.get(F_ID, ""))))
    say("  policy      : {}  {}".format(
        record.policy_name, cD("({})".format(
            record.policy.get(F_CATEGORY, "?")))))
    say("  manager     : {}  [{}]".format(cC(record.nsx.name), record.origin))
    hr()
    for label, value in (
            ("action", _rule_action_colour(rule.get(F_ACTION_FIELD))(
                str(rule.get(F_ACTION_FIELD, "?")))),
            ("direction", rule.get(F_DIRECTION, "")),
            ("sequence", rule.get(F_SEQUENCE_NUMBER, "")),
            ("state", _state(rule)),
            ("logged", "yes" if rule.get(F_LOGGED) else "no"),
            ("realized id", rule.get(F_RULE_ID, "")),
            ("path", cD(record.path))):
        say("    {:12s}: {}".format(label, value))
    for label, field in (("source", F_SOURCE_GROUPS),
                         ("destination", F_DEST_GROUPS),
                         ("services", F_SERVICES),
                         ("applied to", F_SCOPE)):
        values = [v for v in (rule.get(field) or []) if v] or [ANY]
        say("    {:12s}: {}".format(label, values[0]))
        for extra in values[1:]:
            say("    {:12s}  {}".format("", extra))
    if rule.get("description"):
        say("    {:12s}: {}".format("description", rule["description"]))
    hr()
    say("  {} {}".format(cD("next:"), cC(
        "nsxctl trace VM_A VM_B --port N   # does this rule actually decide "
        "a flow?")))
    rows = [rule_row(record)]
    exporter.stage("rule", RULE_HEADERS, rows)
    return rows


def act_policy_list(sessions, domain, exporter, contains=None,
                    cache_key=None):
    """Security policies, in evaluation order, with their rule counts."""
    section("SECURITY POLICIES")
    records = sweep_rules(sessions, domain)
    counts = {}
    for record in records:
        counts[(record.nsx.name, record.policy_id)] = counts.get(
            (record.nsx.name, record.policy_id), 0) + 1

    gm_sessions, lm_sessions = ordered_sessions(sessions)
    needle = (contains or "").lower()
    seen = set()
    rows = []
    for nsx in gm_sessions + lm_sessions:
        for policy in policies_for(nsx, domain):
            path = policy.get(F_PATH, "")
            if path and path in seen:
                continue
            if path:
                seen.add(path)
            pid = policy.get(F_ID, "?")
            name = policy.get(F_DISPLAY_NAME, pid)
            if needle and needle not in "{} {}".format(name, pid).lower():
                continue
            rows.append([nsx.name, origin_of_path(path),
                         str(policy.get(F_CATEGORY, "")),
                         str(policy.get(F_SEQUENCE_NUMBER, "")),
                         pid, name, str(counts.get((nsx.name, pid), 0)),
                         _short_refs(policy.get(F_SCOPE))])

    rows.sort(key=lambda r: (category_rank(r[2]), r[3], r[5]))
    say("  {} policy(ies) across {} manager(s)".format(
        cC(str(len(rows))), len(sessions)))
    hr()
    table(["Manager", "Origin", "Category", "Seq", "Id", "Name", "Rules",
           "Applied to"],
          [[cC(r[0]), cD(r[1]), r[2], r[3], cB(r[4]), r[5], r[6], r[7]]
           for r in rows[:LIST_CONSOLE_LIMIT]], indent=4)
    more_note(LIST_CONSOLE_LIMIT, len(rows))
    exporter.stage("policies", POLICY_HEADERS, rows)
    remember_names(KIND_POLICY, [r[4] for r in rows] + [r[5] for r in rows],
                   cache_key)
    return rows


def describe_service(service):
    """(protocol, ports, kind) for one service definition.

    `kind` is what the port matcher in trace.py can do with it: an L4 port set
    reduces to a port comparison, anything else does not, and saying so here
    is what makes an undecided trace verdict explicable rather than mystifying.
    """
    entries = service.get(F_SERVICE_ENTRIES) or []
    if not entries:
        return "", "", "empty"
    protocols, ports, kinds = [], [], []
    for entry in entries:
        kind = entry.get(RT, "?")
        kinds.append(str(kind).replace("ServiceEntry", ""))
        if kind != RT_L4_PORTSET:
            continue
        protocols.append(str(entry.get(F_L4_PROTOCOL, "")))
        ports.extend(str(p) for p in (entry.get(F_DESTINATION_PORTS) or []))
    l4 = all(e.get(RT) == RT_L4_PORTSET for e in entries)
    return (",".join(sorted({p for p in protocols if p})),
            ",".join(ports) or ("any" if l4 else ""),
            "L4 port set" if l4 else "/".join(sorted(set(kinds))))


def act_service_list(sessions, domain, exporter, contains=None,
                     cache_key=None):
    """Service definitions, and whether each is one trace can decide."""
    section("SERVICES")
    services = service_inventory(sessions, domain)
    needle = (contains or "").lower()
    rows = []
    for path, service in sorted(services.items()):
        sid = service.get(F_ID, path)
        name = service.get(F_DISPLAY_NAME, sid)
        if needle and needle not in "{} {}".format(name, sid).lower():
            continue
        protocol, ports, kind = describe_service(service)
        rows.append([sid, name, protocol, ports, kind])

    say("  {} service(s)".format(cC(str(len(rows)))))
    hr()
    table(["Id", "Name", "Protocol", "Ports", "Kind"],
          [[cB(r[0]), r[1], r[2], r[3],
            r[4] if r[4] == "L4 port set" else cY(r[4])]
           for r in rows[:LIST_CONSOLE_LIMIT]], indent=4)
    more_note(LIST_CONSOLE_LIMIT, len(rows))
    not_l4 = sum(1 for r in rows if r[4] != "L4 port set")
    if not_l4:
        say("\n  {} {} service(s) are not plain L4 port sets, so "
            "`nsxctl trace`".format(cD("note:"), not_l4))
        say("  {}".format(cD(
            "reports a rule limited to one of them as undecided rather than "
            "guessing.")))
    exporter.stage("services", SERVICE_HEADERS, rows)
    remember_names(KIND_SERVICE, [r[0] for r in rows] + [r[1] for r in rows],
                   cache_key)
    return rows


def act_service_show(sessions, domain, exporter, ref):
    section("SERVICE")
    services = service_inventory(sessions, domain)
    needle = str(ref).strip().lower()
    hits = [s for s in services.values()
            if needle in (str(s.get(F_ID, "")).lower(),
                          str(s.get(F_DISPLAY_NAME, "")).lower())]
    if not hits:
        say("  {} no service called '{}'.".format(cBR("Not found:"), ref))
        exporter.stage("service", SERVICE_HEADERS, [])
        return []
    service = hits[0]
    protocol, ports, kind = describe_service(service)
    say("  {}   {}".format(cB(service.get(F_DISPLAY_NAME, ref)),
                           cD(service.get(F_ID, ""))))
    say("  path        : {}".format(cD(service.get(F_PATH, ""))))
    say("  kind        : {}".format(kind))
    hr()
    for entry in (service.get(F_SERVICE_ENTRIES) or []):
        say("    {}".format(cB(str(entry.get(RT, "?")))))
        for key in sorted(entry):
            if key in (RT, F_ID, F_DISPLAY_NAME, F_PATH) or key.startswith("_"):
                continue
            say("      {:20s} {}".format(key, entry[key]))
    if kind != "L4 port set":
        say("\n  {}".format(cD(
            "Not a plain L4 port set, so `nsxctl trace` cannot decide whether "
            "a rule limited to this service matches a given port.")))
    rows = [[service.get(F_ID, ""), service.get(F_DISPLAY_NAME, ""),
             protocol, ports, kind]]
    exporter.stage("service", SERVICE_HEADERS, rows)
    return rows


# ==========================================================================
# actions/doctor.py  --  What does THIS NSX actually serve.
# ==========================================================================

DOCTOR_HEADERS = ["manager", "role", "capability", "status", "detail"]

OK, MISSING, DEGRADED, NA = "ok", "missing", "degraded", "n/a"

# What each capability is FOR, so a missing one names the command it breaks
# rather than an endpoint nobody has heard of.
CAPABILITY_USES = {
    "policy base": "everything",
    "groups": "group list, impact, hygiene",
    "security policies": "rule list, hygiene, drift, trace",
    "services": "rule create --service, trace port matching",
    "rule statistics": "rule hygiene unused checks, rule baseline",
    "vm inventory": "tag commands, compliance, trace",
    "group associations": "impact, trace static evaluation",
    "vifs": "trace (source NIC resolution)",
    "logical ports": "trace (packet injection point)",
    "traceflow": "trace (the live half)",
    "projects": "--project scoping",
}


class Probe:
    """One capability check against one manager."""

    __slots__ = ("manager", "role", "capability", "status", "detail")

    def __init__(self, manager, role, capability, status, detail=""):
        self.manager = manager
        self.role = role
        self.capability = capability
        self.status = status
        self.detail = detail

    def row(self):
        return [self.manager, self.role, self.capability, self.status,
                self.detail]


def _count_of(payload):
    if not isinstance(payload, dict):
        return None
    if F_RESULT_COUNT in payload:
        return payload.get(F_RESULT_COUNT)
    results = payload.get(F_RESULTS)
    return len(results) if isinstance(results, list) else None


def _probe_get(nsx, path, params=None):
    """(status, detail) for one bounded GET."""
    try:
        payload = nsx.get(path, params=params or {PARAM_PAGE_SIZE: 1})
    except NsxError as e:
        text = str(e)
        if "HTTP 404" in text:
            return MISSING, "404 -- not served by this version"
        if "HTTP 403" in text:
            return DEGRADED, "403 -- the account cannot read it"
        return MISSING, text[-110:]
    count = _count_of(payload)
    return OK, "" if count is None else "{} item(s)".format(count)


def probe_manager(nsx, domain=DEFAULT_DOMAIN):
    """Every capability the toolkit depends on, checked once."""
    probes = []
    role = ROLE_LABEL.get(nsx.role, "?")

    def add(capability, status, detail=""):
        probes.append(Probe(nsx.name, role, capability, status, detail))

    version = None
    try:
        payload = nsx.get(PATH_NODE_VERSION)
        version = payload.get("node_version") or payload.get("product_version")
        add("version", OK, str(version or "unknown"))
    except NsxError as e:
        add("version", MISSING, str(e)[-110:])

    try:
        base = nsx.base(domain)
        add("policy base", OK, base)
    except NsxError as e:
        add("policy base", MISSING, str(e)[-110:])
        return probes, version

    add("groups", *_probe_get(nsx, p_groups(base, domain)))
    add("security policies", *_probe_get(nsx, p_sec_policies(base, domain)))
    add("services", *_probe_get(nsx, p_services(base)))
    add("group associations", *_probe_get(nsx, p_vm_group_assoc(base),
                                          params={"vm_external_id": "probe"}))

    # Statistics hang off a real policy, so probe one rather than guessing an
    # id -- a 404 for "no such policy" would look like "not supported".
    stats_status, stats_detail = _probe_statistics(nsx, base, domain)
    add("rule statistics", stats_status, stats_detail)

    if nsx.role == ROLE_LM:
        add("vm inventory", *_probe_get(nsx, PATH_FABRIC_VMS))
        add("vifs", *_probe_get(nsx, PATH_FABRIC_VIFS))
        add("logical ports", *_probe_get(nsx, PATH_LOGICAL_PORTS))
        add("traceflow", *_probe_get(nsx, PATH_TRACEFLOW))
    else:
        for capability in ("vm inventory", "vifs", "logical ports",
                           "traceflow"):
            add(capability, NA, "Local Manager only")

    add("projects", *_probe_get(nsx, p_projects(nsx.org)))
    return probes, version


def _probe_statistics(nsx, base, domain):
    """Statistics need a policy to hang off, so find one first."""
    try:
        policies = nsx.get(p_sec_policies(base, domain),
                           params={PARAM_PAGE_SIZE: 1}).get(F_RESULTS) or []
    except NsxError as e:
        return MISSING, "could not list policies: {}".format(str(e)[-80:])
    if not policies:
        return NA, "no policy to measure against"
    pid = policies[0].get("id", "?")
    status, detail = _probe_get(nsx, p_policy_stats(base, domain, pid),
                                params={})
    if status == MISSING:
        return status, (detail + " -- hit-count checks will be skipped")
    return status, detail


def _probe_colour(status):
    return {OK: cBG, MISSING: cBR, DEGRADED: cBY, NA: cD}.get(status, cD)


def act_doctor(sessions, domain, exporter):
    """Returns (probes, healthy). Prints a per-manager capability report."""
    section("NSX CAPABILITY REPORT")
    say("  {}".format(cD(
        "What this NSX actually serves. Every probe is a bounded read -- "
        "nothing is written,")))
    say("  {}".format(cD(
        "and traceflow is checked by listing, never by injecting a packet.")))

    all_probes = []
    for nsx in sessions:
        hr()
        say("  {}  {}  {}".format(cB(nsx.name),
                                  cD(ROLE_LABEL.get(nsx.role, "?")),
                                  cD(nsx.base_url)))
        if nsx.project:
            say("  {}".format(cD("scoped to project {}".format(nsx.project))))
        probes, _version = probe_manager(nsx, domain)
        all_probes.extend(probes)
        rows = []
        for probe in probes:
            use = CAPABILITY_USES.get(probe.capability, "")
            rows.append([
                probe.capability,
                _probe_colour(probe.status)(probe.status),
                probe.detail[:52],
                cD(use) if probe.status in (MISSING, DEGRADED) else ""])
        table(["Capability", "Status", "Detail", "Affects"], rows, indent=4)

    hr()
    missing = [p for p in all_probes if p.status == MISSING]
    degraded = [p for p in all_probes if p.status == DEGRADED]
    exporter.stage("doctor", DOCTOR_HEADERS, [p.row() for p in all_probes])
    exporter.stage_findings("nsx_capabilities", [
        make_finding(probe.capability, probe.status,
                     "{} on {}".format(probe.capability, probe.manager),
                     where=probe.manager,
                     passed=probe.status in (OK, NA),
                     detail="{}  affects: {}".format(
                         probe.detail,
                         CAPABILITY_USES.get(probe.capability, "")))
        for probe in all_probes])

    if not missing and not degraded:
        say("  {} every surface the toolkit uses is available.".format(
            cBG("Healthy:")))
        return all_probes, True

    if missing:
        say("  {} {} capability(ies) are not served here:".format(
            cBR("Missing:"), len(missing)))
        for probe in missing:
            say("    {} / {}   {}".format(
                cC(probe.manager), cB(probe.capability),
                cD(CAPABILITY_USES.get(probe.capability, ""))))
    if degraded:
        say("  {} {} capability(ies) exist but this account cannot read "
            "them:".format(cBY("Degraded:"), len(degraded)))
        for probe in degraded:
            say("    {} / {}".format(cC(probe.manager), cB(probe.capability)))
    say("\n  {}".format(cD(
        "A missing capability is not a bug in the toolkit -- the commands "
        "that use it")))
    say("  {}".format(cD(
        "degrade and say so. This report is the thing to paste into a "
        "question about it.")))
    return all_probes, False


def unhealthy_count(probes):
    return sum(1 for p in probes if p.status in (MISSING, DEGRADED))


def gm_only_estate(sessions):
    """True when nothing that needs a Local Manager can possibly work."""
    return bool(sessions) and all(s.role == ROLE_GM for s in sessions)


# ==========================================================================
# actions/recommend.py  --  Turn observed flows into a reviewable ruleset proposal.
# ==========================================================================

PROPOSAL_HEADERS = ["source", "destination", "protocol", "ports", "flows"]
UNRESOLVED_HEADERS = ["address", "side", "flows"]

RECOMMEND_CONSOLE_LIMIT = 30


def act_recommend(sessions, domain, exporter, flow_file, policy=None,
                  out_file=None, max_ports=DEFAULT_MAX_PORTS,
                  include_denied=False, action="ALLOW"):
    """Read a flow export, propose rules, and write a change file.

    Returns (proposals, unresolved, wide). Nothing is written to NSX: the
    output is an `nsxctl apply` document, because a ruleset derived from an
    observation window is a draft that needs a person to read it.
    """
    section("RULE RECOMMENDATIONS FROM OBSERVED FLOWS")
    flows, problems = read_flows(flow_file, include_denied=include_denied)
    for problem in problems[:10]:
        warn(problem)
    more_note(10, len(problems), "rows skipped")

    groups = group_inventory(sessions, domain)
    names = group_display_names(groups)
    proposals, unresolved, wide = propose_rules(flows, groups,
                                                max_ports=max_ports)

    say("  Flows read     : {}".format(cC(str(len(flows)))))
    say("  Groups known   : {}".format(cC(str(len(groups)))))
    say("  Rules proposed : {}".format(cC(str(len(proposals)))))
    hr()

    def label(paths):
        return ", ".join(names.get(p, p.rsplit("/", 1)[-1]) for p in paths)

    if proposals:
        table(["Source", "Destination", "Proto", "Ports", "Flows"],
              [[cB(label(p.source_groups)), cB(label(p.destination_groups)),
                p.protocol, ",".join(str(x) for x in p.ports),
                str(p.flow_count)]
               for p in proposals[:RECOMMEND_CONSOLE_LIMIT]], indent=4)
        more_note(RECOMMEND_CONSOLE_LIMIT, len(proposals))
    else:
        say("  {}".format(cD("No flow resolved to a pair of known groups.")))

    if wide:
        say("\n  {} {} pair(s) talked on more than {} ports and were NOT "
            "turned into rules:".format(cBY("WIDE:"), len(wide), max_ports))
        for proposal in wide[:10]:
            say("    {} -> {}   {} ports".format(
                label(proposal.source_groups),
                label(proposal.destination_groups), len(proposal.ports)))
        say("  {}".format(cD(
            "That shape is usually a scanner or a monitoring host. One rule "
            "with fifty ports would bury it rather than surface it.")))

    if unresolved:
        say("\n  {} {} address(es) belong to no group:".format(
            cBR("UNCLASSIFIED:"), len(unresolved)))
        for item in unresolved[:RECOMMEND_CONSOLE_LIMIT]:
            say("    {:18s} {:12s} {} flow(s)".format(
                item.address, item.side, item.flow_count))
        more_note(RECOMMEND_CONSOLE_LIMIT, len(unresolved))
        say("  {}".format(cD(
            "These are the most useful rows here: traffic exists and nobody "
            "has classified the workload. No rule is proposed for them.")))

    exporter.stage("flow_proposals", PROPOSAL_HEADERS,
                   [p.row() for p in proposals])
    exporter.stage("flow_unresolved", UNRESOLVED_HEADERS,
                   [u.row() for u in unresolved])

    hr()
    say("  {} this proposes ALLOW rules for traffic that was "
        "observed.".format(cD("note:")))
    say("  {}".format(cD(
        "It never proposes a default-deny: no traffic seen in one window is "
        "not")))
    say("  {}".format(cD(
        "evidence none exists -- the same reason a zero hit count cannot "
        "retire a rule.")))

    if out_file and proposals:
        if not policy:
            raise ConfigError(
                "Writing a change file needs --policy: a rule has to go "
                "somewhere.")
        document = proposals_to_change_file(proposals, policy, action=action)
        _write_change_file(out_file, document)
        ok_msg("Change file: {}".format(out_file))
        say("  {} review it, then:".format(cD("next:")))
        say("    {}".format(cC("nsxctl apply {}".format(out_file))))
        say("    {}".format(cD(
            "(dry run by default; add --enable-writes to commit)")))
    elif out_file:
        say("  {}".format(cD("Nothing to write: no rules proposed.")))
    return proposals, unresolved, wide


def _write_change_file(path, document):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def recommend_summary(proposals, unresolved, wide):
    return {"proposed": len(proposals), "unclassified": len(unresolved),
            "wide": len(wide)}


def clean_estate(unresolved, wide):
    """True when every observed endpoint was classified and nothing was wide."""
    return not unresolved and not wide


# ==========================================================================
# actions/audit_view.py  --  Audit log viewing and single-entry undo.
# ==========================================================================

AUDIT_HEADERS = ["timestamp", "user", "manager", "action", "object_type",
                 "object", "added", "removed", "status"]

UNDOABLE_OBJECTS = (OBJ_GROUP, OBJ_RULE)


def _entry_row(entry, added, removed):
    return [entry["timestamp"], entry["user"], entry["manager"],
            entry["action"], entry["object_type"], entry["object_name"],
            fmt_tags_plain(added) if added else "",
            fmt_tags_plain(removed) if removed else "",
            entry["status"]]


def _print_entry(index, entry):
    say("  {:5s} {}  {:28s}  {}  [{}]".format(
        cD(str(index) + "."), cD(str(entry["timestamp"])[:19]),
        str(entry["object_name"])[:28], cD(entry["object_type"]),
        cC(entry["manager"])))
    if entry["object_type"] == OBJ_VM_TAGS:
        added, removed = summarise_entry(entry)
        if added:
            say("        {}".format(cG("+ " + fmt_tags_plain(added))))
        if removed:
            say("        {}".format(cR("- " + fmt_tags_plain(removed))))
        return
    if entry["before"] is None:
        say("        {}".format(cG("created")))
    elif entry["after"] is None:
        say("        {}".format(cR("deleted")))
    else:
        say("        {}".format(cBY("modified")))
    if entry["status"] and entry["status"] != "success":
        say("        {} {}".format(cR(entry["status"]), cD(entry["detail"])))


def act_audit_log(audit, sessions, write_enabled, exporter=None, limit=20,
                  domain="default"):
    entries = audit.last_n_normalised(limit)
    if not entries:
        say("  Audit log empty.")
        if exporter is not None:
            exporter.stage("audit_log", AUDIT_HEADERS, [])
        return
    say("\n  Last {} entries:".format(cC(str(len(entries)))))
    hr()
    rows = []
    for index, entry in enumerate(entries, 1):
        _print_entry(index, entry)
        added, removed = summarise_entry(entry)
        rows.append(_entry_row(entry, added, removed))
    if exporter is not None:
        exporter.stage("audit_log", AUDIT_HEADERS, rows)

    if not write_enabled:
        say("\n  {}.".format(cBY("Undo needs write mode")))
        return
    if not is_interactive():
        return
    hr()
    choice = ask("  Undo entry # (or b): ")
    if not choice.isdigit() or not (1 <= int(choice) <= len(entries)):
        say("  Cancelled.")
        return
    target = entries[int(choice) - 1]
    try:
        if target["object_type"] == OBJ_VM_TAGS:
            _undo_vm_tags(target, sessions, audit)
        elif target["object_type"] in UNDOABLE_OBJECTS:
            undo_object_entry(target, sessions, domain, audit)
        else:
            err("Entries of type '{}' cannot be undone.".format(
                target["object_type"]))
    except NsxError as e:
        err(str(e))


def _undo_vm_tags(target, sessions, audit):
    """The original tag undo, unchanged in behaviour.

    Reads `before`/`after` off the normalised entry, which for a tag entry
    comes from `tags_before`/`tags_after` whether it was written this release
    or three releases ago.
    """
    restore_to = target["before"] or []
    raw = target["raw"]
    vm_name = raw.get("vm_display_name", target["object_name"])
    mgr_name = target["manager"]
    ext = raw.get("vm_external_id", "?")

    nsx = next((s for s in sessions if s.name == mgr_name), None)
    if not nsx:
        err("Manager '{}' is not in this session.".format(mgr_name))
        return
    vm = nsx.get_vm_by_external_id(ext)
    if not vm:
        err("VM '{}' (external_id {}) not found on {}.".format(
            vm_name, ext, mgr_name))
        return
    current = sorted(tags_of(vm))
    say("\n  Restore '{}' on [{}]".format(cB(vm_name), cC(mgr_name)))
    say("    current : {}".format(fmt_tags_plain(current)))
    say("    restore : {}".format(fmt_tags_plain(sorted(restore_to))))
    if current == sorted(restore_to):
        say("  Already in that state -- nothing to undo.")
        return
    if not confirm("  Apply undo? [y/N]: "):
        say("  Cancelled.")
        return
    fresh = nsx.refresh_vm(vm) or vm
    nsx.update_vm_tags(fresh, restore_to)
    audit.log("undo", nsx.name, vm_name, fresh.get(F_EXTERNAL_ID),
              current, restore_to, detail="undo of {}".format(
                  target.get("timestamp", "?")))
    ok_msg("Undo applied.")


# ==========================================================================
# actions/trace.py  --  Connectivity trace: can A reach B, and which rule decided it.
# ==========================================================================

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


# ==========================================================================
# actions/drift.py  --  Drift from the interactive menu.
# ==========================================================================

MENU_CHANGE_LIMIT = 25


def act_drift_menu(ctx):
    """Compare the newest snapshot against live NSX."""
    section("CONFIGURATION DRIFT")
    existing = list_snapshots()
    if not existing:
        say("  No snapshots yet.")
        say("  Take one first: {}".format(cC("nsxctl snapshot save")))
        return
    newest = existing[0]
    say("  Snapshot : {}  ({})".format(cC(newest["name"]), newest["taken"]))
    say("  Against  : {}".format(cC("live NSX")))
    try:
        before = load_snapshot(newest["root"])
        after = capture_snapshot(
            ctx.sessions, ctx.domain,
            with_tags=bool(before["manifest"].get("with_tags")))
    except NsxError as e:
        err(str(e))
        return

    changes = diff_snapshots(before, after)
    ctx.exporter.stage("drift", DRIFT_HEADERS, diff_rows(changes))
    ctx.exporter.stage_findings("config_drift", drift_findings(changes))
    hr()
    if not changes:
        say("  {} configuration matches the snapshot exactly.".format(
            cBG("No drift:")))
        return

    counts = summarise_diff(changes)
    table(["Change", "Count"],
          [[k, str(counts[k])] for k in
           ("added", "removed", "modified", "security", "cosmetic")
           if counts.get(k)], indent=4)
    for change in changes[:MENU_CHANGE_LIMIT]:
        colour = cBR if change.impact == "security" else cD
        who = " {}".format(cD("by " + change.changed_by)) \
            if change.changed_by else ""
        say("\n  {} {} {}{}".format(
            cBY(change.status.upper()), cB(str(change.name)),
            colour("[{}]".format(change.impact)), who))
        for field in change.fields[:8]:
            say("      {}: {} -> {}".format(
                cC(field.field), cD(str(field.before)), field.after))
    if len(changes) > MENU_CHANGE_LIMIT:
        say("\n  {}".format(cD("... +{} more (full set in export)".format(
            len(changes) - MENU_CHANGE_LIMIT))))
    hr()


# ==========================================================================
# wizard.py  --  First-run setup.
# ==========================================================================

def _intro():
    say(cBC("=" * W))
    say("  {} v{} -- {}".format(cB(TOOL_NAME), VERSION, cB("first-run setup")))
    say(cBC("=" * W))
    say("")
    say("  No inventory was found, so let's build one. You'll be asked for")
    say("  each NSX manager you want the toolkit to talk to.")
    say("")
    say("  {} the Global Manager (if you have one), then each".format(cD("Add")))
    say("  {} Local Manager. Tags and VM inventory live on Local".format(cD("")))
    say("  Managers; groups and policies exist on both.")
    say("")
    if not have_requests():
        say("  {} 'requests' is not installed -- using the built-in".format(
            cD("note:")))
        say("        stdlib transport. Everything works; client-certificate")
        say("        authentication is the one feature that needs requests.")
        say("")


def _ask_role():
    while True:
        say("    1. Local Manager  {}".format(cD("(VMs, tags, local policy)")))
        say("    2. Global Manager {}".format(cD("(federated groups and policy)")))
        c = ask("  Role [1]: ", default="1").strip().lower()
        if c in ("1", "lm", "local"):
            return ROLE_LM
        if c in ("2", "gm", "global"):
            return ROLE_GM
        say("    Pick 1 or 2.")


def _ask_manager(index, used_names):
    say("\n  {}".format(cB("Manager #{}".format(index))))
    hr()
    host = ask("  Hostname or IP: ").strip()
    if not host:
        return None
    default_name = host.split(".")[0][:24] or "nsx{}".format(index)
    while True:
        name = ask("  Short name [{}]: ".format(default_name),
                   default=default_name).strip()
        if name not in used_names:
            break
        say("    '{}' is already used -- pick another.".format(name))
    role = _ask_role()
    port = ask("  Port [443]: ", default="443").strip()
    verify = confirm("  Verify the TLS certificate? "
                     "[y/N] (N is usual for self-signed): ")
    entry = {
        "name": name,
        "role": role,
        "host": host,
        "port": int(port) if port.isdigit() else 443,
        "verify_ssl": bool(verify),
        "auth": "session",
    }
    if verify:
        ca = ask("  CA bundle path (blank = system trust store): ",
                 default="").strip()
        if ca:
            entry["ca_bundle"] = ca
    u_env, p_env = default_env_names(name)
    entry["username_env"] = u_env
    entry["password_env"] = p_env
    problems = validate_manager(entry, index)
    for p in problems:
        warn(p)
    return entry


def _test(entry):
    """Authenticate and make one real call. Returns True when it works."""
    name = entry.get("name", "?")
    say("\n  Testing {} ...".format(cC(name)))
    try:
        user, pwd, src = credentials_for(entry, allow_prompt=True)
    except (NsxError, UserAbort) as e:
        err("{}: {}".format(name, e))
        return False
    say("    credentials {}".format(cD(src)))
    try:
        nsx = Nsx(entry, user, pwd, transport=make_transport())
        base = nsx.base(verbose=True)
        version = nsx.version()
        say("    api base    {}".format(cD(base)))
        if version:
            say("    nsx version {}".format(cD("{}.{}".format(*version))))
        ok_msg("{}: reachable and authenticated.".format(name))
        nsx.close()
        return True
    except NsxError as e:
        err("{}: {}".format(name, str(e)[:200]))
        return False


def run_wizard(explicit_path=None):
    """Build an inventory interactively. Returns its path, or None."""
    if not is_interactive():
        err("No inventory file found, and this is not an interactive terminal.")
        say("")
        say("  Create one and re-run. Minimal example:")
        say(cD('    {"managers": [{"name": "lm1", "role": "lm",'))
        say(cD('       "host": "nsx.example.com", "verify_ssl": false,'))
        say(cD('       "username_env": "NSX_LM1_USER",'))
        say(cD('       "password_env": "NSX_LM1_PASS"}]}'))
        say("")
        say("  Save it as {} in the current directory or in {},".format(
            cC(DEFAULT_INVENTORY_NAME), cC(DATA_DIR)))
        say("  or pass --inventory <path>. Run with a terminal for guided setup.")
        return None

    _intro()
    managers = []
    used = set()
    while True:
        entry = _ask_manager(len(managers) + 1, used)
        if entry is None:
            if managers:
                break
            say("  A hostname is required.")
            continue
        managers.append(entry)
        used.add(entry["name"])
        if not confirm("\n  Add another manager? [y/N]: "):
            break

    if not managers:
        err("No managers configured.")
        return None

    default_dir = explicit_path and os.path.dirname(os.path.abspath(explicit_path))
    if not default_dir:
        default_dir = DATA_DIR
    target = explicit_path or os.path.join(default_dir, DEFAULT_INVENTORY_NAME)
    say("\n  {}".format(cB("Where should the inventory live?")))
    say("    1. {}  {}".format(
        os.path.join(DATA_DIR, DEFAULT_INVENTORY_NAME),
        cD("(found from anywhere)")))
    say("    2. {}  {}".format(
        os.path.join(os.getcwd(), DEFAULT_INVENTORY_NAME),
        cD("(this directory only)")))
    choice = ask("  Choice [1]: ", default="1").strip()
    if choice == "2":
        target = os.path.join(os.getcwd(), DEFAULT_INVENTORY_NAME)
    elif not explicit_path:
        target = os.path.join(DATA_DIR, DEFAULT_INVENTORY_NAME)

    if os.path.exists(target) and not confirm(
            "  {} exists. Overwrite? [y/N]: ".format(target)):
        say("  Cancelled -- nothing written.")
        return None

    write_inventory(target, managers)
    ok_msg("Wrote {}".format(target))

    if not keyring_available():
        say("  {} no OS keyring here, so you'll be asked whether to".format(
            cD("note:")))
        say("        store credentials on disk when you enter them.")

    say("\n  {}".format(cB("Connectivity check")))
    hr()
    results = [(m.get("name"), _test(m)) for m in managers]
    good = [n for n, k in results if k]
    bad = [n for n, k in results if not k]

    hr()
    if bad:
        say("  {} {} of {} manager(s) failed: {}".format(
            cBY("WARNING:"), len(bad), len(results), ", ".join(bad)))
        say("  The inventory was still written -- fix the entry and re-run")
        say("  {} to retest, or {} to re-enter credentials.".format(
            cC("--verify"), cC("--set-credentials")))
    else:
        say("  {} all {} manager(s) reachable.".format(cBG("Ready:"), len(good)))
    say("")
    say("  Next: {}   {}".format(cC("nsx-toolkit"), cD("(interactive menu)")))
    say("        {}   {}".format(cC("nsx-toolkit --dashboard"),
                                 cD("(compliance posture)")))
    say("")
    return target


def maybe_bootstrap(explicit_path, search_dirs=None):
    """Called when no inventory was found. Returns a path or None."""
    search_dirs = search_dirs or config_search_dirs()
    if explicit_path:
        say("  {} {}".format(cBR("Inventory not found:"), explicit_path))
    else:
        looked = ", ".join(os.path.join(d, DEFAULT_INVENTORY_NAME)
                           for d in search_dirs)
        say("  {} looked in: {}".format(cD("No inventory found."), cD(looked)))
    return run_wizard(explicit_path)


# ==========================================================================
# menu.py  --  Interactive menu.
# ==========================================================================

class AppContext:
    """Everything an action needs, assembled once in cli.main()."""

    def __init__(self, sessions, audit, exporter, taxonomy,
                 write_enabled=False, domain=DEFAULT_DOMAIN, managers=None,
                 profile=None, project=None, inventory_path=None):
        self.sessions = sessions
        self.audit = audit
        self.exporter = exporter
        self.taxonomy = taxonomy
        self.write_enabled = write_enabled
        self.domain = domain
        # Inventory entries, for commands that act on configuration rather
        # than on a live connection (login).
        self.managers = managers or []
        # Which estate, and which tenant inside it, this run is talking to.
        self.profile = profile
        self.project = project
        self.inventory_path = inventory_path

    def cache_key(self):
        """(profile, project) -- which estate and tenant a cached name
        belongs to. Completing production names into a DR command is worse
        than completing nothing."""
        return (self.profile, self.project)

    def lms(self):
        return [s for s in self.sessions if s.role == ROLE_LM]

    def close(self):
        for s in self.sessions:
            s.close()


def menu_text(mode_str):
    h = cBC("=" * W)
    d = cD("-" * 42)
    return """
{h}
  {groups}   {gsub}
  {d}
    1.  Search groups + show criteria
    2.  Search groups + criteria + VM members

  {tags}     {tsub}
  {d}
    3.  Show all tags on a VM
    4.  Find all VMs carrying a specific tag
    5.  Add / remove tags                      {audit}

  {bulk}
  {d}
    6.  Bulk tag from CSV                      {dry}
    7.  Reverse lookup: VM -> groups -> rules  {rl}
    8.  Parity validation (static vs dynamic)
    9.  Compliance dashboard
   15.  DFW rule hygiene                       {hyg}
   16.  Drift since last snapshot              {dft}
   17.  Trace a flow: can A reach B?             {trc}
   18.  Create / edit groups and rules            {aut}

  {ops}
  {d}
   10.  Verify connectivity + API detection
   11.  View audit log / undo
   12.  Toggle write mode                      [{mode}]
   13.  Generate change ticket from CSV
   14.  List managers

    m.  Show this menu again    q.  Quit
{h}
""".format(h=h, d=d, mode=mode_str,
           groups=cB("GROUPS"), gsub=cD("(Global Manager + Local Managers)"),
           tags=cB("TAGS"), tsub=cD("(Local Managers only)"),
           bulk=cB("BULK & ANALYSIS"), ops=cB("OPERATIONS"),
           audit=cD("(audit logged)"), dry=cD("(dry-run first)"),
           rl=cD("(any member type, deduped)"),
           hyg=cD("(any-any, shadowed, unused, broken refs)"),
           dft=cD("(what changed, and who changed it)"),
           trc=cD("(policy verdict, and the data plane's)"),
           aut=cD("(dry-run first, audited, undoable)"))


def select_managers(sessions, allow_roles, allow_all=False, label=""):
    pool = [s for s in sessions if s.role in allow_roles]
    if not pool:
        say("\n  No managers of that type are connected.")
        return []
    if len(pool) == 1:
        return pool
    say("\n  Target for {}:".format(cB(label)))
    for i, s in enumerate(pool, 1):
        say("    {}. {:26s}  {:30s}  {}".format(
            i, cC(s.name), s.host, cD(ROLE_LABEL.get(s.role, "?"))))
    if allow_all:
        note = "  (tags span LMs)" if tuple(allow_roles) == (ROLE_LM,) else ""
        say("    a. ALL ({}){}".format(len(pool), note))
    say("    b. back")
    while True:
        c = ask("  Choice: ").lower()
        if allow_all and c == "a":
            return pool
        if c.isdigit() and 1 <= int(c) <= len(pool):
            return [pool[int(c) - 1]]
        say("    Invalid.")


def _mode_str(ctx):
    return cBG("READ-WRITE") if ctx.write_enabled else cBY("READ-ONLY")


def interactive(ctx):
    say(menu_text(_mode_str(ctx)))
    say("  Tip: {}".format(cD("m = menu, b = back mid-prompt, q = quit")))

    while True:
        try:
            c = ask("\n  Choice [{}{} ".format(_mode_str(ctx), cD("]:")),
                    allow_back=False).strip().lower()
        except UserAbort:
            say("\n  Bye.")
            return 0

        try:
            if c == "q":
                say("  Bye.")
                return 0

            elif c == "m":
                say(menu_text(_mode_str(ctx)))

            elif c == "14":
                say("")
                table(["Name", "Host", "Role", "Auth"],
                      [[cC(s.name), s.host, cD(ROLE_LABEL.get(s.role, "?")),
                        cD(s.auth_mode)] for s in ctx.sessions])

            elif c in ("1", "2"):
                tgt = select_managers(ctx.sessions, (ROLE_GM, ROLE_LM),
                                      allow_all=True, label="group search")
                if not tgt:
                    continue
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                needle = ask("  Name/id contains (blank=all): ", default="")
                act_groups(tgt, domain, needle, show_members=(c == "2"),
                           exporter=ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "3":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="VM tag lookup")
                if not tgt:
                    continue
                vm = ask("  VM name contains: ")
                if vm:
                    act_vm_tags(tgt, vm, ctx.exporter, ctx.taxonomy)
                    offer_export(ctx.exporter)

            elif c == "4":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="tag search")
                if not tgt:
                    continue
                scope = ask("  Tag scope (blank=any): ", default="")
                tag = ask("  Tag value (blank=any): ", default="")
                if not scope and not tag:
                    say("    Give a scope, a value, or both.")
                    continue
                act_vms_by_tag(tgt, scope, tag, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "5":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="tag management")
                if not tgt:
                    continue
                vm = ask("  VM name contains: ")
                if vm:
                    act_manage_tags(tgt, vm, ctx.audit, ctx.write_enabled,
                                    ctx.taxonomy)

            elif c == "6":
                tgt = select_managers(ctx.sessions, (ROLE_LM,),
                                      allow_all=True, label="bulk tagging")
                if not tgt:
                    continue
                csv_path = ask("  CSV file path: ")
                if not csv_path:
                    continue
                say("\n  {} first ...".format(cBY("DRY RUN")))
                act_bulk_tag(tgt, csv_path, ctx.audit, ctx.write_enabled,
                             dry_run=True, taxonomy=ctx.taxonomy)
                if not ctx.write_enabled:
                    say("  {} -- enable write mode (12) to apply.".format(
                        cBY("READ-ONLY")))
                    continue
                if confirm("\n  {} [y/N]: ".format(cB("Apply for real?"))):
                    act_bulk_tag(tgt, csv_path, ctx.audit, ctx.write_enabled,
                                 dry_run=False, taxonomy=ctx.taxonomy)
                else:
                    say("  Cancelled.")

            elif c == "7":
                # Always sweeps every connected manager -- see the docstring on
                # act_reverse_lookup for why a partial selection is wrong here.
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                vm = ask("  VM name contains: ")
                if vm:
                    act_reverse_lookup(ctx.sessions, vm, domain, ctx.exporter)
                    offer_export(ctx.exporter)

            elif c == "8":
                static = ask("  Static group name/id: ")
                if not static:
                    continue
                dynamic = ask("  Dynamic group name/id: ")
                if not dynamic:
                    continue
                domain = ask("  Domain [{}]: ".format(ctx.domain), default=ctx.domain)
                act_parity(ctx.sessions, domain, static, dynamic, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "9":
                act_dashboard(ctx.sessions, ctx.exporter, ctx.taxonomy)
                offer_export(ctx.exporter)

            elif c == "15":
                act_hygiene(ctx.sessions, ctx.domain, ctx.exporter)
                offer_export(ctx.exporter)

            elif c == "16":
                act_drift_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "17":
                trace_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "18":
                author_menu(ctx)
                offer_export(ctx.exporter)

            elif c == "10":
                tgt = select_managers(ctx.sessions, (ROLE_GM, ROLE_LM),
                                      allow_all=True, label="verification")
                if tgt:
                    act_verify(tgt, ctx.domain)

            elif c == "11":
                act_audit_log(ctx.audit, ctx.sessions, ctx.write_enabled,
                              ctx.exporter, domain=ctx.domain)
                offer_export(ctx.exporter)

            elif c == "12":
                ctx.write_enabled = not ctx.write_enabled
                # --yes is a non-interactive gate; in the menu every write is
                # already confirmed at the prompt, so never leave it latched on.
                set_assume_yes(False)
                say("  Write mode: {}".format(
                    cBG("ENABLED") if ctx.write_enabled else cBY("DISABLED")))

            elif c == "13":
                csv_path = ask("  CSV file path: ")
                if csv_path:
                    act_change_ticket(ctx.sessions, csv_path, ctx.exporter)
                    offer_export(ctx.exporter)

            elif c == "":
                continue

            else:
                say("  Not a valid choice. ({})".format(cD("'m' for menu")))

        except UserAbort:
            say("  (backed out)")
            continue
        except NsxError as e:
            err(str(e))
        except Exception as e:  # noqa: BLE001 - menu must survive any action
            err("unexpected: {}".format(e))
        # No "press Enter to continue" + full-menu reprint here on purpose:
        # that pattern is what pushed results off-screen.


# ==========================================================================
# commands/__init__.py  --  The `nsxctl <noun> <verb>` command tree.
# ==========================================================================

PROG = "nsxctl"

# Defaults live here rather than on the arguments, because the arguments use
# SUPPRESS so that "not given" is distinguishable from "given the default".
GLOBAL_DEFAULTS = {
    "inventory": None,
    "profile": None,
    "project": None,
    "taxonomy": None,
    "manager": None,
    "all_lm": False,
    "domain": DEFAULT_DOMAIN,
    "ca_bundle": None,
    "store": "auto",
    "json": False,
    "no_color": False,
    "non_interactive": False,
    "debug": False,
    "yes": False,
    "enable_writes": False,
    "force": False,
    "out_csv": None,
    "out_json": None,
    "out_html": None,
    "out_junit": None,
    "out_sarif": None,
    "out_metrics": None,
    "notify": None,
    "only_on_change": False,
}

EPILOG = """
getting started:
  nsxctl init                       guided setup: managers, credentials, a check
  nsxctl status                     can I reach and authenticate everywhere?
  nsxctl doctor                     what does this NSX actually serve?
  nsxctl                            interactive menu

everyday:
  nsxctl compliance                 tagging posture across every Local Manager
  nsxctl tag find --scope env --tag prod
  nsxctl impact web-prod-01         what breaks if I retag this VM
  nsxctl trace web-01 db-01 --port 3306    can A reach B, and what decided it
  nsxctl rule list --policy app-tier
  nsxctl group list --contains web
  nsxctl tag apply changes.csv      dry run; add --enable-writes --yes to commit

authoring (dry run unless --enable-writes):
  nsxctl group create g-web --criteria 'tag:env=prod AND tag:tier=web'
  nsxctl rule create allow-web-db --policy app-tier --from g-web --to g-db
  nsxctl apply changes.yaml         a declarative file of groups and rules
  nsxctl recommend flows.csv --policy app-tier --out-file proposed.json

scheduled:
  nsxctl rule hygiene --only-on-change --notify $SLACK_URL
  nsxctl drift --fail-on-drift security --out-junit drift.xml
  nsxctl doctor --out-metrics /var/lib/node_exporter/nsxctl.prom

Run `nsxctl <command> --help` for a command's options and examples.
"""


def add_global_args(parser):
    """Flags accepted before or after the subcommand."""
    cfg = parser.add_argument_group("configuration")
    cfg.add_argument("--inventory", metavar="PATH", default=argparse.SUPPRESS,
                     help="Inventory file (default: ./inventory.json, then "
                          "~/.nsx_toolkit/inventory.json).")
    cfg.add_argument("--taxonomy", metavar="PATH", default=argparse.SUPPRESS,
                     help="Tag taxonomy file (JSON, or YAML with PyYAML).")
    cfg.add_argument("--profile", metavar="NAME", default=argparse.SUPPRESS,
                     help="Which estate in a multi-profile inventory. "
                          "Also read from $NSX_PROFILE.")
    cfg.add_argument("--project", metavar="NAME", default=argparse.SUPPRESS,
                     help="Scope every policy path to an NSX Project. "
                          "Objects in the default infra are not visible from "
                          "inside a project.")
    cfg.add_argument("--manager", metavar="NAME", default=argparse.SUPPRESS,
                     help="Target one manager by name.")
    cfg.add_argument("--all-lm", action="store_true", default=argparse.SUPPRESS,
                     help="Target every Local Manager.")
    cfg.add_argument("--domain", metavar="NAME", default=argparse.SUPPRESS,
                     help="NSX domain (default: {}).".format(DEFAULT_DOMAIN))
    cfg.add_argument("--ca-bundle", metavar="PATH", default=argparse.SUPPRESS,
                     help="CA bundle for TLS verification on all managers.")
    cfg.add_argument("--store", choices=("auto", "keyring", "plaintext", "none"),
                     default=argparse.SUPPRESS,
                     help="Where prompted credentials are saved.")

    wr = parser.add_argument_group("writes")
    wr.add_argument("--enable-writes", action="store_true",
                    default=argparse.SUPPRESS,
                    help="Permit changes. Without it everything is read-only.")
    wr.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                    help="Skip confirmation prompts. Required to write "
                         "non-interactively.")
    wr.add_argument("--force", action="store_true", default=argparse.SUPPRESS,
                    help="Apply even if state changed since the plan was built.")

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                     help="Structured JSON on stdout. Implies "
                          "--non-interactive.")
    out.add_argument("--out-csv", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write results to CSV.")
    out.add_argument("--out-json", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write results to JSON.")
    out.add_argument("--out-html", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write a shareable HTML report where supported.")
    out.add_argument("--out-junit", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write findings as JUnit XML, for a pipeline.")
    out.add_argument("--out-sarif", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write findings as SARIF, for a code-scanning UI.")
    out.add_argument("--out-metrics", metavar="PATH",
                     default=argparse.SUPPRESS,
                     help="Write Prometheus textfile metrics, for a "
                          "node_exporter collector directory.")
    out.add_argument("--notify", metavar="URL", default=argparse.SUPPRESS,
                     help="POST a JSON summary to a webhook when the run "
                          "finishes.")
    out.add_argument("--only-on-change", action="store_true",
                     default=argparse.SUPPRESS,
                     help="Print nothing and notify nobody unless the "
                          "findings differ from the last run. For cron: a "
                          "quiet night sends no mail.")
    out.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                     help="Disable colored output.")
    out.add_argument("--non-interactive", action="store_true",
                     default=argparse.SUPPRESS,
                     help="Never prompt; fail rather than ask.")
    out.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                     help="Log HTTP method, URL, status and timing to stderr.")
    return parser


def apply_global_defaults(args):
    """Fill in globals neither the top level nor the subcommand supplied."""
    for key, value in GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    return args


def build_parser():
    pass
    pass
    pass
    pass
    pass
    pass
    pass
    pass
    pass
    pass
    pass

    global_parent = argparse.ArgumentParser(add_help=False)
    add_global_args(global_parent)

    parser = argparse.ArgumentParser(
        prog=PROG,
        parents=[global_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="{} v{} -- {}".format(TOOL_NAME, VERSION, TOOL_TAGLINE),
        epilog=EPILOG)
    parser.add_argument(
        "--version", action="version",
        version="{} v{} ({})".format(TOOL_NAME, VERSION, VERSION_DATE))

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    parents = [global_parent]
    for register in (register_setup, register_group, register_tag,
                     register_rule, register_inspect,
                     register_analysis, register_trace,
                     register_snapshot, register_apply,
                     register_recommend,
                     register_shell):
        register(sub, parents)
    return parser


def add_action(sub, parents, name, help_text, description=None, epilog=None):
    """A second-level subparser (`nsxctl group create`), with the same raw
    formatter as a top-level command so a syntax table survives --help."""
    return sub.add_parser(
        name, parents=parents, help=help_text,
        description=description or help_text, epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)


def add_command(sub, parents, name, help_text, description=None, epilog=None):
    """Consistent subparser construction, so every command's help looks alike."""
    return sub.add_parser(
        name, parents=parents, help=help_text,
        description=description or help_text,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)


# ==========================================================================
# commands/setup.py  --  Setup and introspection: init, status, managers, login, config.
# ==========================================================================

PROFILE_HEADERS = ["profile", "in_effect", "managers"]
PROJECT_HEADERS = ["manager", "id", "name", "description"]


def register_setup(sub, parents):
    p = add_command(
        sub, parents, "init", "Guided first-run setup.",
        epilog="Asks for each NSX manager, stores credentials, and proves\n"
               "every one is reachable before finishing.")
    p.set_defaults(func=cmd_init, needs_inventory=False, needs_sessions=False)

    p = add_command(
        sub, parents, "status",
        "Check every manager is reachable and authenticated.",
        epilog="examples:\n"
               "  nsxctl status\n"
               "  nsxctl status --manager gm --debug")
    p.set_defaults(func=cmd_status)

    p = add_command(
        sub, parents, "doctor",
        "What does this NSX actually serve?",
        description="Probe every API surface the toolkit depends on and "
                    "report, per manager, which are available.\n\n"
                    "The toolkit degrades rather than fails when a surface is "
                    "absent -- statistics may 404, traceflow is Local Manager "
                    "only, Projects may not exist -- which means a missing "
                    "feature and a bug in the tool look identical until you "
                    "run this.\n\n"
                    "Every probe is a bounded read. Nothing is written, and "
                    "traceflow is checked by listing, never by injecting a "
                    "packet.",
        epilog="examples:\n"
               "  nsxctl doctor\n"
               "  nsxctl doctor --json          # paste this into a bug report\n"
               "  nsxctl doctor --fail-on-missing   # for a pipeline")
    p.add_argument("--fail-on-missing", action="store_true",
                   help="Exit 1 if any capability is missing or unreadable.")
    p.set_defaults(func=cmd_doctor)

    p = add_command(sub, parents, "managers", "List the configured managers.")
    p.set_defaults(func=cmd_managers)

    p = add_command(
        sub, parents, "profiles", "List the estates this inventory defines.",
        description="An inventory can name several estates and select one "
                    "with --profile. A flat single-estate inventory has none, "
                    "and still works exactly as it always did.",
        epilog="examples:\n"
               "  nsxctl profiles\n"
               "  nsxctl --profile dr status\n"
               "  NSX_PROFILE=dr nsxctl compliance")
    p.set_defaults(func=cmd_profiles, needs_sessions=False)

    p = add_command(
        sub, parents, "projects", "List NSX Projects on each manager.",
        description="NSX Projects are multi-tenancy: each has its own infra "
                    "tree, so objects in the default infra are NOT visible "
                    "from inside a project and vice versa. Scope a run with "
                    "--project.",
        epilog="examples:\n"
               "  nsxctl projects\n"
               "  nsxctl --project tenant-a group list")
    p.set_defaults(func=cmd_projects)

    p = add_command(
        sub, parents, "login", "Store or replace credentials for a manager.",
        epilog="examples:\n"
               "  nsxctl login              all managers\n"
               "  nsxctl login lm-london    just that one")
    p.add_argument("name", nargs="?", help="Manager name (default: all).")
    p.set_defaults(func=cmd_login, needs_sessions=False)

    p = add_command(
        sub, parents, "config", "Show or check the configuration in effect.")
    csub = p.add_subparsers(dest="config_action", metavar="<action>")
    c = csub.add_parser("show", parents=parents,
                        help="Configuration currently in effect.")
    c.set_defaults(func=cmd_config_show)
    c = csub.add_parser("path", parents=parents,
                        help="Where every file lives.")
    c.set_defaults(func=cmd_config_path)
    c = csub.add_parser("validate", parents=parents,
                        help="Validate inventory and taxonomy; non-zero on error.")
    c.set_defaults(func=cmd_config_validate)
    p.set_defaults(func=cmd_config_show, config_action="show")
    for c in csub.choices.values():
        c.set_defaults(needs_inventory=False, needs_sessions=False)
    p.set_defaults(needs_inventory=False, needs_sessions=False)


def cmd_init(args, ctx):
    return 0 if run_wizard(args.inventory) else 1


def cmd_status(args, ctx):
    return 0 if act_verify(ctx.sessions, args.domain) else 1


def cmd_managers(args, ctx):
    section("Managers")
    table(["Name", "Host", "Role", "Auth", "Verify TLS"],
          [[cC(s.name), s.host, ROLE_LABEL.get(s.role, "?"), s.auth_mode,
            str(s.verify)] for s in ctx.sessions])
    return 0


def cmd_doctor(args, ctx):
    _probes, healthy = act_doctor(ctx.sessions, args.domain, ctx.exporter)
    if args.fail_on_missing and not healthy:
        return 1
    return 0


def cmd_profiles(args, ctx):
    section("Profiles")
    if not ctx.inventory_path:
        err("No inventory in effect.")
        return 2
    names = list_profiles(ctx.inventory_path)
    say("  Inventory: {}".format(cC(ctx.inventory_path)))
    if not names:
        say("\n  {} -- a single-estate inventory.".format(cD("No profiles")))
        say("  {}".format(cD(
            "Add a 'profiles' object to name several estates; see "
            "`nsxctl profiles --help`.")))
        ctx.exporter.stage("profiles", PROFILE_HEADERS,
                           [[IMPLICIT_PROFILE, "yes", ""]])
        return 0
    active, why = resolve_profile(ctx.inventory_path, args.profile)
    rows = []
    for name in names:
        try:
            count = len(load_inventory(ctx.inventory_path, profile=name))
        except ConfigError:
            count = 0
        rows.append([name, "yes" if name == active else "", str(count)])
    table(["Profile", "In effect", "Managers"],
          [[cC(r[0]), cBG(r[1]) if r[1] else "", r[2]] for r in rows],
          indent=4)
    say("\n  {} selected by {}.".format(cB(str(active)), cD(why)))
    ctx.exporter.stage("profiles", PROFILE_HEADERS, rows)
    return 0


def cmd_projects(args, ctx):
    section("NSX Projects")
    rows = []
    for nsx in ctx.sessions:
        try:
            found = nsx.get_all(p_projects(nsx.org))
        except NsxError as e:
            say("  {:22s}  {}".format(cC(nsx.name), cD(
                "no project API ({})".format(str(e)[:70]))))
            continue
        if not found:
            say("  {:22s}  {}".format(cC(nsx.name), cD("no projects")))
            continue
        for project in found:
            rows.append([nsx.name, project.get(F_ID, "?"),
                         project.get(F_DISPLAY_NAME, ""),
                         project.get("description", "")])
    if rows:
        table(["Manager", "Id", "Name", "Description"],
              [[cC(r[0]), cB(r[1]), r[2], cD(r[3])] for r in rows], indent=4)
        say("\n  {}".format(cD(
            "Scope a run to one with --project ID. Objects in the default "
            "infra are not visible from inside a project.")))
    ctx.exporter.stage("projects", PROJECT_HEADERS, rows)
    return 0


def cmd_login(args, ctx):
    only = {args.name} if args.name else None
    if only and not any(m.get("name") in only for m in ctx.managers):
        err("'{}' is not in the inventory. Known: {}".format(
            args.name, ", ".join(m.get("name", "?") for m in ctx.managers)))
        return 2
    return force_set_credentials(ctx.managers, only=only)


def _resolve(args):
    inv = find_inventory(args.inventory, config_search_dirs())
    tax = load_taxonomy(
        args.taxonomy,
        search_dirs=([os.path.dirname(os.path.abspath(inv))] if inv else [])
        + config_search_dirs(),
        names=("taxonomy.json", "taxonomy.yaml", "taxonomy.yml"))
    return inv, tax


def cmd_config_path(args, ctx):
    inv, tax = _resolve(args)
    section("Paths")
    rows = [
        ["inventory", inv or cD("(none found)")],
        ["taxonomy", tax.source],
        ["credentials", creds_file_path()],
        ["audit log", DEFAULT_AUDIT_FILE],
        ["exports", DEFAULT_EXPORT_DIR],
        ["change plans", DEFAULT_TICKET_DIR],
        ["snapshots", DEFAULT_SNAPSHOT_DIR],
        ["data dir", DATA_DIR],
    ]
    table(["What", "Where"], rows)
    say("")
    say("  Searched for inventory.json in: {}".format(
        cD(", ".join(config_search_dirs()))))
    return 0


def cmd_config_show(args, ctx):
    inv, tax = _resolve(args)
    section("Configuration in effect")
    say("  Inventory : {}".format(cC(inv) if inv else cBR("none found")))
    say("  Taxonomy  : {}".format(cC(tax.source)))
    say("  Keyring   : {}".format(
        cBG("available") if keyring_available() else cD("not available")))
    if inv:
        try:
            managers = load_inventory(inv)
        except ConfigError as e:
            err(str(e))
            return 1
        say("\n  {}".format(cB("Managers")))
        table(["Name", "Host", "Role", "Auth", "Verify TLS"],
              [[m.get("name", "?"), m.get("host", "?"),
                ROLE_LABEL.get(m.get("role"), "?"), m.get("auth", "session"),
                str(m.get("verify_ssl", True))] for m in managers], indent=4)
    say("\n  {}".format(cB("Tag taxonomy")))
    rows = []
    for scope in tax.all_scopes:
        allowed = tax.values_for(scope)
        rows.append([scope,
                     "yes" if scope in tax.mandatory else "no",
                     ", ".join(allowed) if allowed else cD("(any)")])
    table(["Scope", "Required", "Allowed values"], rows, indent=4)
    return 0


def cmd_config_validate(args, ctx):
    inv, _ = _resolve(args)
    problems = 0
    if not inv:
        err("No inventory found. Run: nsxctl init")
        return 2
    try:
        managers = load_inventory(inv)
        ok_msg("inventory: {} manager(s) in {}".format(len(managers), inv))
    except ConfigError as e:
        err(str(e))
        problems += 1
    try:
        tax = load_taxonomy(
            args.taxonomy,
            search_dirs=[os.path.dirname(os.path.abspath(inv))]
            + config_search_dirs(),
            names=("taxonomy.json", "taxonomy.yaml", "taxonomy.yml"))
        ok_msg("taxonomy: {} required, {} optional scope(s) from {}".format(
            len(tax.mandatory), len(tax.conditional), tax.source))
    except ConfigError as e:
        err(str(e))
        problems += 1
    hr()
    if problems:
        say("  {} problem(s).".format(cBR(str(problems))))
        return 1
    say("  {}".format(cBG("Configuration is valid.")))
    return 0


# ==========================================================================
# commands/group.py  --  Groups: `nsxctl group list|show|create|edit|delete`.
# ==========================================================================

def register_group(sub, parents):
    p = add_command(
        sub, parents, "group", "Search and inspect security groups.")
    gsub = p.add_subparsers(dest="group_action", metavar="<action>")

    ls = add_action(
        gsub, parents, "list", "List groups and their criteria.",
        description="List groups on the Global Manager and Local Managers, "
                    "with their membership criteria.",
        epilog="examples:\n"
               "  nsxctl group list\n"
               "  nsxctl group list --contains web-prod\n"
               "  nsxctl group list --members --out-csv groups.csv")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only groups whose name or id contains TEXT.")
    ls.add_argument("--members", action="store_true",
                    help="Also resolve and list VM members.")
    ls.set_defaults(func=cmd_group_list)

    sh = add_action(
        gsub, parents, "show", "Show one group in full.",
        description="Show a single group's criteria and members.",
        epilog="example:\n  nsxctl group show web-prod")
    sh.add_argument("name", help="Group name or id.")
    sh.set_defaults(func=cmd_group_show)

    cr = add_action(
        gsub, parents, "create", "Create a group from criteria.",
        description="Create a dynamic security group.\n\n" + CRITERIA_HELP +
                    "\n\nDry run by default: nothing is written without "
                    "--enable-writes.",
        epilog="examples:\n"
               "  nsxctl group create g-web --criteria 'tag:env=prod AND "
               "tag:tier=web'\n"
               "  nsxctl group create g-web --criteria 'tag:env=prod' "
               "--enable-writes --yes")
    cr.add_argument("name", help="Group id to create.")
    cr.add_argument("--criteria", required=True,
                    help="Membership criteria. See the syntax above.")
    cr.add_argument("--display-name", help="Human-readable name.")
    cr.add_argument("--description", help="Free-text description.")
    cr.set_defaults(func=cmd_group_create)

    ed = add_action(
        gsub, parents, "edit", "Change an existing group.",
        description="Change a group's criteria, name or description. The plan "
                    "is shown as a field-level diff before anything is "
                    "written.\n\n" + CRITERIA_HELP,
        epilog="example:\n"
               "  nsxctl group edit g-web --criteria 'tag:env=prod OR "
               "tag:env=staging'")
    ed.add_argument("name", help="Group name or id.")
    ed.add_argument("--criteria", help="Replacement membership criteria.")
    ed.add_argument("--display-name", help="New human-readable name.")
    ed.add_argument("--description", help="New description.")
    ed.set_defaults(func=cmd_group_edit)

    dl = add_action(
        gsub, parents, "delete", "Delete a group.",
        description="Delete a group. Rules referencing it are NOT rewritten -- "
                    "run `nsxctl rule hygiene` afterwards to find any left "
                    "pointing at nothing.",
        epilog="example:\n  nsxctl group delete g-old --enable-writes")
    dl.add_argument("name", help="Group name or id.")
    dl.set_defaults(func=cmd_group_delete)

    p.set_defaults(func=_group_needs_action)


def _group_needs_action(args, ctx):
    err("Specify what to do: nsxctl group list | show | create | edit | delete")
    return 2


def _targets(ctx):
    """Groups exist on GM and LMs alike, so sweep whatever is connected."""
    return [s for s in ctx.sessions if s.role in (ROLE_GM, ROLE_LM)]


def cmd_group_list(args, ctx):
    act_groups(_targets(ctx), args.domain, args.contains,
               show_members=args.members, exporter=ctx.exporter,
               cache_key=ctx.cache_key())
    return 0


def cmd_group_show(args, ctx):
    act_groups(_targets(ctx), args.domain, args.name,
               show_members=True, exporter=ctx.exporter,
               cache_key=ctx.cache_key())
    return 0


def _group_write(args, ctx, **kwargs):
    """Shared plumbing: dry run unless writes are enabled."""
    try:
        result = act_group_write(
            ctx, args.name, dry_run=not ctx.write_enabled,
            force=args.force, **kwargs)
    except (NsxError, ConfigError) as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


def cmd_group_create(args, ctx):
    return _group_write(args, ctx, criteria=args.criteria,
                        display_name=args.display_name,
                        description=args.description)


def cmd_group_edit(args, ctx):
    if not any((args.criteria, args.display_name, args.description)):
        err("Nothing to change. Give --criteria, --display-name or "
            "--description.")
        return 2
    return _group_write(args, ctx, criteria=args.criteria,
                        display_name=args.display_name,
                        description=args.description)


def cmd_group_delete(args, ctx):
    return _group_write(args, ctx, delete=True)


# ==========================================================================
# commands/tag.py  --  Tag operations: `nsxctl tag list|find|edit|apply|ticket`.
# ==========================================================================

CSV_HELP = "CSV with columns: vm_name,scope,tag,action  (action = add | remove)"


def register_tag(sub, parents):
    p = add_command(sub, parents, "tag", "Read and change VM tags.")
    tsub = p.add_subparsers(dest="tag_action", metavar="<action>")

    ls = tsub.add_parser(
        "list", parents=parents, help="Show every tag on a VM.",
        description="Show all tags on matching VMs, validated against the "
                    "configured taxonomy.",
        epilog="example:\n  nsxctl tag list web-prod-01")
    ls.add_argument("vm", help="VM name, or part of one.")
    ls.set_defaults(func=cmd_tag_list)

    fd = tsub.add_parser(
        "find", parents=parents, help="Find every VM carrying a tag.",
        description="Find VMs by tag scope, value, or both.",
        epilog="examples:\n"
               "  nsxctl tag find --scope env --tag prod\n"
               "  nsxctl tag find --scope owner --out-csv owners.csv")
    fd.add_argument("--scope", help="Tag scope (blank = any).")
    fd.add_argument("--tag", help="Tag value (blank = any).")
    fd.set_defaults(func=cmd_tag_find)

    ed = tsub.add_parser(
        "edit", parents=parents, help="Add or remove tags interactively.",
        description="Interactive add/remove for one VM. Audit-logged and "
                    "undoable.",
        epilog="example:\n  nsxctl tag edit web-prod-01 --enable-writes")
    ed.add_argument("vm", help="VM name, or part of one.")
    ed.set_defaults(func=cmd_tag_edit)

    ap = tsub.add_parser(
        "apply", parents=parents, help="Apply bulk tag changes from a CSV.",
        description="Bulk tag changes. Always previews first; writing needs "
                    "--enable-writes and confirmation.\n\n" + CSV_HELP,
        epilog="examples:\n"
               "  nsxctl tag apply changes.csv                    preview only\n"
               "  nsxctl tag apply changes.csv --enable-writes --yes")
    ap.add_argument("csv", metavar="FILE", help=CSV_HELP)
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview only, even with --enable-writes.")
    ap.set_defaults(func=cmd_tag_apply)

    tk = tsub.add_parser(
        "ticket", parents=parents, help="Generate a change-plan document.",
        description="Build a change plan from a CSV, validated against live "
                    "NSX: current tags, proposed tags, and anything that "
                    "cannot be resolved.\n\n" + CSV_HELP,
        epilog="example:\n  nsxctl tag ticket changes.csv")
    tk.add_argument("csv", metavar="FILE", help=CSV_HELP)
    tk.set_defaults(func=cmd_tag_ticket)

    p.set_defaults(func=_tag_needs_action)


def _tag_needs_action(args, ctx):
    err("Specify what to do: nsxctl tag list|find|edit|apply|ticket")
    return 2


def cmd_tag_list(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_vm_tags(ctx.lms(), args.vm, ctx.exporter, ctx.taxonomy)
    return 0


def cmd_tag_find(args, ctx):
    if not args.scope and not args.tag:
        err("Give --scope, --tag, or both.")
        return 2
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_vms_by_tag(ctx.lms(), args.scope, args.tag, ctx.exporter)
    return 0


def cmd_tag_edit(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_manage_tags(ctx.lms(), args.vm, ctx.audit, ctx.write_enabled,
                    ctx.taxonomy)
    return 0


def cmd_tag_apply(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    # Preview always runs first, in every invocation path.
    act_bulk_tag(ctx.lms(), args.csv, ctx.audit, ctx.write_enabled,
                 dry_run=True, taxonomy=ctx.taxonomy)
    if args.dry_run:
        return 0
    if not ctx.write_enabled:
        say("\n  {} -- add --enable-writes to apply.".format(cBY("READ-ONLY")))
        return 0
    if not _tag_write_gate():
        say("  Cancelled -- nothing written.")
        return 0
    result = act_bulk_tag(ctx.lms(), args.csv, ctx.audit, ctx.write_enabled,
                          dry_run=False, taxonomy=ctx.taxonomy,
                          force=args.force)
    return 1 if result["failed"] else 0


def _tag_write_gate():
    """A write needs --yes, or an interactive confirmation. Never assumed."""
    pass
    if assume_yes():
        return True
    if not is_interactive():
        err("Refusing to write without confirmation. Re-run with --yes "
            "(or --dry-run to preview).")
        return False
    return confirm("  {} [y/N]: ".format(cB("Apply for real?")))


def cmd_tag_ticket(args, ctx):
    act_change_ticket(ctx.sessions, args.csv, ctx.exporter)
    return 0


# ==========================================================================
# commands/rule.py  --  DFW rules: `nsxctl rule hygiene|baseline|create|edit|move|delete`.
# ==========================================================================

def register_rule(sub, parents):
    p = add_command(
        sub, parents, "rule", "Inspect distributed firewall rules.")
    rsub = p.add_subparsers(dest="rule_action", metavar="<action>")

    hy = add_action(
        rsub, parents, "hygiene", "Report rule hygiene problems.",
        description="Find any-any rules, overly broad applied-to scopes, "
                    "rules referencing missing or inert groups, duplicates, "
                    "rules shadowed by an any-any above them, disabled rules, "
                    "and drop rules with logging off.\n\n"
                    "Findings marked 'soft' are indications, not proof, and "
                    "say why in the detail column.",
        epilog="examples:\n"
               "  nsxctl rule hygiene\n"
               "  nsxctl rule hygiene --json\n"
               "  nsxctl rule hygiene --out-html hygiene.html\n"
               "  nsxctl rule hygiene --fail-on critical    # for CI")
    hy.add_argument("--fail-on", choices=SEVERITIES, metavar="LEVEL",
                    help="Exit 1 when findings at or above LEVEL exist "
                         "({}).".format(" | ".join(SEVERITIES)))
    hy.add_argument("--skip-member-counts", action="store_true",
                    help="Do not resolve group members. Faster on large "
                         "estates; drops the empty-group check.")
    hy.set_defaults(func=cmd_rule_hygiene)

    bl = add_action(
        rsub, parents, "baseline",
        "Save or compare rule hit counts.",
        description="NSX hit counters are cumulative since the last reset, so "
                    "a single read cannot prove a rule is unused. Save a "
                    "baseline, wait, then compare: a counter that did not "
                    "move between the two reads genuinely saw no traffic in "
                    "that window.\n\n"
                    "If the second read is lower than the first, the counter "
                    "was reset and the window proves nothing -- that is "
                    "reported as counter_reset, never as unused.",
        epilog="examples:\n"
               "  nsxctl rule baseline save\n"
               "  nsxctl rule baseline save --baseline-file monday.json\n"
               "  nsxctl rule baseline compare --baseline-file monday.json")
    bl.add_argument("action", choices=("save", "compare"))
    bl.add_argument("--baseline-file", metavar="PATH",
                    help="Baseline to write, or to compare against "
                         "(required for compare).")
    bl.set_defaults(func=cmd_rule_baseline)

    ls = add_action(
        rsub, parents, "list", "List DFW rules in evaluation order.",
        description="Every rule across the Global Manager and Local Managers, "
                    "deduplicated, listed in the order NSX evaluates them: "
                    "category first (Ethernet, Emergency, Infrastructure, "
                    "Environment, Application), then policy and rule "
                    "sequence.\n\n"
                    "That is not the order the API returns them in, and it is "
                    "the order that decides traffic.",
        epilog="examples:\n"
               "  nsxctl rule list\n"
               "  nsxctl rule list --policy app-tier\n"
               "  nsxctl rule list --action DROP --out-csv drops.csv\n"
               "  nsxctl rule list --disabled")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only rules whose name or id contains TEXT.")
    ls.add_argument("--policy", metavar="NAME",
                    help="Only rules in policies matching NAME.")
    ls.add_argument("--action", metavar="ACTION",
                    help="Only rules with this action.")
    ls.add_argument("--disabled", action="store_true",
                    help="Only disabled rules.")
    ls.set_defaults(func=cmd_rule_list)

    sh = add_action(
        rsub, parents, "show", "Show one rule in full.",
        description="Every field of a rule, unabridged, including its "
                    "realized numeric id -- the one a traceflow observation "
                    "names when it drops a packet.",
        epilog="example:\n  nsxctl rule show allow-web-db")
    sh.add_argument("name", help="Rule name or id.")
    sh.add_argument("--policy", help="Policy the rule is in.")
    sh.set_defaults(func=cmd_rule_show)

    cr = add_action(
        rsub, parents, "create", "Create a DFW rule.",
        description="Create a rule in an existing security policy.\n\n"
                    "Before anything is written the proposed rule is run "
                    "through the same checks as `nsxctl rule hygiene`, so an "
                    "any-any ALLOW is caught here rather than in tomorrow's "
                    "report. Dry run by default.",
        epilog="examples:\n"
               "  nsxctl rule create allow-web-db --policy app-tier \\\n"
               "      --from g-web --to g-db --service MySQL --action ALLOW\n"
               "  nsxctl rule create deny-all --policy app-tier "
               "--action DROP --enable-writes")
    cr.add_argument("name", help="Rule id to create.")
    _add_rule_body_args(cr, require_policy=True)
    cr.set_defaults(func=cmd_rule_create)

    ed = add_action(
        rsub, parents, "edit", "Change an existing rule.",
        description="Change a rule. The plan is a field-level diff, "
                    "classified security or cosmetic by the same engine "
                    "`nsxctl drift` uses.",
        epilog="example:\n  nsxctl rule edit allow-web-db --action DROP")
    ed.add_argument("name", help="Rule name or id.")
    _add_rule_body_args(ed)
    ed.set_defaults(func=cmd_rule_edit)

    mv = add_action(
        rsub, parents, "move", "Reorder a rule within its policy.",
        description="Move a rule before or after another in the same policy, "
                    "by giving it a sequence number in the gap. If there is "
                    "no free number in that gap it refuses rather than "
                    "renumbering every rule in the policy.",
        epilog="example:\n  nsxctl rule move allow-web-db --before deny-all")
    mv.add_argument("name", help="Rule name or id.")
    mv.add_argument("--policy", help="Policy the rule is in.")
    group = mv.add_mutually_exclusive_group(required=True)
    group.add_argument("--before", metavar="RULE",
                       help="Put it immediately before this rule.")
    group.add_argument("--after", metavar="RULE",
                       help="Put it immediately after this rule.")
    mv.set_defaults(func=cmd_rule_move)

    dl = add_action(
        rsub, parents, "delete", "Delete a rule.",
        description="Delete a rule. Undo can restore it from the audit log, "
                    "but recreating a deleted object is the one undo this "
                    "tool will not promise -- take a snapshot first.",
        epilog="example:\n  nsxctl rule delete old-rule --enable-writes")
    dl.add_argument("name", help="Rule name or id.")
    dl.add_argument("--policy", help="Policy the rule is in.")
    dl.set_defaults(func=cmd_rule_delete)

    p.set_defaults(func=_rule_needs_action)


def cmd_rule_list(args, ctx):
    act_rule_list(ctx.sessions, args.domain, ctx.exporter,
                  contains=args.contains, policy_ref=args.policy,
                  action=args.action, disabled_only=args.disabled,
                  cache_key=ctx.cache_key())
    return 0


def cmd_rule_show(args, ctx):
    try:
        act_rule_show(ctx.sessions, args.domain, ctx.exporter, args.name,
                      policy_ref=args.policy)
    except NsxError as e:
        err(str(e))
        return 2
    return 0


def _add_rule_body_args(parser, require_policy=False):
    parser.add_argument("--policy", required=require_policy,
                        help="Security policy the rule belongs to.")
    parser.add_argument("--from", dest="sources", action="append",
                        metavar="GROUP",
                        help="Source group. Repeatable. Default ANY.")
    parser.add_argument("--to", dest="destinations", action="append",
                        metavar="GROUP",
                        help="Destination group. Repeatable. Default ANY.")
    parser.add_argument("--service", dest="services", action="append",
                        metavar="SERVICE",
                        help="Service. Repeatable. Default ANY.")
    parser.add_argument("--applied-to", dest="scope", action="append",
                        metavar="GROUP",
                        help="Enforce only on these groups. Default ANY, "
                             "which means every workload.")
    parser.add_argument("--action", choices=RULE_ACTIONS, metavar="ACTION",
                        help="One of {}.".format(" | ".join(RULE_ACTIONS)))
    parser.add_argument("--direction", choices=RULE_DIRECTIONS,
                        metavar="DIRECTION",
                        help="One of {}.".format(" | ".join(RULE_DIRECTIONS)))
    parser.add_argument("--display-name", help="Human-readable name.")
    parser.add_argument("--description", help="Free-text description.")
    parser.add_argument("--sequence", type=int, metavar="N",
                        help="Evaluation position within the policy.")
    logging = parser.add_mutually_exclusive_group()
    logging.add_argument("--log", dest="logged", action="store_true",
                         default=None, help="Turn rule logging on.")
    logging.add_argument("--no-log", dest="logged", action="store_false",
                         default=None, help="Turn rule logging off.")
    state = parser.add_mutually_exclusive_group()
    state.add_argument("--disable", dest="disabled", action="store_true",
                       default=None, help="Disable the rule.")
    state.add_argument("--enable", dest="disabled", action="store_false",
                       default=None, help="Enable the rule.")


def _rule_write(args, ctx, **kwargs):
    try:
        result = act_rule_write(ctx, args.name, dry_run=not ctx.write_enabled,
                                force=args.force, **kwargs)
    except (NsxError, ConfigError) as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


def _rule_body_kwargs(args):
    return {"policy_ref": args.policy, "sources": args.sources,
            "destinations": args.destinations, "services": args.services,
            "scope": args.scope, "action": args.action,
            "direction": args.direction, "display_name": args.display_name,
            "description": args.description, "disabled": args.disabled,
            "logged": args.logged, "sequence_number": args.sequence}


def cmd_rule_create(args, ctx):
    return _rule_write(args, ctx, **_rule_body_kwargs(args))


def cmd_rule_edit(args, ctx):
    kwargs = _rule_body_kwargs(args)
    if not any(v is not None for k, v in kwargs.items() if k != "policy_ref"):
        err("Nothing to change. Give at least one of --from, --to, --service, "
            "--applied-to, --action, --direction, --display-name, "
            "--description, --sequence, --log/--no-log, --enable/--disable.")
        return 2
    return _rule_write(args, ctx, **kwargs)


def cmd_rule_move(args, ctx):
    return _rule_write(args, ctx, policy_ref=args.policy,
                       move_before=args.before, move_after=args.after)


def cmd_rule_delete(args, ctx):
    return _rule_write(args, ctx, policy_ref=args.policy, delete=True)


def _rule_needs_action(args, ctx):
    err("Specify what to do: nsxctl rule list | show | hygiene | baseline "
        "| create | edit | move | delete")
    return 2


# === hygiene ===
def cmd_rule_hygiene(args, ctx):
    findings, worst = act_hygiene(
        ctx.sessions, args.domain, ctx.exporter,
        with_members=not args.skip_member_counts)

    if args.out_html:
        counts = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        path = write_report(
            args.out_html,
            "DFW Rule Hygiene",
            "domain <code>{}</code> &middot; {} manager(s)".format(
                args.domain, len(ctx.sessions)),
            notes=[
                "Findings marked 'soft' are indications, not proof -- the "
                "detail column says why.",
                "Hit counters are cumulative since the last reset, so a zero "
                "count is not evidence a rule is unused. Use "
                "`nsxctl rule baseline` for that.",
                "Group member counts are resolved only for groups whose "
                "criteria is VM-resolvable; others are never reported as "
                "empty.",
            ],
            tiles=[(sev, counts.get(sev, 0)) for sev in SEVERITIES],
            sections=[("Findings", HYGIENE_HEADERS,
                       [f.row() for f in findings])])
        ok_msg("HTML report: {}".format(path))

    if args.fail_on:
        blocking = at_or_above(findings, args.fail_on)
        if blocking:
            say("\n  {} {} finding(s) at or above {}.".format(
                cBR("FAIL:"), len(blocking), args.fail_on))
            return 1
        say("\n  {} nothing at or above {}.".format(cBG("PASS:"),
                                                    args.fail_on))
    return 0


# === baseline ===
def _current_snapshot(ctx, domain):
    records = sweep_rules(ctx.sessions, domain)
    stats, supported = fetch_hit_counts(records, domain)
    if not supported:
        raise NsxError(
            "This NSX did not serve rule statistics, so hit counts cannot be "
            "baselined. Run with --debug to see the request that failed.")
    return build_hit_baseline(records, stats, domain=domain), records


def cmd_rule_baseline(args, ctx):
    if args.action == "save":
        return _baseline_save(args, ctx)
    return _baseline_compare(args, ctx)


def _baseline_save(args, ctx):
    section("SAVE HIT-COUNT BASELINE")
    snapshot, _ = _current_snapshot(ctx, args.domain)
    path = save_hit_baseline(snapshot, args.baseline_file,
                             domain=args.domain)
    measured = sum(1 for r in snapshot["rules"].values()
                   if r.get("hit_count") is not None)
    say("  Rules recorded : {}".format(cC(str(snapshot["rule_count"]))))
    say("  With counters  : {}".format(cC(str(measured))))
    say("  Taken          : {}".format(snapshot["taken"]))
    ok_msg("Baseline: {}".format(path))
    say("\n  {} compare against it later with:".format(cD("next:")))
    say("    {}".format(cC(
        "nsxctl rule baseline compare --baseline-file {}".format(path))))
    return 0


def _baseline_compare(args, ctx):
    if not args.baseline_file:
        err("compare needs --baseline-file PATH (from `rule baseline save`).")
        return 2
    before = load_hit_baseline(args.baseline_file)
    section("COMPARE AGAINST HIT-COUNT BASELINE")
    after, _ = _current_snapshot(ctx, args.domain)

    results = compare_hit_baselines(before, after)
    counts = hit_baseline_summary(results)
    ctx.exporter.stage("hit_baseline", BASELINE_HEADERS, hit_baseline_rows(results))

    say("  Baseline taken : {}".format(before.get("taken", "?")))
    say("  Compared at    : {}".format(after.get("taken", "?")))
    hr()

    unused = [r for r in results if r["status"] == "unused_since_baseline"]
    reset = [r for r in results if r["status"] == "counter_reset"]

    table(["Status", "Rules"],
          [[_status_colour(status)(status), str(counts[status])]
           for status in sorted(counts, key=lambda s: -counts[s])], indent=4)

    if reset:
        say("\n  {} {} rule(s) had their counters reset between the two "
            "reads.".format(cBY("WARNING:"), len(reset)))
        say("  {}".format(cD(
            "For those the window proves nothing -- take a fresh baseline.")))
        for result in reset[:10]:
            say("    {} / {}   {} -> {}".format(
                result["policy"], result["rule"],
                result["hits_then"], result["hits_now"]))

    if unused:
        say("\n  {} saw no traffic between the two reads:".format(
            cB("{} rule(s)".format(len(unused)))))
        for result in unused[:40]:
            say("    {} / {}   [{}]".format(
                result["policy"], result["rule"], cD(result["manager"])))
        if len(unused) > 40:
            say("    {}".format(cD(
                "... +{} more (full set in export)".format(len(unused) - 40))))
        say("\n  {} this IS evidence for the window shown above. It is not "
            "evidence".format(cD("note:")))
        say("  {}".format(cD(
            "about any traffic outside it -- a monthly pattern needs a "
            "monthly window.")))
    else:
        say("\n  {} every rule with counters saw traffic in this "
            "window.".format(cBG("None idle:")))

    if args.out_html:
        path = write_report(
            args.out_html, "Rule Hit Baseline Comparison",
            "baseline <code>{}</code> &rarr; now".format(
                before.get("taken", "?")),
            notes=[
                "unused_since_baseline means the counter did not move between "
                "the two reads. That is evidence for this window only.",
                "counter_reset means the counter went backwards, so it was "
                "reset and this window proves nothing.",
            ],
            tiles=[(status, counts[status]) for status in sorted(counts)],
            sections=[("Per-rule comparison", BASELINE_HEADERS,
                       hit_baseline_rows(results))])
        ok_msg("HTML report: {}".format(path))

    if not is_json_mode():
        hr()
    return 0


def _status_colour(status):
    return {"counter_reset": cBY, "unused_since_baseline": cB,
            "active": cBG, "added": cD, "removed": cD}.get(status, cD)


# ==========================================================================
# commands/inspect.py  --  Policy and service inspection: `nsxctl policy|service list|show`.
# ==========================================================================

def register_inspect(sub, parents):
    p = add_command(
        sub, parents, "policy", "Inspect security policies.")
    psub = p.add_subparsers(dest="policy_action", metavar="<action>")
    ls = add_action(
        psub, parents, "list", "List security policies.",
        description="Policies across every manager, deduplicated, in NSX "
                    "evaluation order with their rule counts. This is where "
                    "the name `nsxctl rule create --policy` wants comes from.",
        epilog="examples:\n"
               "  nsxctl policy list\n"
               "  nsxctl policy list --contains app")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only policies whose name or id contains TEXT.")
    ls.set_defaults(func=cmd_policy_list)
    p.set_defaults(func=cmd_policy_list, contains=None)

    p = add_command(
        sub, parents, "service", "Inspect service definitions.")
    ssub = p.add_subparsers(dest="service_action", metavar="<action>")
    ls = add_action(
        ssub, parents, "list", "List services and their ports.",
        description="Service definitions, with the ports each covers and "
                    "whether it is a plain L4 port set.\n\n"
                    "That last column is what makes an undecided "
                    "`nsxctl trace` verdict explicable: only an L4 port set "
                    "reduces to a port comparison, so a rule limited to an "
                    "ICMP or ALG service cannot be decided by port alone.",
        epilog="examples:\n"
               "  nsxctl service list\n"
               "  nsxctl service list --contains sql")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only services whose name or id contains TEXT.")
    ls.set_defaults(func=cmd_service_list)
    sh = add_action(
        ssub, parents, "show", "Show one service in full.",
        description="Every entry of a service definition, spelled out.",
        epilog="example:\n  nsxctl service show MySQL")
    sh.add_argument("name", help="Service name or id.")
    sh.set_defaults(func=cmd_service_show)
    p.set_defaults(func=cmd_service_list, contains=None)


def cmd_policy_list(args, ctx):
    act_policy_list(ctx.sessions, args.domain, ctx.exporter,
                    contains=getattr(args, "contains", None),
                    cache_key=ctx.cache_key())
    return 0


def cmd_service_list(args, ctx):
    act_service_list(ctx.sessions, args.domain, ctx.exporter,
                     contains=getattr(args, "contains", None),
                     cache_key=ctx.cache_key())
    return 0


def cmd_service_show(args, ctx):
    act_service_show(ctx.sessions, args.domain, ctx.exporter, args.name)
    return 0


# ==========================================================================
# commands/analysis.py  --  Analysis commands: impact, parity, compliance, audit.
# ==========================================================================

def register_analysis(sub, parents):
    p = add_command(
        sub, parents, "impact",
        "What breaks if I change this VM: VM -> groups -> DFW rules.",
        description="Resolve every group a VM belongs to (any member type) "
                    "and every DFW rule referencing those groups. Sweeps the "
                    "Global Manager and all Local Managers, deduplicating "
                    "GM-authored rules realized onto each LM.",
        epilog="example:\n  nsxctl impact web-prod-01")
    p.add_argument("vm", help="VM name, or part of one.")
    p.set_defaults(func=cmd_impact)

    p = add_command(
        sub, parents, "parity",
        "Compare a static group against its dynamic replacement.",
        description="Which members the static group has that the dynamic one "
                    "does not -- the real measure of migration progress. Both "
                    "groups are resolved on the same manager.",
        epilog="example:\n  nsxctl parity web-static web-dynamic")
    p.add_argument("static", help="Static group name or id.")
    p.add_argument("dynamic", help="Dynamic group name or id.")
    p.set_defaults(func=cmd_parity)

    p = add_command(
        sub, parents, "compliance",
        "Tagging posture across every Local Manager.",
        description="Per-scope coverage and per-manager progress against the "
                    "configured tag taxonomy.",
        epilog="examples:\n"
               "  nsxctl compliance\n"
               "  nsxctl compliance --json\n"
               "  nsxctl compliance --out-csv posture.csv")
    p.set_defaults(func=cmd_compliance)

    p = add_command(
        sub, parents, "audit", "Review and undo audited writes.",
        description="Every write the toolkit makes -- tags, groups and rules "
                    "alike -- is logged with both sides of it, and one entry "
                    "at a time can be reversed.\n\n"
                    "Undo is asymmetric: reversing a create is a delete and "
                    "reversing a modify is a write of the before-body, both "
                    "exact. Reversing a delete recreates an object whose "
                    "references may have been cleaned up in the meantime, "
                    "which cannot be guaranteed -- a snapshot restore is the "
                    "reliable way back from a delete.")
    asub = p.add_subparsers(dest="audit_action", metavar="<action>")
    ls = asub.add_parser("list", parents=parents,
                         help="Show recent audited writes.")
    ls.add_argument("-n", "--limit", type=int, default=20,
                    help="How many entries (default 20).")
    ls.set_defaults(func=cmd_audit_list)
    un = asub.add_parser("undo", parents=parents,
                         help="Reverse one audited write.")
    un.add_argument("-n", "--limit", type=int, default=20,
                    help="How many entries to choose from (default 20).")
    un.set_defaults(func=cmd_audit_undo)
    p.set_defaults(func=cmd_audit_list, audit_action="list", limit=20)


def cmd_impact(args, ctx):
    # Always the full session set -- see act_reverse_lookup's docstring for
    # why a partial selection produces a wrong answer here.
    act_reverse_lookup(ctx.sessions, args.vm, args.domain, ctx.exporter)
    return 0


def cmd_parity(args, ctx):
    act_parity(ctx.sessions, args.domain, args.static, args.dynamic,
               ctx.exporter)
    return 0


def cmd_compliance(args, ctx):
    act_dashboard(ctx.sessions, ctx.exporter, ctx.taxonomy)
    return 0


def cmd_audit_list(args, ctx):
    act_audit_log(ctx.audit, ctx.sessions, write_enabled=False,
                  exporter=ctx.exporter, limit=args.limit, domain=args.domain)
    return 0


def cmd_audit_undo(args, ctx):
    if not ctx.write_enabled:
        err("Undo writes to NSX. Re-run with --enable-writes.")
        return 2
    act_audit_log(ctx.audit, ctx.sessions, write_enabled=True,
                  exporter=ctx.exporter, limit=args.limit, domain=args.domain)
    return 0


# ==========================================================================
# commands/trace.py  --  Connectivity trace: `nsxctl trace A B --port 3306`.
# ==========================================================================

def register_trace(sub, parents):
    p = add_command(
        sub, parents, "trace",
        "Can A reach B, and which rule decided it.",
        description="Evaluates the policy, and -- unless --static is given --"
                    " injects a synthetic packet at the source VM's logical "
                    "port and reports what the data plane actually did with "
                    "it.\n\n"
                    "The two answers are printed separately and compared, "
                    "because they answer different questions and can "
                    "legitimately differ. NAT, a partial realization, or a "
                    "rule not yet pushed to a host will all make them "
                    "disagree, and that disagreement is the finding.\n\n"
                    "Traceflow is a Local Manager API: the Global Manager "
                    "does not serve it. With no LM connected, or a "
                    "powered-off source, --static is the only half that can "
                    "run and the report says so.",
        epilog="examples:\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 3306\n"
               "  nsxctl trace web-prod-01 --to 10.20.30.40 --port 443\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 3306 --static\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 22 --yes"
               "        # unattended\n"
               "  nsxctl trace web-prod-01 db-prod-01 --nic 2 --timeout 30s")
    p.add_argument("source", help="Source VM name, or part of one.")
    p.add_argument("destination", nargs="?",
                   help="Destination VM name. Omit when using --to.")
    p.add_argument("--to", metavar="ADDRESS", dest="to_address",
                   help="Trace to an IP address instead of a VM.")
    p.add_argument("--port", type=int, metavar="N",
                   help="Destination port. Without it, rules restricted to a "
                        "service cannot be decided and are reported as such.")
    p.add_argument("--proto", default=DEFAULT_PROTO,
                   choices=("tcp", "udp", "icmp"),
                   help="Transport protocol (default: {}).".format(DEFAULT_PROTO))
    p.add_argument("--nic", metavar="NIC",
                   help="Which NIC to trace from on a multi-NIC VM: a 1-based "
                        "index, a device name, or a MAC.")
    p.add_argument("--timeout", metavar="DURATION", default=None,
                   help="How long to wait for observations (15s, 2m). "
                        "Default 15s.")
    p.add_argument("--static", action="store_true",
                   help="Evaluate the policy only. Sends no packet, needs no "
                        "confirmation, and works on a GM or a powered-off VM.")
    p.set_defaults(func=cmd_trace)


def cmd_trace(args, ctx):
    if not args.destination and not args.to_address:
        err("Give a destination VM, or an address with --to.")
        return 2
    try:
        timeout = parse_duration(args.timeout)
        outcome = act_trace(
            ctx.sessions, args.source, args.destination, args.domain,
            ctx.exporter, port=args.port, proto=args.proto,
            to_address=args.to_address, static_only=args.static,
            nic=args.nic, timeout=timeout)
    except AmbiguousNic as e:
        report_ambiguous_nic(e)
        return 2
    except NsxError as e:
        # Nothing ran: an endpoint could not be resolved. That is a "could not
        # start" failure, not a finding about the flow.
        err(str(e))
        return 2
    return 0 if outcome.has_verdict else 1


# ==========================================================================
# commands/apply.py  --  Declarative batch: `nsxctl apply changes.yaml`.
# ==========================================================================

APPLY_EXAMPLE = """file format (JSON always; YAML if PyYAML is installed):

  groups:
    - id: g-web
      display_name: Web tier
      criteria: 'tag:env=prod AND tag:tier=web'
    - id: g-retired
      state: absent

  rules:
    - id: allow-web-db
      policy: app-tier
      source: [g-web]
      destination: [g-db]
      services: [MySQL]
      action: ALLOW

Every entry needs an id. `state: absent` deletes; the default is present,
which creates the object or brings it into line if it already exists.
"""


def register_apply(sub, parents):
    p = add_command(
        sub, parents, "apply",
        "Apply a declarative file of groups and rules.",
        description="Bring NSX into line with a file describing the groups "
                    "and rules that should exist.\n\n"
                    "Dry run by default: the whole plan is printed as a "
                    "field-level diff, proposed rules are run through the "
                    "hygiene checks, and nothing is written without "
                    "--enable-writes. An entry that already matches NSX "
                    "produces no change at all.\n\n" + APPLY_EXAMPLE,
        epilog="examples:\n"
               "  nsxctl apply changes.yaml\n"
               "  nsxctl apply changes.json --enable-writes --yes")
    p.add_argument("file", help="Change file (JSON, or YAML with PyYAML).")
    p.set_defaults(func=cmd_apply)


def cmd_apply(args, ctx):
    try:
        result = act_apply_file(ctx, args.file, dry_run=not ctx.write_enabled,
                                force=args.force)
    except ConfigError as e:
        err(str(e))
        return 2
    except NsxError as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


# ==========================================================================
# commands/recommend.py  --  Flow-derived rule proposals: `nsxctl recommend flows.csv`.
# ==========================================================================

RECOMMEND_HELP = """flow export format (CSV or a JSON list of records):

  source,destination,port,protocol,action,count
  10.1.1.10,10.1.2.20,3306,tcp,ALLOW,842
  10.1.1.11,10.1.2.20,3306,tcp,ALLOW,71

Column names are matched loosely -- src/src_ip/source_ip all work, as do
dst_port/destination_port -- because every exporter names them differently
and none of them are wrong. Denied flows are ignored unless --include-denied:
a blocked flow is usually evidence the segmentation is working, not evidence
a rule is missing.
"""


def register_recommend(sub, parents):
    p = add_command(
        sub, parents, "recommend",
        "Propose rules from a flow export.",
        description="Turn traffic that actually happened into a reviewable "
                    "ruleset.\n\n"
                    "Reads a flow export you already have (NSX Intelligence "
                    "export, vRNI, a firewall-log query) rather than calling "
                    "the Intelligence recommendation API, which is licensed "
                    "separately and absent on most estates.\n\n"
                    "Endpoints are resolved against the IP addresses your "
                    "groups declare. An address no group claims is REPORTED, "
                    "never guessed at -- an unclassified workload is the most "
                    "useful thing this finds.\n\n"
                    "Output is an `nsxctl apply` change file. Nothing is "
                    "written to NSX.\n\n" + RECOMMEND_HELP,
        epilog="examples:\n"
               "  nsxctl recommend flows.csv\n"
               "  nsxctl recommend flows.csv --policy app-tier "
               "--out-file proposed.json\n"
               "  nsxctl recommend flows.csv --max-ports 25")
    p.add_argument("flow_file", metavar="FLOWS",
                   help="Flow export (CSV, or a JSON list of records).")
    p.add_argument("--policy", metavar="NAME",
                   help="Policy the proposed rules should go in. Required to "
                        "write a change file.")
    p.add_argument("--out-file", metavar="PATH",
                   help="Write the proposal as an `nsxctl apply` document.")
    p.add_argument("--max-ports", type=int, default=DEFAULT_MAX_PORTS,
                   metavar="N",
                   help="Flag a pair talking on more than N ports instead of "
                        "proposing a rule for it (default {}).".format(
                            DEFAULT_MAX_PORTS))
    p.add_argument("--include-denied", action="store_true",
                   help="Also derive rules from flows that were denied.")
    p.set_defaults(func=cmd_recommend)


def cmd_recommend(args, ctx):
    try:
        proposals, _unresolved, _wide = act_recommend(
            ctx.sessions, args.domain, ctx.exporter, args.flow_file,
            policy=args.policy, out_file=args.out_file,
            max_ports=args.max_ports, include_denied=args.include_denied)
    except (ConfigError, NsxError) as e:
        err(str(e))
        return 2
    return 0 if proposals else 1


# ==========================================================================
# commands/snapshot.py  --  Snapshot and drift: `nsxctl snapshot ...` and `nsxctl drift`.
# ==========================================================================

CONSOLE_CHANGE_LIMIT = 40
IMPACT_COLOUR = {"security": cBR, "cosmetic": cD}
STATUS_COLOUR = {"added": cBG, "removed": cBR, "modified": cBY}
# "policies".rstrip("s") gives "policie"; spell the singulars out.
KIND_LABEL = {"groups": "group", "policies": "policy", "rules": "rule",
              "tags": "tags"}


def register_snapshot(sub, parents):
    p = add_command(
        sub, parents, "snapshot",
        "Capture and compare NSX configuration.",
        description="Snapshots are written as a directory of one JSON file "
                    "per object, with volatile fields stripped -- so `git "
                    "diff` on the tree shows real configuration changes and "
                    "nothing else.")
    ssub = p.add_subparsers(dest="snapshot_action", metavar="<action>")

    save = ssub.add_parser(
        "save", parents=parents, help="Capture the current configuration.",
        description="Read groups, policies and rules across every connected "
                    "manager and write them as a snapshot.",
        epilog="examples:\n"
               "  nsxctl snapshot save\n"
               "  nsxctl snapshot save approved-2026-Q1\n"
               "  nsxctl snapshot save --with-tags")
    save.add_argument("name", nargs="?",
                      help="Snapshot name (default: domain plus timestamp).")
    save.add_argument("--with-tags", action="store_true",
                      help="Also capture VM tags. Off by default because "
                           "retagging is routine churn that would bury a "
                           "real rule change.")
    save.add_argument("--snapshot-dir", metavar="DIR",
                      help="Where snapshots live (default: {}).".format(
                          DEFAULT_SNAPSHOT_DIR))
    save.set_defaults(func=cmd_snapshot_save)

    ls = ssub.add_parser("list", parents=parents,
                         help="List the snapshots taken so far.")
    ls.add_argument("--snapshot-dir", metavar="DIR")
    ls.set_defaults(func=cmd_snapshot_list, needs_inventory=False,
                    needs_sessions=False)

    show = ssub.add_parser("show", parents=parents,
                           help="Show one snapshot's manifest.")
    show.add_argument("name")
    show.add_argument("--snapshot-dir", metavar="DIR")
    show.set_defaults(func=cmd_snapshot_show, needs_inventory=False,
                      needs_sessions=False)

    diff = ssub.add_parser(
        "diff", parents=parents, help="Compare two snapshots.",
        description="Compare two stored snapshots. Neither needs a live NSX.",
        epilog="example:\n  nsxctl snapshot diff approved current")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--snapshot-dir", metavar="DIR")
    diff.add_argument("--fail-on-drift", choices=("security", "any"),
                      metavar="LEVEL",
                      help="Exit 1 when changes at this level exist "
                           "(security | any).")
    diff.set_defaults(func=cmd_snapshot_diff, needs_inventory=False,
                      needs_sessions=False)

    rs = add_action(
        ssub, parents, "restore", "Put a snapshot's configuration back.",
        description="Bring live NSX back into line with a stored snapshot, "
                    "one object at a time through the same plan-then-apply "
                    "path as `nsxctl rule edit`.\n\n"
                    "Each object gets a field-level diff you can read, a "
                    "_revision check that refuses to overwrite a concurrent "
                    "edit, and its own audit entry -- so a restore is "
                    "reviewable and individually undoable, not a blind push "
                    "of a whole tree.\n\n"
                    "Objects that exist now but not in the snapshot are LEFT "
                    "ALONE unless --prune is given: a snapshot records what "
                    "was there, it does not assert that nothing else may "
                    "exist, and a group created legitimately since is not "
                    "drift to be erased.\n\n"
                    "Dry run by default.",
        epilog="examples:\n"
               "  nsxctl snapshot restore approved\n"
               "  nsxctl snapshot restore approved --enable-writes\n"
               "  nsxctl snapshot restore approved --prune --enable-writes")
    rs.add_argument("name", nargs="?", help="Snapshot name or path.")
    rs.add_argument("--snapshot-dir", metavar="DIR")
    rs.add_argument("--prune", action="store_true",
                    help="Also DELETE objects that exist now but are not in "
                         "the snapshot.")
    rs.set_defaults(func=cmd_snapshot_restore)

    p.set_defaults(func=_snapshot_needs_action)

    d = add_command(
        sub, parents, "drift",
        "Has anything changed since the last snapshot?",
        description="Compare a snapshot against live NSX. With no name, uses "
                    "the most recent snapshot.\n\n"
                    "Changes are classified security or cosmetic, so a "
                    "scheduled check can stay quiet about a renamed policy "
                    "and be loud about a new any-any rule.",
        epilog="examples:\n"
               "  nsxctl drift\n"
               "  nsxctl drift approved-2026-Q1\n"
               "  nsxctl drift --fail-on-drift security   # for cron\n"
               "  nsxctl drift --out-html drift.html")
    d.add_argument("name", nargs="?",
                   help="Snapshot to compare against (default: newest).")
    d.add_argument("--snapshot-dir", metavar="DIR")
    d.add_argument("--fail-on-drift", choices=("security", "any"),
                   metavar="LEVEL",
                   help="Exit 1 when changes at this level exist "
                        "(security | any).")
    d.set_defaults(func=cmd_drift)


def _snapshot_needs_action(args, ctx):
    err("Specify what to do: nsxctl snapshot save|list|show|diff")
    return 2


def _snapshot_dir(args):
    return getattr(args, "snapshot_dir", None) or DEFAULT_SNAPSHOT_DIR


# === save / list / show ===
def cmd_snapshot_save(args, ctx):
    section("CAPTURE CONFIGURATION SNAPSHOT")
    snapshot = capture_snapshot(ctx.sessions, args.domain,
                                with_tags=args.with_tags)
    root = save_snapshot(snapshot, args.name, root_dir=_snapshot_dir(args))
    describe_snapshot(snapshot)
    ok_msg("Snapshot: {}".format(root))
    say("\n  {} check for changes later with:".format(cD("next:")))
    say("    {}".format(cC("nsxctl drift")))
    return 0


def cmd_snapshot_list(args, ctx):
    found = list_snapshots(_snapshot_dir(args))
    section("SNAPSHOTS")
    if not found:
        say("  None yet in {}.".format(_snapshot_dir(args)))
        say("  Take one with: {}".format(cC("nsxctl snapshot save")))
        return 0
    table(["Name", "Taken", "Domain", "Objects"],
          [[cC(item["name"]), item["taken"], item["domain"],
            ", ".join("{} {}".format(v, k)
                      for k, v in sorted(item["counts"].items()) if v)]
           for item in found])
    return 0


def cmd_snapshot_show(args, ctx):
    root = resolve_snapshot(args.name, _snapshot_dir(args))
    snapshot = load_snapshot(root)
    section("SNAPSHOT {}".format(snapshot["manifest"].get("name", args.name)))
    say("  Root     : {}".format(root))
    describe_snapshot(snapshot)
    return 0


# === diff / drift ===
def cmd_snapshot_restore(args, ctx):
    try:
        root = resolve_snapshot(args.name, args.snapshot_dir)
        snapshot = load_snapshot(root)
    except NsxError as e:
        err(str(e))
        return 2
    try:
        result = act_restore(ctx, snapshot,
                             dry_run=not ctx.write_enabled,
                             force=args.force, prune=args.prune)
    except (NsxError, ConfigError) as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


def cmd_snapshot_diff(args, ctx):
    directory = _snapshot_dir(args)
    before = load_snapshot(resolve_snapshot(args.before, directory))
    after = load_snapshot(resolve_snapshot(args.after, directory))
    section("SNAPSHOT DIFF")
    say("  Before : {}  ({})".format(args.before,
                                     before["manifest"].get("taken", "?")))
    say("  After  : {}  ({})".format(args.after,
                                     after["manifest"].get("taken", "?")))
    return _report(args, ctx, before, after)


def cmd_drift(args, ctx):
    directory = _snapshot_dir(args)
    root = resolve_snapshot(args.name, directory)
    before = load_snapshot(root)
    section("CONFIGURATION DRIFT")
    say("  Snapshot : {}  ({})".format(
        os.path.basename(root), before["manifest"].get("taken", "?")))
    say("  Against  : {}".format(cC("live NSX")))
    # The "after" side is captured in memory rather than written, so a drift
    # check never leaves a snapshot behind as a side effect.
    after = capture_snapshot(
        ctx.sessions, args.domain,
        with_tags=bool(before["manifest"].get("with_tags")))
    return _report(args, ctx, before, after)


def _report(args, ctx, before, after):
    changes = diff_snapshots(before, after)
    counts = summarise_diff(changes)
    ctx.exporter.stage("drift", DRIFT_HEADERS, diff_rows(changes))
    ctx.exporter.stage_findings("config_drift", drift_findings(changes))
    hr()

    if not changes:
        say("  {} configuration matches the snapshot exactly.".format(
            cBG("No drift:")))
        return 0

    table(["Change", "Count"],
          [[STATUS_COLOUR.get(k, cD)(k), str(counts[k])]
           for k in ("added", "removed", "modified") if counts.get(k)]
          + [[IMPACT_COLOUR.get(k, cD)(k), str(counts[k])]
             for k in ("security", "cosmetic") if counts.get(k)], indent=4)

    for change in changes[:CONSOLE_CHANGE_LIMIT]:
        who = ""
        if change.changed_by:
            who = "   {}".format(cD("by {}".format(change.changed_by)))
        say("\n  {} {} {} {}{}".format(
            STATUS_COLOUR.get(change.status, cD)(change.status.upper()),
            cD(KIND_LABEL.get(change.kind, change.kind)), cB(str(change.name)),
            IMPACT_COLOUR.get(change.impact, cD)("[{}]".format(change.impact)),
            who))
        for field in change.fields[:12]:
            if field.kind == "added":
                say("      {} {}".format(cG("+"), _line(field.field,
                                                        field.after)))
            elif field.kind == "removed":
                say("      {} {}".format(cBR("-"), _line(field.field,
                                                         field.before)))
            else:
                say("      {}: {} -> {}".format(
                    cC(field.field), cD(_short(field.before)),
                    _short(field.after)))
        if len(change.fields) > 12:
            say("      {}".format(cD("... +{} more field(s)".format(
                len(change.fields) - 12))))
    if len(changes) > CONSOLE_CHANGE_LIMIT:
        say("\n  {}".format(cD("... +{} more object(s) (full set in "
                               "export)".format(
                                   len(changes) - CONSOLE_CHANGE_LIMIT))))

    if args.out_html:
        path = write_report(
            args.out_html, "Configuration Drift",
            "{} object(s) changed".format(len(changes)),
            notes=[
                "Volatile fields (revision, timestamps, realization ids) are "
                "stripped before comparison, so everything listed here is a "
                "real configuration change.",
                "security means the change can alter what traffic is "
                "permitted. cosmetic means only a name, description or note "
                "changed.",
            ],
            tiles=[(k, counts.get(k, 0))
                   for k in ("added", "removed", "modified", "security")],
            sections=[("Changes", DRIFT_HEADERS, diff_rows(changes))])
        ok_msg("HTML report: {}".format(path))

    hr()
    if args.fail_on_drift:
        blocking = at_impact(changes, args.fail_on_drift)
        if blocking:
            say("  {} {} change(s) at level '{}'.".format(
                cBR("DRIFT:"), len(blocking), args.fail_on_drift))
            return 1
        say("  {} no changes at level '{}'.".format(
            cBG("PASS:"), args.fail_on_drift))
    return 0


def _short(value, limit=60):
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _line(field, value):
    return "{}: {}".format(field, _short(value))


# ==========================================================================
# commands/shell.py  --  Shell integration: `nsxctl completion`, `nsxctl menu`, `nsxctl version`.
# ==========================================================================

SHELLS = ("bash", "zsh", "fish")

# `completion <shell>` prints a script and needs no NSX at all; `completion
# cache` reads the whole estate. Same command, opposite requirements, which is
# why the requirement is set from the value rather than on the parser.
CACHE_TARGET = "cache"


class _CompletionTarget(argparse.Action):
    """Set the NSX requirement from which target was asked for."""

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, value)
        needs_nsx = value == CACHE_TARGET
        namespace.needs_inventory = needs_nsx
        namespace.needs_sessions = needs_nsx

# Which cached names an option takes. Everything not listed completes files,
# which is the right default for --out-csv and friends.
OPTION_VALUE_KINDS = {
    "--policy": KIND_POLICY,
    "--service": KIND_SERVICE,
    "--from": KIND_GROUP,
    "--to": KIND_GROUP,
    "--applied-to": KIND_GROUP,
    "--manager": KIND_MANAGER,
    "--profile": KIND_PROFILE,
    "--before": KIND_RULE,
    "--after": KIND_RULE,
    "--contains": "",          # free text: complete nothing rather than lie
}

# Which cached names a subcommand's first positional takes.
POSITIONAL_VALUE_KINDS = {
    ("group", "show"): KIND_GROUP,
    ("group", "edit"): KIND_GROUP,
    ("group", "delete"): KIND_GROUP,
    ("rule", "show"): KIND_RULE,
    ("rule", "edit"): KIND_RULE,
    ("rule", "move"): KIND_RULE,
    ("rule", "delete"): KIND_RULE,
    ("service", "show"): KIND_SERVICE,
    ("login", ""): KIND_MANAGER,
}


def register_shell(sub, parents):
    p = add_command(
        sub, parents, "menu", "Open the interactive menu.",
        description="The guided menu. Running nsxctl with no arguments does "
                    "the same thing.")
    p.set_defaults(func=cmd_menu)

    p = add_command(
        sub, parents, "completion", "Print a shell completion script.",
        description="Generated from the command tree, so it always matches "
                    "the commands this build actually has.",
        epilog="install:\n"
               "  bash   nsxctl completion bash > "
               "/etc/bash_completion.d/nsxctl\n"
               "  zsh    nsxctl completion zsh  > "
               "\"${fpath[1]}/_nsxctl\"\n"
               "  fish   nsxctl completion fish > "
               "~/.config/fish/completions/nsxctl.fish")
    p.add_argument("target", nargs="?", choices=SHELLS + (CACHE_TARGET,),
                   action=_CompletionTarget, metavar="TARGET",
                   help="{} to print that shell's script, or '{}' to refresh "
                        "the name cache.".format(" | ".join(SHELLS),
                                                 CACHE_TARGET))
    p.add_argument("--status", action="store_true",
                   help="With '{}': report what is cached without refreshing "
                        "it.".format(CACHE_TARGET))
    p.set_defaults(func=cmd_completion, needs_inventory=False,
                   needs_sessions=False)

    p = add_command(
        sub, parents, "__complete", argparse.SUPPRESS,
        description="Internal: print cached names for shell completion. "
                    "Reads a file and never touches NSX.")
    p.add_argument("kind", choices=CACHE_KINDS)
    p.add_argument("prefix", nargs="?", default="")
    p.set_defaults(func=cmd_internal_complete, needs_inventory=False,
                   needs_sessions=False)

    p = add_command(sub, parents, "version", "Print the version and exit.")
    p.set_defaults(func=cmd_version, needs_inventory=False,
                   needs_sessions=False)


def cmd_menu(args, ctx):
    pass
    return interactive(ctx)


def cmd_version(args, ctx):
    say("{} v{} ({})".format(TOOL_NAME, VERSION, VERSION_DATE))
    return 0


# === PARSER INTROSPECTION ===
def _completion_options(parser):
    out = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        out.extend(s for s in action.option_strings if s.startswith("--"))
    return sorted(set(out))


def _completion_subparsers(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def command_tree(parser):
    """{command: {"options": [...], "subcommands": {name: [options]}}}"""
    tree = {}
    for name, cmd_parser in _completion_subparsers(parser).items():
        entry = {"options": _completion_options(cmd_parser), "subcommands": {}}
        for sub_name, sub_parser in _completion_subparsers(cmd_parser).items():
            entry["subcommands"][sub_name] = _completion_options(sub_parser)
        tree[name] = entry
    return tree


def _tree_and_globals():
    pass
    parser = build_parser()
    return command_tree(parser), _completion_options(parser)


# === EMITTERS ===
def _completion_bash(tree, global_opts):
    commands = " ".join(sorted(tree))
    lines = [
        "# {} completion for bash -- generated by `{} completion bash`".format(
            PROG, PROG),
        "_{}() {{".format(PROG),
        '    local cur cmd sub i',
        '    cur="${COMP_WORDS[COMP_CWORD]}"',
        '    cmd=""; sub=""',
        '    for ((i=1; i<COMP_CWORD; i++)); do',
        '        case "${COMP_WORDS[i]}" in',
        '            -*) continue ;;',
        '            *)  if [ -z "$cmd" ]; then cmd="${COMP_WORDS[i]}";',
        '                elif [ -z "$sub" ]; then sub="${COMP_WORDS[i]}"; fi ;;',
        '        esac',
        '    done',
        '    local commands="{}"'.format(commands),
        '    local globals="{}"'.format(" ".join(global_opts)),
        '    if [ -z "$cmd" ]; then',
        '        if [[ "$cur" == -* ]]; then',
        '            COMPREPLY=( $(compgen -W "$globals" -- "$cur") )',
        '        else',
        '            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )',
        '        fi',
        '        return',
        '    fi',
        '    local subs="" opts="$globals"',
        '    case "$cmd" in',
    ]
    for name in sorted(tree):
        entry = tree[name]
        subs = " ".join(sorted(entry["subcommands"]))
        opts = " ".join(sorted(set(entry["options"]) | set(global_opts)))
        lines.append('        {}) subs="{}"; opts="{}" ;;'.format(
            name, subs, opts))
    lines.extend([
        '    esac',
        '    local prev="${COMP_WORDS[COMP_CWORD-1]}" kind=""',
        '    case "$prev" in',
    ])
    for option, kind in sorted(OPTION_VALUE_KINDS.items()):
        lines.append('        {}) kind="{}" ;;'.format(option, kind))
    lines.extend([
        '    esac',
        '    if [ -n "$kind" ]; then',
        # Reads a cache file. Never a network call -- see namecache.py.
        '        COMPREPLY=( $(compgen -W "$({} __complete "$kind" '
        '2>/dev/null)" -- "$cur") )'.format(PROG),
        '        return',
        '    fi',
        '    if [[ "$prev" == -* ]] && [ -z "$kind" ]; then',
        '        case "$prev" in',
        '            --out-csv|--out-json|--out-html|--inventory|--taxonomy'
        '|--ca-bundle|--baseline-file)',
        '                COMPREPLY=( $(compgen -f -- "$cur") ); return ;;',
        '        esac',
        '    fi',
        '    if [[ "$cur" == -* ]]; then',
        '        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )',
        '        return',
        '    fi',
        '    if [ -n "$subs" ] && [ -z "$sub" ]; then',
        '        COMPREPLY=( $(compgen -W "$subs" -- "$cur") )',
        '        return',
        '    fi',
        '    local poskind=""',
        '    case "$cmd $sub" in',
    ])
    for (command, subcommand), kind in sorted(POSITIONAL_VALUE_KINDS.items()):
        lines.append('        "{} {}") poskind="{}" ;;'.format(
            command, subcommand, kind))
    lines.extend([
        '    esac',
        '    if [ -n "$poskind" ]; then',
        '        COMPREPLY=( $(compgen -W "$({} __complete "$poskind" '
        '2>/dev/null)" -- "$cur") )'.format(PROG),
        '    else',
        '        COMPREPLY=( $(compgen -f -- "$cur") )',
        '    fi',
        "}",
        "complete -F _{} {}".format(PROG, PROG),
    ])
    return "\n".join(lines) + "\n"


def _completion_zsh(tree, global_opts):
    lines = [
        "#compdef {}".format(PROG),
        "# generated by `{} completion zsh`".format(PROG),
        "_{}() {{".format(PROG),
        "    local -a commands",
        "    commands=({})".format(
            " ".join("'{}'".format(c) for c in sorted(tree))),
        "    if (( CURRENT == 2 )); then",
        "        _describe 'command' commands",
        "        return",
        "    fi",
        "    case \"${words[2]}\" in",
    ]
    for name in sorted(tree):
        subs = sorted(tree[name]["subcommands"])
        if subs:
            lines.append("        {})".format(name))
            lines.append("            if (( CURRENT == 3 )); then")
            lines.append("                _values 'action' {}".format(
                " ".join("'{}'".format(s) for s in subs)))
            lines.append("            else")
            lines.append("                _files")
            lines.append("            fi ;;")
        else:
            lines.append("        {}) _files ;;".format(name))
    lines.extend([
        "    esac",
        "    local prev=\"${words[CURRENT-1]}\" kind=\"\"",
        "    case \"$prev\" in",
    ])
    for option, kind in sorted(OPTION_VALUE_KINDS.items()):
        if kind:
            lines.append("        {}) kind={} ;;".format(option, kind))
    lines.extend([
        "    esac",
        "    if [[ -n \"$kind\" ]]; then",
        # A cache read, not a network call.
        "        local -a vals; vals=(${{(f)\"$({} __complete $kind "
        "2>/dev/null)\"}})".format(PROG),
        "        _describe 'name' vals",
        "    fi",
        "}",
        "_{} \"$@\"".format(PROG),
    ])
    return "\n".join(lines) + "\n"


def _completion_fish(tree, global_opts):
    lines = ["# generated by `{} completion fish`".format(PROG)]
    has_cmd = "__fish_seen_subcommand_from"
    lines.append("function __{}_no_command".format(PROG))
    lines.append("    not {} {}".format(has_cmd, " ".join(sorted(tree))))
    lines.append("end")
    for name in sorted(tree):
        lines.append(
            "complete -c {} -n '__{}_no_command' -a '{}'".format(
                PROG, PROG, name))
        for sub in sorted(tree[name]["subcommands"]):
            lines.append(
                "complete -c {} -n '{} {}' -a '{}'".format(
                    PROG, has_cmd, name, sub))
    for opt in global_opts:
        lines.append("complete -c {} -l '{}'".format(PROG, opt.lstrip("-")))
    # Value completion reads the cache; fish runs this per keystroke, so it
    # must stay a file read.
    for option, kind in sorted(OPTION_VALUE_KINDS.items()):
        if not kind:
            continue
        lines.append(
            "complete -c {} -l '{}' -f -a '({} __complete {} 2>/dev/null)'"
            .format(PROG, option.lstrip("-"), PROG, kind))
    return "\n".join(lines) + "\n"


COMPLETION_EMITTERS = {"bash": _completion_bash,
                       "zsh": _completion_zsh,
                       "fish": _completion_fish}


def completion_script(shell):
    tree, global_opts = _tree_and_globals()
    return COMPLETION_EMITTERS[shell](tree, global_opts)


def cmd_completion(args, ctx):
    if args.target == CACHE_TARGET:
        return cmd_completion_cache(args, ctx)
    if not args.target:
        err("Which shell? {}   (or '{}' to refresh the name cache)".format(
            " | ".join(SHELLS), CACHE_TARGET))
        return 2
    # print(), not say(): this is data piped into a file, so it must be
    # emitted even when --json or a quiet mode is in effect.
    print(completion_script(args.target), end="")
    return 0


def _completion_profile(args):
    """Which cache to read, worked out without loading anything expensive.

    This command runs with needs_inventory=False on purpose: if the inventory
    were loaded the normal way, a shell hook on a machine with no config would
    trigger the first-run WIZARD, at a prompt, from a TAB press. So the file is
    read directly, only if it already exists, and every failure resolves to the
    default cache rather than being reported.
    """
    if getattr(args, "profile", None):
        return args.profile
    try:
        path = find_inventory(getattr(args, "inventory", None),
                              config_search_dirs())
        if not path:
            return None
        return resolve_profile(path)[0]
    except Exception:  # noqa: BLE001 - never fail loudly inside a shell hook
        return None


def cmd_internal_complete(args, ctx):
    """Print cached names, one per line. Never touches the network.

    Deliberately tolerant of everything: this runs inside a shell hook where
    an error message would be printed over the user's prompt.
    """
    try:
        profile = _completion_profile(args)
        project = getattr(args, "project", None)
        names = cached_names(args.kind, profile, project)
        if not names and profile:
            # A cache written before the profile existed, or under a different
            # one. Falling back to the default is better than offering nothing.
            names = cached_names(args.kind, None, project)
    except Exception:  # noqa: BLE001 - a completion hook must never fail loudly
        return 0
    prefix = args.prefix or ""
    for name in names:
        if name.startswith(prefix):
            print(name)
    return 0


def cmd_completion_cache(args, ctx):
    section("COMPLETION NAME CACHE")
    profile = getattr(ctx, "profile", None)
    project = getattr(ctx, "project", None)
    path = cache_path(profile, project)
    age = cache_age(profile, project)

    if args.status:
        say("  File   : {}".format(cC(path)))
        say("  Written: {}".format(describe_age(age)))
        rows = [[kind, str(len(cached_names(kind, profile, project)))]
                for kind in CACHE_KINDS]
        table(["Kind", "Names"], rows, indent=4)
        if age is None:
            say("\n  {} run `nsxctl completion cache` to build it.".format(
                cBY("Empty:")))
        return 0

    written, counts = refresh_from_nsx(ctx.sessions, args.domain,
                                       profile=profile, project=project)
    if not written:
        say("  {} the cache could not be written; completion will simply "
            "offer nothing.".format(cBY("Note:")))
        return 0
    table(["Kind", "Names"],
          [[k, str(v)] for k, v in sorted(counts.items())], indent=4)
    hr()
    ok_msg("Cached: {}".format(written))
    say("  {}".format(cD(
        "TAB now completes these names without talking to NSX.")))
    return 0


# ==========================================================================
# legacy.py  --  Translation from the pre-4.0 flag interface to `nsxctl <noun> <verb>`.
# ==========================================================================

# old flag -> (subcommand words, how to consume its value)
#   "flag"     : no value
#   "value"    : one positional value
#   "two"      : two positional values
SIMPLE = {
    "init": (["init"], "flag"),
    "verify": (["status"], "flag"),
    "list_managers": (["managers"], "flag"),
    "dashboard": (["compliance"], "flag"),
    "audit_log": (["audit", "list"], "flag"),
    "vm_tags": (["tag", "list"], "value"),
    "reverse_lookup": (["impact"], "value"),
    "change_ticket": (["tag", "ticket"], "value"),
    "parity": (["parity"], "two"),
}

# Presentation order, so a multi-action run is deterministic and matches the
# order the old cli.py executed them in.
ORDER = ["list_managers", "verify", "groups", "vm_tags", "vms_by_tag",
         "dashboard", "parity", "reverse_lookup", "change_ticket",
         "audit_log", "bulk_tag", "init", "set_credentials"]

REPLACEMENT = {
    "--init": "nsxctl init",
    "--verify": "nsxctl status",
    "--list-managers": "nsxctl managers",
    "--set-credentials": "nsxctl login",
    "--groups": "nsxctl group list",
    "--vm-tags": "nsxctl tag list VM",
    "--vms-by-tag": "nsxctl tag find --scope S --tag T",
    "--bulk-tag": "nsxctl tag apply FILE",
    "--change-ticket": "nsxctl tag ticket FILE",
    "--reverse-lookup": "nsxctl impact VM",
    "--parity": "nsxctl parity STATIC DYNAMIC",
    "--dashboard": "nsxctl compliance",
    "--audit-log": "nsxctl audit list",
}


def _legacy_parser():
    """Recognises only the old action flags and the old action-scoped options.

    Global flags are deliberately absent so `parse_known_args` hands them back
    untouched, to be passed through to the new parser.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--init", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--list-managers", action="store_true")
    p.add_argument("--set-credentials", action="store_true")
    p.add_argument("--dashboard", action="store_true")
    p.add_argument("--audit-log", action="store_true")
    p.add_argument("--groups", action="store_true")
    p.add_argument("--vms-by-tag", action="store_true")
    p.add_argument("--vm-tags", default=None)
    p.add_argument("--reverse-lookup", default=None)
    p.add_argument("--bulk-tag", default=None)
    p.add_argument("--change-ticket", default=None)
    p.add_argument("--parity", nargs=2, default=None)
    # Options that used to be global but now belong to a specific command.
    p.add_argument("--contains", default=None)
    p.add_argument("--members", action="store_true")
    p.add_argument("--scope", default=None)
    p.add_argument("--tag", default=None)
    p.add_argument("--dry-run", action="store_true")
    return p


LEGACY_FLAGS = frozenset(REPLACEMENT) | {
    "--contains", "--members", "--scope", "--tag", "--dry-run"}


def uses_legacy(argv):
    """True when argv contains any pre-4.0 flag."""
    for token in argv:
        head = token.split("=", 1)[0]
        if head in LEGACY_FLAGS:
            return True
    return False


def translate_legacy_argv(argv):
    """(list_of_new_argv, warnings). Raises nothing; unknown args pass through.

    Returns ([], warnings) when a legacy flag was present but named no action
    (for example `--scope` on its own) -- the caller reports that.
    """
    parser = _legacy_parser()
    try:
        known, passthrough = parser.parse_known_args(argv)
    except SystemExit:
        # Malformed legacy input: let the new parser produce the error.
        return None, []

    warnings = []
    commands = []

    def warn_for(flag):
        replacement = REPLACEMENT.get(flag)
        if replacement:
            warnings.append(
                "{} is deprecated and will be removed in 5.0. "
                "use: {}".format(flag, replacement))

    for key in ORDER:
        value = getattr(known, key, None)
        if key == "set_credentials":
            if value:
                warn_for("--set-credentials")
                commands.append(["login"] + list(passthrough))
            continue
        if key == "groups":
            if value:
                warn_for("--groups")
                extra = []
                if known.contains:
                    extra += ["--contains", known.contains]
                if known.members:
                    extra += ["--members"]
                commands.append(["group", "list"] + extra + list(passthrough))
            continue
        if key == "vms_by_tag":
            if value:
                warn_for("--vms-by-tag")
                extra = []
                if known.scope:
                    extra += ["--scope", known.scope]
                if known.tag:
                    extra += ["--tag", known.tag]
                commands.append(["tag", "find"] + extra + list(passthrough))
            continue
        if key == "bulk_tag":
            if value:
                warn_for("--bulk-tag")
                extra = ["--dry-run"] if known.dry_run else []
                commands.append(["tag", "apply", value] + extra
                                + list(passthrough))
            continue
        if key in SIMPLE:
            words, kind = SIMPLE[key]
            flag = "--" + key.replace("_", "-")
            if kind == "flag" and value:
                warn_for(flag)
                commands.append(list(words) + list(passthrough))
            elif kind == "value" and value:
                warn_for(flag)
                commands.append(list(words) + [value] + list(passthrough))
            elif kind == "two" and value:
                warn_for(flag)
                commands.append(list(words) + list(value) + list(passthrough))

    return commands, warnings


# ==========================================================================
# cli.py  --  Entry point: assemble configuration, connect, dispatch a subcommand.
# ==========================================================================

TAXONOMY_NAMES = ("taxonomy.json", "taxonomy.yaml", "taxonomy.yml")


def banner(inv_path, mgr_count, audit_path, taxonomy, write_enabled,
           profile=None, project=None):
    say(cBC("=" * W))
    say("  {} v{}    ({})".format(cB(TOOL_NAME), VERSION, VERSION_DATE))
    say("  {}".format(cC(TOOL_TAGLINE)))
    say(cD("-" * W))
    say("  Inventory  : {}  ({} manager(s))".format(cC(inv_path), mgr_count))
    say("  Profile    : {}".format(cC(profile or IMPLICIT_PROFILE)))
    if project:
        say("  Project    : {}  {}".format(
            cC(project), cD("(default infra is not visible from here)")))
    say("  Taxonomy   : {}".format(taxonomy.source))
    say("  Audit log  : {}".format(audit_path))
    say("  Exports    : {}".format(DEFAULT_EXPORT_DIR))
    mode = (cBG("READ-WRITE") if write_enabled
            else cBY("READ-ONLY") + " (--enable-writes)")
    say("  Mode       : {}".format(mode))
    say("  Transport  : {}".format("requests" if have_requests() else "stdlib urllib"))
    say("  Platform   : {} / Python {}".format(
        platform.node(), platform.python_version()))
    say(cBC("=" * W))


def connect_all(managers, only=None, ca_bundle=None, quiet=True,
                project=None):
    """Authenticate against each manager. Quiet by default: a one-shot command
    should print its results, not a login transcript."""
    if not quiet:
        say("\n  {} ...".format(cB("Authenticating")))
    sessions, failed = [], []
    transport = make_transport()
    for m in managers:
        name = m.get("name", "?")
        if only and name not in only:
            continue
        if ca_bundle or project:
            m = dict(m)
            if ca_bundle:
                m["ca_bundle"] = ca_bundle
                m["verify_ssl"] = True
            if project:
                m["project"] = project
        try:
            user, pwd, src = credentials_for(m, allow_prompt=True)
            sessions.append(Nsx(m, user, pwd, transport=transport))
            if not quiet:
                say("    {:26s}  credentials {}".format(cC(name), cG(src)))
        except UserAbort:
            raise
        except NsxError as e:
            failed.append(name)
            err(str(e))
    if failed:
        say("    ({} unavailable: {})".format(
            cBR(str(len(failed))), ", ".join(failed)))
    return sessions


def _write_sinks(args, exporter, command, profile, project, changed):
    """Machine-readable outputs. Each failure is reported, never fatal.

    A hygiene report that found real problems must not be thrown away because
    a metrics directory was read-only.
    """
    findings = exporter.findings
    if args.out_junit:
        try:
            say("  Exported: {}".format(write_text(
                args.out_junit, render_junit(exporter.findings_by_suite()))))
        except OSError as e:
            err("could not write JUnit XML: {}".format(e))
    if args.out_sarif:
        try:
            say("  Exported: {}".format(write_text(
                args.out_sarif, render_sarif(findings))))
        except OSError as e:
            err("could not write SARIF: {}".format(e))
    if args.out_metrics:
        try:
            say("  Exported: {}".format(write_text(
                args.out_metrics, render_metrics(command, findings))))
        except OSError as e:
            err("could not write metrics: {}".format(e))
    if args.notify:
        payload = webhook_payload(command, findings, changed, profile, project)
        try:
            status = post_webhook(args.notify, payload)
            say("  Notified: HTTP {}".format(status))
        except NsxError as e:
            err(str(e))


def _emit_json(exporter, errors, rc):
    payload = {"tool": TOOL_NAME, "version": VERSION,
               "timestamp": utc_now_iso(), "exit_code": rc,
               "results": exporter.json_payload()}
    if errors:
        payload["errors"] = errors
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    print()


def _parse(parser, argv_list):
    out = []
    for argv in argv_list:
        out.append(apply_global_defaults(parser.parse_args(argv)))
    return out


def _apply_modes(args):
    if args.no_color:
        set_color(False)
    if args.json:
        set_json_mode(True)
    if args.non_interactive:
        set_interactive(False)
    if args.yes:
        set_assume_yes(True)
    if args.debug:
        set_debug(True)
    set_store_policy(args.store)


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)

    # --- pre-4.0 flags: translate, warn, continue -------------------------
    legacy_warnings = []
    argv_list = [raw]
    if uses_legacy(raw):
        translated, legacy_warnings = translate_legacy_argv(raw)
        if translated:
            argv_list = translated

    parser = build_parser()
    try:
        parsed = _parse(parser, argv_list)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    first = parsed[0]
    _apply_modes(first)
    for warning in legacy_warnings:
        print("warning: {}".format(warning), file=sys.stderr)

    os.makedirs(DATA_DIR, exist_ok=True)

    menu_mode = getattr(first, "command", None) is None
    if menu_mode and not is_interactive():
        parser.print_help()
        return 2

    needs_inventory = menu_mode or any(
        getattr(ns, "needs_inventory", True) for ns in parsed)
    needs_sessions = menu_mode or any(
        getattr(ns, "needs_sessions", True) for ns in parsed)

    exporter = Exporter()
    audit = AuditLog()
    errors = []

    # --- configuration ----------------------------------------------------
    managers, inv_path, taxonomy = [], None, None
    profile = None
    if needs_inventory:
        inv_path = find_inventory(first.inventory, config_search_dirs())
        if not inv_path:
            inv_path = maybe_bootstrap(first.inventory, config_search_dirs())
            if not inv_path:
                return 2
        try:
            profile, _why = resolve_profile(inv_path, first.profile)
            managers = load_inventory(inv_path, profile=profile)
        except ConfigError as e:
            err(str(e))
            return 2

    try:
        taxonomy = load_taxonomy(
            first.taxonomy,
            search_dirs=([os.path.dirname(os.path.abspath(inv_path))]
                         if inv_path else []) + config_search_dirs(),
            names=TAXONOMY_NAMES)
    except ConfigError as e:
        err(str(e))
        return 2

    only = None
    if needs_inventory and first.manager:
        only = {first.manager}
        if not any(m.get("name") == first.manager for m in managers):
            err("'{}' is not in {}. Known: {}".format(
                first.manager, inv_path,
                ", ".join(m.get("name", "?") for m in managers)))
            return 2
    elif needs_inventory and first.all_lm:
        only = {m.get("name") for m in managers if m.get("role") == ROLE_LM}
        if not only:
            err('No managers with "role": "lm" in {}.'.format(inv_path))
            return 2

    # --- connect ----------------------------------------------------------
    sessions = []
    if needs_sessions:
        if menu_mode:
            banner(inv_path, len(managers), audit.path, taxonomy,
                   first.enable_writes, profile=profile,
                   project=first.project)
        try:
            sessions = connect_all(managers, only=only,
                                   ca_bundle=first.ca_bundle,
                                   quiet=not menu_mode,
                                   project=first.project)
        except UserAbort:
            err("Credentials required.")
            return 2
        if not sessions:
            err("No manager could be authenticated.")
            return 2

    ctx = AppContext(sessions, audit, exporter, taxonomy,
                     write_enabled=first.enable_writes, domain=first.domain,
                     managers=managers, profile=profile,
                     project=first.project, inventory_path=inv_path)

    # --- dispatch ---------------------------------------------------------
    rc = 0
    try:
        if menu_mode:
            try:
                return interactive(ctx)
            except (KeyboardInterrupt, EOFError, UserAbort):
                say("\n  Bye.")
                return 0

        # --only-on-change collects the report rather than printing it, so a
        # run that turns out to have found nothing new can be discarded before
        # it reaches stdout. Cron then sends mail only when something moved.
        if first.only_on_change and not first.json:
            start_buffering()

        for ns in parsed:
            handler = getattr(ns, "func", None)
            if handler is None:
                if first.only_on_change and not first.json:
                    flush_buffered()
                parser.print_help()
                return 2
            result = handler(ns, ctx)
            if result:
                rc = result

        command = getattr(first, "command", None) or "nsxctl"
        changed, previous = True, {}
        # State belongs to --only-on-change, and is written only when it is
        # asked for. A plain interactive run that quietly primed it would make
        # the FIRST scheduled run silent -- with forty findings sitting there
        # unreported, which is the exact failure this feature exists to avoid.
        if first.only_on_change:
            state_root = os.path.join(DATA_DIR, "state")
            changed, previous = changed_since_last(
                command, exporter.findings, profile, first.project,
                root=state_root)
            save_state(command, fingerprint(exporter.findings),
                       summarise_findings(exporter.findings),
                       profile, first.project, root=state_root)
        if first.only_on_change and not first.json:
            if changed:
                flush_buffered()
            else:
                drop_buffered()
                if first.debug:
                    err("unchanged since {}; output suppressed".format(
                        previous.get("last_run", "the last run")))
                return rc

        if first.out_csv and exporter.has_staged():
            for path in exporter.to_csv(first.out_csv):
                say("  Exported: {}".format(path))
        if first.out_json and exporter.has_staged():
            for path in exporter.to_json(first.out_json):
                say("  Exported: {}".format(path))
        if any((first.out_junit, first.out_sarif, first.out_metrics,
                first.notify)):
            _write_sinks(first, exporter, command, profile, first.project,
                         changed)
        if first.json:
            _emit_json(exporter, errors, rc)
        return rc

    except UserAbort:
        say("\n  Cancelled.")
        return 130
    except NsxError as e:
        errors.append(str(e))
        err(str(e))
        if first.json:
            _emit_json(exporter, errors, 1)
        return 1
    except KeyboardInterrupt:
        say("\n  Cancelled.")
        return 130
    finally:
        ctx.close()


def entry():
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
