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
import html
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
    if not _json_mode:
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


def load_inventory(path):
    """Read and validate an inventory file. Raises ConfigError on any problem."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise ConfigError("Invalid JSON in {}: {}".format(path, e)) from e
    except OSError as e:
        raise ConfigError("Cannot read {}: {}".format(path, e)) from e
    if not isinstance(data, dict):
        raise ConfigError("{}: top level must be an object".format(path))
    managers = data.get("managers")
    if not managers:
        raise ConfigError("{} has no 'managers'.".format(path))
    if not isinstance(managers, list):
        raise ConfigError("{}: 'managers' must be a list".format(path))
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
        raise ConfigError("{}:\n      - {}".format(path, "\n      - ".join(problems)))
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
                raise NsxError("[{}] {} {} -> HTTP {}: {}".format(
                    self.name, method, url, r.status, r.text()))
            return r.json()
        raise last_exc or NsxError("[{}] {} {} -> exhausted retries".format(
            self.name, method, url))

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, body=None, params=None):
        return self._req("POST", path, body=body, params=params)

    def patch(self, path, body=None, params=None):
        return self._req("PATCH", path, body=body, params=params)

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

    def log(self, action, manager, vm_name, vm_ext_id, tags_before, tags_after,
            status="success", detail=""):
        entry = {
            "timestamp": utc_now_iso(),
            "user": current_user(),
            "host": platform.node(),
            "manager": manager,
            "action": action,
            "vm_display_name": vm_name,
            "vm_external_id": vm_ext_id,
            "tags_before": [{"scope": s, "tag": t} for s, t in tags_before],
            "tags_after": [{"scope": s, "tag": t} for s, t in tags_after],
            "status": status,
            "detail": detail,
        }
        self._rotate_if_needed()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            err("audit write failed: {}".format(e))
        return entry

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

    def stage(self, label, headers, rows):
        """Add a result set. Empty sets are still recorded so --json reports
        'this action ran and found nothing' rather than staying silent."""
        self._sets.append(ResultSet(label, list(headers), list(rows)))

    @property
    def sets(self):
        return list(self._sets)

    def has_staged(self):
        return any(rs.rows for rs in self._sets)

    def clear(self):
        self._sets = []

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


def _fmt(value):
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
                         _fmt(field.before), _fmt(field.after),
                         change.changed_by, str(change.changed_at)])
    return rows


def at_impact(changes, level):
    """Changes at or above an impact level, for --fail-on-drift."""
    if level == "any":
        return list(changes)
    if level == "security":
        return [c for c in changes if c.impact == "security"]
    return []


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


def act_groups(sessions, domain, needle, show_members, exporter):
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
# actions/audit_view.py  --  Audit log viewing and single-entry undo.
# ==========================================================================

AUDIT_HEADERS = ["timestamp", "user", "manager", "action", "vm_name",
                  "added", "removed", "status"]


def _pairs(entries):
    return [(t.get("scope", ""), t.get("tag", "")) for t in (entries or [])]


def act_audit_log(audit, sessions, write_enabled, exporter=None, limit=20):
    entries = audit.last_n(limit)
    if not entries:
        say("  Audit log empty.")
        if exporter is not None:
            exporter.stage("audit_log", AUDIT_HEADERS, [])
        return
    say("\n  Last {} entries:".format(cC(str(len(entries)))))
    hr()
    rows = []
    for i, e in enumerate(entries, 1):
        before = _pairs(e.get("tags_before"))
        after = _pairs(e.get("tags_after"))
        added = [p for p in after if p not in before]
        removed = [p for p in before if p not in after]
        say("  {:5s} {}  {:30s}  [{}]".format(
            cD(str(i) + "."), cD(str(e.get("timestamp", "?"))[:19]),
            e.get("vm_display_name", "?"), cC(e.get("manager", "?"))))
        if added:
            say("        {}".format(cG("+ " + fmt_tags_plain(added))))
        if removed:
            say("        {}".format(cR("- " + fmt_tags_plain(removed))))
        rows.append([e.get("timestamp", ""), e.get("user", ""),
                     e.get("manager", ""), e.get("action", ""),
                     e.get("vm_display_name", ""), fmt_tags_plain(added),
                     fmt_tags_plain(removed), e.get("status", "")])
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
    restore_to = _pairs(target.get("tags_before"))
    vm_name = target.get("vm_display_name", "?")
    mgr_name = target.get("manager", "?")
    ext = target.get("vm_external_id", "?")

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
    try:
        fresh = nsx.refresh_vm(vm) or vm
        nsx.update_vm_tags(fresh, restore_to)
        audit.log("undo", nsx.name, vm_name, fresh.get(F_EXTERNAL_ID),
                  current, restore_to, detail="undo of {}".format(
                      target.get("timestamp", "?")))
        ok_msg("Undo applied.")
    except NsxError as e:
        err(str(e))


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
def _listed(rule, field):
    return [v for v in (rule.get(field) or []) if v]


def _is_any(values):
    """NSX writes the wildcard as ["ANY"]; an empty list means the same."""
    return not values or list(values) == [ANY]


def match_key(rule):
    """What makes two rules equivalent, without expanding services.

    Service definitions are compared as opaque paths on purpose: expanding
    them into port ranges is where a shadow analysis starts producing false
    "unreachable" claims.
    """
    return (
        tuple(sorted(_listed(rule, "source_groups"))),
        tuple(sorted(_listed(rule, "destination_groups"))),
        tuple(sorted(_listed(rule, F_SERVICES))),
        tuple(sorted(_listed(rule, F_SCOPE))),
        rule.get(F_ACTION_FIELD, ""),
        rule.get(F_DIRECTION, ""),
    )


def matches_everything(rule):
    """True when this rule matches all traffic in its policy."""
    return (_is_any(_listed(rule, "source_groups"))
            and _is_any(_listed(rule, "destination_groups"))
            and _is_any(_listed(rule, F_SERVICES))
            and _is_any(_listed(rule, F_SCOPE))
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
    if not (_is_any(_listed(rule, "source_groups"))
            and _is_any(_listed(rule, "destination_groups"))):
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
    if _is_any(_listed(rule, F_SCOPE)):
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
                 write_enabled=False, domain=DEFAULT_DOMAIN, managers=None):
        self.sessions = sessions
        self.audit = audit
        self.exporter = exporter
        self.taxonomy = taxonomy
        self.write_enabled = write_enabled
        self.domain = domain
        # Inventory entries, for commands that act on configuration rather
        # than on a live connection (login).
        self.managers = managers or []

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
           dft=cD("(what changed, and who changed it)"))


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

            elif c == "10":
                tgt = select_managers(ctx.sessions, (ROLE_GM, ROLE_LM),
                                      allow_all=True, label="verification")
                if tgt:
                    act_verify(tgt, ctx.domain)

            elif c == "11":
                act_audit_log(ctx.audit, ctx.sessions, ctx.write_enabled,
                              ctx.exporter)
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
}

EPILOG = """
getting started:
  nsxctl init                       guided setup: managers, credentials, a check
  nsxctl status                     can I reach and authenticate everywhere?
  nsxctl                            interactive menu

everyday:
  nsxctl compliance                 tagging posture across every Local Manager
  nsxctl tag find --scope env --tag prod
  nsxctl impact web-prod-01         what breaks if I retag this VM
  nsxctl group list --contains web
  nsxctl tag apply changes.csv      dry run; add --enable-writes --yes to commit

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
                     register_rule, register_analysis, register_snapshot,
                     register_shell):
        register(sub, parents)
    return parser


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

    p = add_command(sub, parents, "managers", "List the configured managers.")
    p.set_defaults(func=cmd_managers)

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
# commands/group.py  --  Group inspection: `nsxctl group list|show`.
# ==========================================================================

def register_group(sub, parents):
    p = add_command(
        sub, parents, "group", "Search and inspect security groups.")
    gsub = p.add_subparsers(dest="group_action", metavar="<action>")

    ls = gsub.add_parser(
        "list", parents=parents, help="List groups and their criteria.",
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

    sh = gsub.add_parser(
        "show", parents=parents, help="Show one group in full.",
        description="Show a single group's criteria and members.",
        epilog="example:\n  nsxctl group show web-prod")
    sh.add_argument("name", help="Group name or id.")
    sh.set_defaults(func=cmd_group_show)

    p.set_defaults(func=_group_needs_action)


def _group_needs_action(args, ctx):
    pass
    err("Specify what to do: nsxctl group list  |  nsxctl group show NAME")
    return 2


def _targets(ctx):
    """Groups exist on GM and LMs alike, so sweep whatever is connected."""
    return [s for s in ctx.sessions if s.role in (ROLE_GM, ROLE_LM)]


def cmd_group_list(args, ctx):
    act_groups(_targets(ctx), args.domain, args.contains,
               show_members=args.members, exporter=ctx.exporter)
    return 0


def cmd_group_show(args, ctx):
    act_groups(_targets(ctx), args.domain, args.name,
               show_members=True, exporter=ctx.exporter)
    return 0


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
# commands/rule.py  --  DFW rule commands: `nsxctl rule hygiene|baseline`.
# ==========================================================================

def register_rule(sub, parents):
    p = add_command(
        sub, parents, "rule", "Inspect distributed firewall rules.")
    rsub = p.add_subparsers(dest="rule_action", metavar="<action>")

    hy = rsub.add_parser(
        "hygiene", parents=parents, help="Report rule hygiene problems.",
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

    bl = rsub.add_parser(
        "baseline", parents=parents,
        help="Save or compare rule hit counts.",
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

    p.set_defaults(func=_rule_needs_action)


def _rule_needs_action(args, ctx):
    err("Specify what to do: nsxctl rule hygiene  |  nsxctl rule baseline")
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

    p = add_command(sub, parents, "audit", "Review and undo audited writes.")
    asub = p.add_subparsers(dest="audit_action", metavar="<action>")
    ls = asub.add_parser("list", parents=parents,
                         help="Show recent audited writes.")
    ls.add_argument("-n", "--limit", type=int, default=20,
                    help="How many entries (default 20).")
    ls.set_defaults(func=cmd_audit_list)
    un = asub.add_parser("undo", parents=parents,
                         help="Restore a VM's tags from an audit entry.")
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
                  exporter=ctx.exporter, limit=args.limit)
    return 0


def cmd_audit_undo(args, ctx):
    if not ctx.write_enabled:
        err("Undo changes tags. Re-run with --enable-writes.")
        return 2
    act_audit_log(ctx.audit, ctx.sessions, write_enabled=True,
                  exporter=ctx.exporter, limit=args.limit)
    return 0


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
    p.add_argument("shell", choices=SHELLS)
    p.set_defaults(func=cmd_completion, needs_inventory=False,
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
        '    if [[ "$cur" == -* ]]; then',
        '        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )',
        '    elif [ -n "$subs" ] && [ -z "$sub" ]; then',
        '        COMPREPLY=( $(compgen -W "$subs" -- "$cur") )',
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
    return "\n".join(lines) + "\n"


COMPLETION_EMITTERS = {"bash": _completion_bash,
                       "zsh": _completion_zsh,
                       "fish": _completion_fish}


def completion_script(shell):
    tree, global_opts = _tree_and_globals()
    return COMPLETION_EMITTERS[shell](tree, global_opts)


def cmd_completion(args, ctx):
    # print(), not say(): this is data piped into a file, so it must be
    # emitted even when --json or a quiet mode is in effect.
    print(completion_script(args.shell), end="")
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


def banner(inv_path, mgr_count, audit_path, taxonomy, write_enabled):
    say(cBC("=" * W))
    say("  {} v{}    ({})".format(cB(TOOL_NAME), VERSION, VERSION_DATE))
    say("  {}".format(cC(TOOL_TAGLINE)))
    say(cD("-" * W))
    say("  Inventory  : {}  ({} manager(s))".format(cC(inv_path), mgr_count))
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


def connect_all(managers, only=None, ca_bundle=None, quiet=True):
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
        if ca_bundle:
            m = dict(m)
            m["ca_bundle"] = ca_bundle
            m["verify_ssl"] = True
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
    if needs_inventory:
        inv_path = find_inventory(first.inventory, config_search_dirs())
        if not inv_path:
            inv_path = maybe_bootstrap(first.inventory, config_search_dirs())
            if not inv_path:
                return 2
        try:
            managers = load_inventory(inv_path)
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
                   first.enable_writes)
        try:
            sessions = connect_all(managers, only=only,
                                   ca_bundle=first.ca_bundle,
                                   quiet=not menu_mode)
        except UserAbort:
            err("Credentials required.")
            return 2
        if not sessions:
            err("No manager could be authenticated.")
            return 2

    ctx = AppContext(sessions, audit, exporter, taxonomy,
                     write_enabled=first.enable_writes, domain=first.domain,
                     managers=managers)

    # --- dispatch ---------------------------------------------------------
    rc = 0
    try:
        if menu_mode:
            try:
                return interactive(ctx)
            except (KeyboardInterrupt, EOFError, UserAbort):
                say("\n  Bye.")
                return 0

        for ns in parsed:
            handler = getattr(ns, "func", None)
            if handler is None:
                parser.print_help()
                return 2
            result = handler(ns, ctx)
            if result:
                rc = result

        if first.out_csv and exporter.has_staged():
            for path in exporter.to_csv(first.out_csv):
                say("  Exported: {}".format(path))
        if first.out_json and exporter.has_staged():
            for path in exporter.to_json(first.out_json):
                say("  Exported: {}".format(path))
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
