"""Inventory loading and validation.

An inventory is a JSON file describing the NSX managers to talk to:

    {"managers": [
      {"name": "gm", "role": "gm", "host": "gm.example.com", "port": 443,
       "verify_ssl": false, "auth": "session",
       "username_env": "NSX_GM_USER", "password_env": "NSX_GM_PASS"}
    ]}

An engineer with more than one estate can name them instead, and select one
with --profile:

    {"default_profile": "prod",
     "profiles": {
       "prod": {"managers": [...]},
       "dr":   {"managers": [...]}}}

Both shapes are supported for good: the flat one is what `nsxctl init` writes
and what every existing config already is, so it must never stop working.

There is deliberately no hard failure when it is missing -- the caller runs the
first-run wizard instead. An inventory that exists but is malformed IS a hard
failure, because silently ignoring it would hide a typo in a real config.
"""

import json
import os

from .api import ROLE_GM, ROLE_LM
from .errors import ConfigError
from .paths import DEFAULT_INVENTORY_NAME

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
