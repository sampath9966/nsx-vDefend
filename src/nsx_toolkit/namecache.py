"""Cached object names, so shell completion never blocks on NSX.

**The rule that shapes this file: pressing TAB must never make a network
call.** A completion that reaches out to eight managers turns a keystroke into
a two-second stall, and on an unreachable manager into a hang with no way to
tell what happened. Every shell that has tried it has regretted it.

So completion reads a plain file written by ordinary commands. `nsxctl group
list`, `policy list`, `service list` and `rule list` refresh it as a side
effect of work you were doing anyway, and `nsxctl completion cache` refreshes
it on demand. A stale cache completes stale names -- which is the right
failure: you get a name that no longer exists and NSX says so, instead of a
shell that freezes.

The cache is per profile and project, because those change which objects exist
at all: completing production group names into a DR command is worse than
completing nothing.
"""

import json
import os
import time

from .api import F_DISPLAY_NAME, F_ID
from .authoring import service_inventory
from .paths import DATA_DIR
from .policy import (
    group_inventory,
    ordered_sessions,
    policies_for,
    sweep_rules,
)

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
