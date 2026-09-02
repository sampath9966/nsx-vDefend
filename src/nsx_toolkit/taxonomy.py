"""Tag taxonomy -- loaded from configuration, not baked into source.

Every organization tags differently, so the scheme lives in a file next to
inventory.json rather than in this code. JSON is the primary format because it
needs no third-party parser; YAML is also accepted when PyYAML happens to be
installed.

Schema:
    {
      "format": "^[a-z0-9][a-z0-9\\\\-]*$",
      "allow_unknown_scopes": false,
      "scopes": {
        "env":  {"required": true,  "values": ["prod", "dev"]},
        "owner": {"required": false}
      }
    }
"""

import json
import os
import re

from .errors import ConfigError

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
