"""Creating and changing groups, policies and rules.

Everything before this release was a read, plus one write path for VM tags.
This is the write path for configuration, and it is built out of the machinery
the read paths already produced rather than beside it:

  * **The dry run is the Phase 3 diff engine.** The proposed body is diffed
    against the live one with the same field walker `nsxctl drift` uses, so it
    inherits set-vs-sequence list semantics and security-vs-cosmetic
    classification for free. "This changes `action`" is flagged as
    security-relevant because that engine already knows it is.
  * **The safety mechanism is NSX's own.** Every write sends the `_revision`
    it read back; NSX answers 412 if anything changed in between. That is the
    read-modify-write pattern from Phase 1, except the server enforces it, so
    two operators editing the same rule cannot silently clobber each other.
  * **Preflight is the 2B hygiene checks**, run against the proposed rule
    before it is written. Catching "the rule you are about to create is
    source ANY, destination ANY, ALLOW" at authoring time rather than in
    tomorrow's report is the payoff for sequencing authoring last.

Undo is asymmetric and the docs say so rather than overclaiming: undoing a
create is a delete and undoing a modify is a PUT of the before-body, both
clean; undoing a delete means recreating an object whose references may have
been cleaned up underneath it, and that cannot be guaranteed. Snapshots are
the real backstop there.
"""

import json
import os

from .api import (
    ANY,
    F_ACTION_FIELD,
    F_DEST_GROUPS,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_ID,
    F_PATH,
    F_REVISION,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SERVICES,
    F_SOURCE_GROUPS,
    KEY_TAG,
    RT,
    RT_CONDITION,
    RT_CONJUNCTION,
    RT_IPADDRESS,
    TAG_SCOPE_SEPARATOR,
    p_group,
    p_sec_policy,
    p_sec_rule,
    p_services,
)
from .errors import ConfigError, NsxError, NsxHttpError
from .policy import ordered_sessions, rule_sequence

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
