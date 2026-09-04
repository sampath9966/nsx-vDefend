"""Authoring groups and rules: plan, preflight, confirm, write, audit.

The discipline is the one `nsxctl tag apply` already established -- dry run
first, explicit confirmation, every write audited with both sides of it -- and
the pieces that do the work are the ones earlier phases built:

  * the plan is rendered by the Phase 3 diff engine, so the preview of a
    change looks exactly like the drift report of that same change;
  * the proposed rule is run through the 2B hygiene checks before anything is
    written, so an any-any ALLOW is caught at authoring time rather than in
    tomorrow's report;
  * the write itself carries the `_revision` NSX handed back, so a concurrent
    edit is refused by the server rather than silently overwritten.
"""

from ..api import (
    ANY,
    F_ACTION_FIELD,
    F_DEST_GROUPS,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_ID,
    F_PATH,
    F_SCOPE,
    F_SEQUENCE_NUMBER,
    F_SERVICES,
    F_SOURCE_GROUPS,
    KEY_TAG,
    ROLE_LM,
    RT,
    RT_CONDITION,
    TAG_SCOPE_SEPARATOR,
    origin_of_path,
    policy_id_from_rule_path,
    policy_path_prefix,
)
from ..audit import OBJ_GROUP, OBJ_RULE
from ..authoring import (
    CRITERIA_HELP,
    KIND_GROUP,
    KIND_RULE,
    OP_CREATE,
    OP_DELETE,
    OP_MODIFY,
    STATE_ABSENT,
    PlannedWrite,
    apply_write,
    build_group_body,
    build_rule_body,
    describe_criteria,
    load_change_file,
    object_url,
    parse_criteria,
    read_object,
    reference_index,
    resolve_references,
    sequence_for_move,
    service_inventory,
    validate_action,
    validate_direction,
)
from ..diff import diff_objects, fmt_diff_value
from ..errors import ConfigError, NsxError
from ..output import (
    ask,
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cG,
    confirm,
    cR,
    err,
    hr,
    ok_msg,
    say,
    section,
    warn,
)
from ..policy import (
    RuleRecord,
    group_inventory,
    ordered_sessions,
    policies_for,
    sweep_rules,
)
from .hygiene import HygieneContext, evaluate

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
