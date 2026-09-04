"""DFW rules: `nsxctl rule hygiene|baseline|create|edit|move|delete`.

Reporting and authoring share a command tree, and share machinery: a rule
about to be created is run through the same hygiene checks that would report
it tomorrow, before it is written.
"""

from ..actions.author import act_rule_write
from ..actions.hygiene import (
    HYGIENE_HEADERS,
    SEVERITIES,
    act_hygiene,
    at_or_above,
    fetch_hit_counts,
)
from ..actions.inspect import act_rule_list, act_rule_show
from ..authoring import RULE_ACTIONS, RULE_DIRECTIONS
from ..baseline import (
    BASELINE_HEADERS,
    build_hit_baseline,
    compare_hit_baselines,
    hit_baseline_rows,
    hit_baseline_summary,
    load_hit_baseline,
    save_hit_baseline,
)
from ..errors import ConfigError, NsxError
from ..output import (
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    err,
    hr,
    is_json_mode,
    ok_msg,
    say,
    section,
    table,
)
from ..policy import sweep_rules
from ..report import write_report
from . import add_action, add_command


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
