"""DFW rule commands: `nsxctl rule hygiene|baseline`."""

from ..actions.hygiene import (
    HYGIENE_HEADERS,
    SEVERITIES,
    act_hygiene,
    at_or_above,
    fetch_hit_counts,
)
from ..baseline import (
    BASELINE_HEADERS,
    build_hit_baseline,
    compare_hit_baselines,
    hit_baseline_rows,
    hit_baseline_summary,
    load_hit_baseline,
    save_hit_baseline,
)
from ..errors import NsxError
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
from . import add_command


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
