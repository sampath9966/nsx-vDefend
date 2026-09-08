"""Analysis commands: impact, parity, compliance, audit."""

from ..actions.audit_view import act_audit_log
from ..actions.dashboard import act_dashboard
from ..actions.parity import act_parity
from ..actions.reverse import act_reverse_lookup
from ..output import err
from . import add_command


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
