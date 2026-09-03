"""Group inspection: `nsxctl group list|show`."""

from ..actions.groups import act_groups
from ..api import ROLE_GM, ROLE_LM
from . import add_command


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
    from ..output import err
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
