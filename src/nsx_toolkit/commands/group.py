"""Groups: `nsxctl group list|show|create|edit|delete`.

Reads and writes sit in one command tree because that is where an operator
looks for them. The writes go through the same plan-then-apply path as
`nsxctl tag apply`: dry run by default, `--enable-writes` to commit.
"""

from ..actions.author import act_group_write
from ..actions.groups import act_groups
from ..api import ROLE_GM, ROLE_LM
from ..authoring import CRITERIA_HELP
from ..errors import ConfigError, NsxError
from ..output import err
from . import add_action, add_command


def register_group(sub, parents):
    p = add_command(
        sub, parents, "group", "Search and inspect security groups.")
    gsub = p.add_subparsers(dest="group_action", metavar="<action>")

    ls = add_action(
        gsub, parents, "list", "List groups and their criteria.",
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

    sh = add_action(
        gsub, parents, "show", "Show one group in full.",
        description="Show a single group's criteria and members.",
        epilog="example:\n  nsxctl group show web-prod")
    sh.add_argument("name", help="Group name or id.")
    sh.set_defaults(func=cmd_group_show)

    cr = add_action(
        gsub, parents, "create", "Create a group from criteria.",
        description="Create a dynamic security group.\n\n" + CRITERIA_HELP +
                    "\n\nDry run by default: nothing is written without "
                    "--enable-writes.",
        epilog="examples:\n"
               "  nsxctl group create g-web --criteria 'tag:env=prod AND "
               "tag:tier=web'\n"
               "  nsxctl group create g-web --criteria 'tag:env=prod' "
               "--enable-writes --yes")
    cr.add_argument("name", help="Group id to create.")
    cr.add_argument("--criteria", required=True,
                    help="Membership criteria. See the syntax above.")
    cr.add_argument("--display-name", help="Human-readable name.")
    cr.add_argument("--description", help="Free-text description.")
    cr.set_defaults(func=cmd_group_create)

    ed = add_action(
        gsub, parents, "edit", "Change an existing group.",
        description="Change a group's criteria, name or description. The plan "
                    "is shown as a field-level diff before anything is "
                    "written.\n\n" + CRITERIA_HELP,
        epilog="example:\n"
               "  nsxctl group edit g-web --criteria 'tag:env=prod OR "
               "tag:env=staging'")
    ed.add_argument("name", help="Group name or id.")
    ed.add_argument("--criteria", help="Replacement membership criteria.")
    ed.add_argument("--display-name", help="New human-readable name.")
    ed.add_argument("--description", help="New description.")
    ed.set_defaults(func=cmd_group_edit)

    dl = add_action(
        gsub, parents, "delete", "Delete a group.",
        description="Delete a group. Rules referencing it are NOT rewritten -- "
                    "run `nsxctl rule hygiene` afterwards to find any left "
                    "pointing at nothing.",
        epilog="example:\n  nsxctl group delete g-old --enable-writes")
    dl.add_argument("name", help="Group name or id.")
    dl.set_defaults(func=cmd_group_delete)

    p.set_defaults(func=_group_needs_action)


def _group_needs_action(args, ctx):
    err("Specify what to do: nsxctl group list | show | create | edit | delete")
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


def _group_write(args, ctx, **kwargs):
    """Shared plumbing: dry run unless writes are enabled."""
    try:
        result = act_group_write(
            ctx, args.name, dry_run=not ctx.write_enabled,
            force=args.force, **kwargs)
    except (NsxError, ConfigError) as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


def cmd_group_create(args, ctx):
    return _group_write(args, ctx, criteria=args.criteria,
                        display_name=args.display_name,
                        description=args.description)


def cmd_group_edit(args, ctx):
    if not any((args.criteria, args.display_name, args.description)):
        err("Nothing to change. Give --criteria, --display-name or "
            "--description.")
        return 2
    return _group_write(args, ctx, criteria=args.criteria,
                        display_name=args.display_name,
                        description=args.description)


def cmd_group_delete(args, ctx):
    return _group_write(args, ctx, delete=True)
