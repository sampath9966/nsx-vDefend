"""Tag operations: `nsxctl tag list|find|edit|apply|ticket`."""

from ..actions.bulk import act_bulk_tag
from ..actions.change_ticket import act_change_ticket
from ..actions.tags import act_manage_tags, act_vm_tags, act_vms_by_tag
from ..output import cB, cBY, confirm, err, is_interactive, say
from . import add_command

CSV_HELP = "CSV with columns: vm_name,scope,tag,action  (action = add | remove)"


def register_tag(sub, parents):
    p = add_command(sub, parents, "tag", "Read and change VM tags.")
    tsub = p.add_subparsers(dest="tag_action", metavar="<action>")

    ls = tsub.add_parser(
        "list", parents=parents, help="Show every tag on a VM.",
        description="Show all tags on matching VMs, validated against the "
                    "configured taxonomy.",
        epilog="example:\n  nsxctl tag list web-prod-01")
    ls.add_argument("vm", help="VM name, or part of one.")
    ls.set_defaults(func=cmd_tag_list)

    fd = tsub.add_parser(
        "find", parents=parents, help="Find every VM carrying a tag.",
        description="Find VMs by tag scope, value, or both.",
        epilog="examples:\n"
               "  nsxctl tag find --scope env --tag prod\n"
               "  nsxctl tag find --scope owner --out-csv owners.csv")
    fd.add_argument("--scope", help="Tag scope (blank = any).")
    fd.add_argument("--tag", help="Tag value (blank = any).")
    fd.set_defaults(func=cmd_tag_find)

    ed = tsub.add_parser(
        "edit", parents=parents, help="Add or remove tags interactively.",
        description="Interactive add/remove for one VM. Audit-logged and "
                    "undoable.",
        epilog="example:\n  nsxctl tag edit web-prod-01 --enable-writes")
    ed.add_argument("vm", help="VM name, or part of one.")
    ed.set_defaults(func=cmd_tag_edit)

    ap = tsub.add_parser(
        "apply", parents=parents, help="Apply bulk tag changes from a CSV.",
        description="Bulk tag changes. Always previews first; writing needs "
                    "--enable-writes and confirmation.\n\n" + CSV_HELP,
        epilog="examples:\n"
               "  nsxctl tag apply changes.csv                    preview only\n"
               "  nsxctl tag apply changes.csv --enable-writes --yes")
    ap.add_argument("csv", metavar="FILE", help=CSV_HELP)
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview only, even with --enable-writes.")
    ap.set_defaults(func=cmd_tag_apply)

    tk = tsub.add_parser(
        "ticket", parents=parents, help="Generate a change-plan document.",
        description="Build a change plan from a CSV, validated against live "
                    "NSX: current tags, proposed tags, and anything that "
                    "cannot be resolved.\n\n" + CSV_HELP,
        epilog="example:\n  nsxctl tag ticket changes.csv")
    tk.add_argument("csv", metavar="FILE", help=CSV_HELP)
    tk.set_defaults(func=cmd_tag_ticket)

    p.set_defaults(func=_tag_needs_action)


def _tag_needs_action(args, ctx):
    err("Specify what to do: nsxctl tag list|find|edit|apply|ticket")
    return 2


def cmd_tag_list(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_vm_tags(ctx.lms(), args.vm, ctx.exporter, ctx.taxonomy)
    return 0


def cmd_tag_find(args, ctx):
    if not args.scope and not args.tag:
        err("Give --scope, --tag, or both.")
        return 2
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_vms_by_tag(ctx.lms(), args.scope, args.tag, ctx.exporter)
    return 0


def cmd_tag_edit(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    act_manage_tags(ctx.lms(), args.vm, ctx.audit, ctx.write_enabled,
                    ctx.taxonomy)
    return 0


def cmd_tag_apply(args, ctx):
    if not ctx.lms():
        err("Tags are Local Manager objects; no Local Manager is connected.")
        return 2
    # Preview always runs first, in every invocation path.
    act_bulk_tag(ctx.lms(), args.csv, ctx.audit, ctx.write_enabled,
                 dry_run=True, taxonomy=ctx.taxonomy)
    if args.dry_run:
        return 0
    if not ctx.write_enabled:
        say("\n  {} -- add --enable-writes to apply.".format(cBY("READ-ONLY")))
        return 0
    if not _tag_write_gate():
        say("  Cancelled -- nothing written.")
        return 0
    result = act_bulk_tag(ctx.lms(), args.csv, ctx.audit, ctx.write_enabled,
                          dry_run=False, taxonomy=ctx.taxonomy,
                          force=args.force)
    return 1 if result["failed"] else 0


def _tag_write_gate():
    """A write needs --yes, or an interactive confirmation. Never assumed."""
    from ..output import assume_yes
    if assume_yes():
        return True
    if not is_interactive():
        err("Refusing to write without confirmation. Re-run with --yes "
            "(or --dry-run to preview).")
        return False
    return confirm("  {} [y/N]: ".format(cB("Apply for real?")))


def cmd_tag_ticket(args, ctx):
    act_change_ticket(ctx.sessions, args.csv, ctx.exporter)
    return 0
