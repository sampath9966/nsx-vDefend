"""`nsxctl vm` — VM-centric views."""

from ..actions.vm import act_vm_groups
from ..errors import NsxError
from ..output import err
from . import add_action, add_command


def register_vm(sub, parents):
    p = add_command(sub, parents, "vm", "VM-centric views.")
    vsub = p.add_subparsers(dest="vm_action", metavar="<action>")

    gr = add_action(
        vsub, parents, "groups", "Show every group a VM belongs to.",
        description="Groups this VM is currently a member of, using NSX's own "
                    "reverse-association index. Shows every group regardless of "
                    "how membership is decided -- tag-based, segment-based, VIF-based "
                    "and IP-set groups all appear, unlike the per-group member listing "
                    "which silently skips non-VirtualMachine member types.\n\n"
                    "Also shows how many DFW rules reference each group, so you can "
                    "see at a glance which groups are security-relevant.",
        epilog="examples:\n"
               "  nsxctl vm groups web-prod-01\n"
               "  nsxctl vm groups web   # substring match\n"
               "  nsxctl vm groups web-prod-01 --json")
    gr.add_argument("vm", help="VM name or substring.")
    gr.set_defaults(func=cmd_vm_groups)

    p.set_defaults(func=_vm_needs_action)


def cmd_vm_groups(args, ctx):
    lms = ctx.lms()
    if not lms:
        err("No Local Manager sessions. Add a manager with role 'lm' to your "
            "inventory.")
        return 2
    try:
        act_vm_groups(ctx.sessions, args.vm, args.domain, ctx.exporter)
    except NsxError as e:
        err(str(e))
        return 2
    return 0


def _vm_needs_action(args, ctx):
    err("Specify what to do: nsxctl vm groups")
    return 2
