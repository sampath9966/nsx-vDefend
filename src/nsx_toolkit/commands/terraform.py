"""Command: terraform export."""
from ..actions.terraform import act_terraform_export
from . import add_command


def register_terraform(sub, parents):
    p = add_command(sub, parents, "terraform",
                    "Export NSX config as Terraform HCL.")
    psub = p.add_subparsers(dest="tf_action", metavar="<action>")
    ex = add_command(psub, parents, "export",
                     "Write HCL files per manager and resource type.")
    ex.add_argument("--out", default="terraform-export", metavar="DIR",
                    help="Output directory (default: terraform-export).")
    ex.add_argument("--types", default="groups,dfw,certs", metavar="LIST",
                    help="Comma-separated resource types to export "
                         "(groups, dfw, certs). Default: all.")
    ex.set_defaults(func=cmd_terraform_export)
    p.set_defaults(func=lambda a, ctx: p.print_help())


def cmd_terraform_export(args, ctx):
    types = [t.strip() for t in args.types.split(",") if t.strip()]
    act_terraform_export(ctx.sessions, args.out,
                         domain=getattr(args, "domain", "default"), types=types)
    return 0
