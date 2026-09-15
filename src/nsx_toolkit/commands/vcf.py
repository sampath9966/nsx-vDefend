"""Command: vcf import."""
import getpass

from ..actions.vcf import act_vcf_import
from . import add_action, add_command


def register_vcf(sub, parents):
    p = add_command(sub, parents, "vcf",
                    "VMware Cloud Foundation (VCF) integration.")
    psub = p.add_subparsers(dest="vcf_action", metavar="<action>")
    imp = add_action(psub, parents, "import",
                     "Discover NSX managers from VCF SDDC Manager and "
                     "add them to the inventory.")
    imp.add_argument("--vcf-host", required=True, metavar="HOST",
                     help="VCF SDDC Manager hostname or IP.")
    imp.add_argument("--vcf-user", default="administrator@vsphere.local",
                     metavar="USER",
                     help="VCF SDDC Manager username.")
    imp.add_argument("--vcf-password", metavar="PASS",
                     help="VCF password (prompted if omitted).")
    imp.add_argument("--out", default="inventory.json", metavar="PATH",
                     help="Inventory file to update (default: inventory.json).")
    imp.set_defaults(func=cmd_vcf_import)
    p.set_defaults(func=lambda a, ctx: p.print_help())


def cmd_vcf_import(args, ctx):
    password = getattr(args, "vcf_password", None)
    if not password and not getattr(args, "non_interactive", False):
        password = getpass.getpass("VCF password: ")
    act_vcf_import(
        vcf_host=args.vcf_host,
        vcf_user=args.vcf_user,
        vcf_password=password or "",
        out_path=args.out,
        ca_bundle=getattr(args, "ca_bundle", None),
        enable_writes=getattr(args, "enable_writes", False),
        exporter=ctx.exporter,
    )
    return 0
