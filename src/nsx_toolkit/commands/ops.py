"""Commands: alarms, cert, capacity."""
from ..actions.ops import act_alarms, act_capacity, act_cert_list
from . import add_action, add_command


def register_ops(sub, parents):
    # ---- alarms -------------------------------------------------------
    p = add_command(sub, parents, "alarms",
                    "Show open NSX alarms.",
                    description="Collect alarms from every manager and display "
                                "them sorted by severity. Deduplicates by alarm "
                                "id when a GM and LMs echo the same event.",
                    epilog="examples:\n"
                           "  nsxctl alarms\n"
                           "  nsxctl alarms --severity critical\n"
                           "  nsxctl alarms --all")
    p.add_argument("--severity", metavar="LEVEL",
                   choices=["critical", "high", "medium", "low"],
                   help="Show only alarms at this severity.")
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="Include resolved alarms (default: OPEN only).")
    p.set_defaults(func=cmd_alarms)

    # ---- cert ---------------------------------------------------------
    c = add_command(sub, parents, "cert",
                    "TLS certificate expiry.",
                    description="Certificate management subcommands.")
    csub = c.add_subparsers(dest="cert_action", metavar="<action>")
    ls = add_action(csub, parents, "list",
                    "List certificates and expiry status.",
                    description="List TLS certificates across every manager with "
                                "color-coded expiry status.",
                    epilog="examples:\n"
                           "  nsxctl cert list\n"
                           "  nsxctl cert list --warn-days 30\n"
                           "  nsxctl cert list --expired")
    ls.add_argument("--warn-days", type=int, default=90, metavar="N",
                    help="Highlight certs expiring within N days (default: 90).")
    ls.add_argument("--expired", action="store_true",
                    help="Show only expired or critically-expiring certs.")
    ls.set_defaults(func=cmd_cert_list)
    c.set_defaults(func=lambda a, ctx: c.print_help())

    # ---- capacity -----------------------------------------------------
    q = add_command(sub, parents, "capacity",
                    "Show NSX resource utilisation.",
                    description="Per-resource utilisation across every manager. "
                                "Resources approaching their limit are highlighted.",
                    epilog="examples:\n"
                           "  nsxctl capacity\n"
                           "  nsxctl capacity --out-csv cap.csv")
    q.set_defaults(func=cmd_capacity)


def cmd_alarms(args, ctx):
    act_alarms(ctx.sessions, ctx.exporter,
               severity=getattr(args, "severity", None),
               show_all=getattr(args, "show_all", False))
    return 0


def cmd_cert_list(args, ctx):
    act_cert_list(ctx.sessions, ctx.exporter,
                  warn_days=getattr(args, "warn_days", 90),
                  expired_only=getattr(args, "expired", False))
    return 0


def cmd_capacity(args, ctx):
    act_capacity(ctx.sessions, ctx.exporter)
    return 0
