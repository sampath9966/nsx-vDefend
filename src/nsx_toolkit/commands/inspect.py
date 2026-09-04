"""Policy and service inspection: `nsxctl policy|service list|show`.

Rules live under `nsxctl rule` alongside their authoring verbs; policies and
services get their own commands because you look them up to *find the names*
the other commands need.
"""

from ..actions.inspect import (
    act_policy_list,
    act_service_list,
    act_service_show,
)
from . import add_action, add_command


def register_inspect(sub, parents):
    p = add_command(
        sub, parents, "policy", "Inspect security policies.")
    psub = p.add_subparsers(dest="policy_action", metavar="<action>")
    ls = add_action(
        psub, parents, "list", "List security policies.",
        description="Policies across every manager, deduplicated, in NSX "
                    "evaluation order with their rule counts. This is where "
                    "the name `nsxctl rule create --policy` wants comes from.",
        epilog="examples:\n"
               "  nsxctl policy list\n"
               "  nsxctl policy list --contains app")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only policies whose name or id contains TEXT.")
    ls.set_defaults(func=cmd_policy_list)
    p.set_defaults(func=cmd_policy_list, contains=None)

    p = add_command(
        sub, parents, "service", "Inspect service definitions.")
    ssub = p.add_subparsers(dest="service_action", metavar="<action>")
    ls = add_action(
        ssub, parents, "list", "List services and their ports.",
        description="Service definitions, with the ports each covers and "
                    "whether it is a plain L4 port set.\n\n"
                    "That last column is what makes an undecided "
                    "`nsxctl trace` verdict explicable: only an L4 port set "
                    "reduces to a port comparison, so a rule limited to an "
                    "ICMP or ALG service cannot be decided by port alone.",
        epilog="examples:\n"
               "  nsxctl service list\n"
               "  nsxctl service list --contains sql")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Only services whose name or id contains TEXT.")
    ls.set_defaults(func=cmd_service_list)
    sh = add_action(
        ssub, parents, "show", "Show one service in full.",
        description="Every entry of a service definition, spelled out.",
        epilog="example:\n  nsxctl service show MySQL")
    sh.add_argument("name", help="Service name or id.")
    sh.set_defaults(func=cmd_service_show)
    p.set_defaults(func=cmd_service_list, contains=None)


def cmd_policy_list(args, ctx):
    act_policy_list(ctx.sessions, args.domain, ctx.exporter,
                    contains=getattr(args, "contains", None),
                    cache_key=ctx.cache_key())
    return 0


def cmd_service_list(args, ctx):
    act_service_list(ctx.sessions, args.domain, ctx.exporter,
                     contains=getattr(args, "contains", None),
                     cache_key=ctx.cache_key())
    return 0


def cmd_service_show(args, ctx):
    act_service_show(ctx.sessions, args.domain, ctx.exporter, args.name)
    return 0
