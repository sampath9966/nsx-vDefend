"""Commands: gw-policy, gw-rule."""
from ..actions.gw_inspect import (
    act_gw_hygiene,
    act_gw_policy_list,
    act_gw_rule_list,
)
from . import add_action, add_command


def register_gw(sub, parents):
    # --- gw-policy ---
    gp = add_command(sub, parents, "gw-policy", "Gateway firewall policies.")
    gpsub = gp.add_subparsers(dest="gp_action", metavar="<action>")
    gpl = add_action(gpsub, parents, "list", "List gateway policies.")
    gpl.add_argument("--contains", metavar="TEXT",
                     help="Filter by name substring.")
    gpl.set_defaults(func=cmd_gw_policy_list)
    gp.set_defaults(func=lambda a, ctx: gp.print_help())

    # --- gw-rule ---
    gr = add_command(sub, parents, "gw-rule", "Gateway firewall rules.")
    grsub = gr.add_subparsers(dest="gr_action", metavar="<action>")

    grl = add_action(grsub, parents, "list", "List gateway firewall rules.")
    grl.add_argument("--policy", metavar="NAME",
                     help="Limit to one policy by name.")
    grl.add_argument("--contains", metavar="TEXT",
                     help="Filter rules by name substring.")
    grl.add_argument("--action", metavar="ACTION",
                     choices=["allow", "drop", "reject"],
                     help="Show only rules with this action.")
    grl.add_argument("--disabled", action="store_true",
                     help="Show only disabled rules.")
    grl.set_defaults(func=cmd_gw_rule_list)

    grh = add_action(grsub, parents, "hygiene",
                     "Check gateway rules for common issues.")
    grh.set_defaults(func=cmd_gw_hygiene)

    gr.set_defaults(func=lambda a, ctx: gr.print_help())


def cmd_gw_policy_list(args, ctx):
    act_gw_policy_list(ctx.sessions, getattr(args, "domain", "default"),
                       ctx.exporter,
                       contains=getattr(args, "contains", None))
    return 0


def cmd_gw_rule_list(args, ctx):
    act_gw_rule_list(ctx.sessions, getattr(args, "domain", "default"),
                     ctx.exporter,
                     policy=getattr(args, "policy", None),
                     contains=getattr(args, "contains", None),
                     action=getattr(args, "action", None),
                     disabled_only=getattr(args, "disabled", False))
    return 0


def cmd_gw_hygiene(args, ctx):
    act_gw_hygiene(ctx.sessions, getattr(args, "domain", "default"),
                   ctx.exporter)
    return 0
