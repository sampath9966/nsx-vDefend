"""Commands: gw-policy, gw-rule."""
from ..actions.gw_inspect import (
    act_gw_hygiene,
    act_gw_policy_list,
    act_gw_rule_list,
)
from ..actions.gw_write import (
    act_gw_policy_create,
    act_gw_policy_delete,
    act_gw_rule_create,
    act_gw_rule_delete,
    act_gw_rule_edit,
    act_gw_rule_move,
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

    gpc = add_action(gpsub, parents, "create",
                     "Create a gateway policy (--enable-writes).")
    gpc.add_argument("name", help="Display name for the new policy.")
    gpc.add_argument("--category", default="LocalGatewayRules",
                     metavar="CAT",
                     help="Policy category (default: LocalGatewayRules).")
    gpc.add_argument("--seq", type=int, default=10, metavar="N",
                     help="Sequence number (default: 10).")
    gpc.set_defaults(func=cmd_gw_policy_create)

    gpd = add_action(gpsub, parents, "delete",
                     "Delete a gateway policy (--enable-writes).")
    gpd.add_argument("name", help="Policy name or id.")
    gpd.set_defaults(func=cmd_gw_policy_delete)

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

    grc = add_action(grsub, parents, "create",
                     "Create a gateway rule (--enable-writes).")
    grc.add_argument("name", help="Display name for the new rule.")
    grc.add_argument("--policy", required=True, metavar="NAME",
                     help="Gateway policy to add the rule to.")
    grc.add_argument("--from", dest="src", metavar="GROUP", action="append",
                     help="Source group (repeat for multiple; default: ANY).")
    grc.add_argument("--to", dest="dst", metavar="GROUP", action="append",
                     help="Destination group (repeat for multiple; default: ANY).")
    grc.add_argument("--service", metavar="PATH",
                     help="Service path (default: ANY).")
    grc.add_argument("--action", dest="rule_action", default="ALLOW",
                     choices=["ALLOW", "DROP", "REJECT"],
                     help="Rule action (default: ALLOW).")
    grc.add_argument("--seq", type=int, default=10, metavar="N",
                     help="Sequence number (default: 10).")
    grc.add_argument("--no-log", dest="logged", action="store_false",
                     help="Disable logging for this rule.")
    grc.add_argument("--disabled", action="store_true",
                     help="Create the rule in disabled state.")
    grc.set_defaults(func=cmd_gw_rule_create, logged=True)

    gre = add_action(grsub, parents, "edit",
                     "Edit a gateway rule in place (--enable-writes).")
    gre.add_argument("name", help="Rule name or id.")
    gre.add_argument("--policy", required=True, metavar="NAME",
                     help="Policy containing the rule.")
    gre.add_argument("--action", dest="rule_action", metavar="ACTION",
                     choices=["ALLOW", "DROP", "REJECT"],
                     help="New action.")
    gre.add_argument("--from", dest="src", metavar="GROUP", action="append",
                     help="Replace source groups.")
    gre.add_argument("--to", dest="dst", metavar="GROUP", action="append",
                     help="Replace destination groups.")
    gre.add_argument("--service", metavar="PATH",
                     help="Replace service.")
    gre.add_argument("--enable-logging", dest="logged", action="store_true",
                     default=None, help="Enable logging.")
    gre.add_argument("--disable-logging", dest="logged", action="store_false",
                     help="Disable logging.")
    gre.add_argument("--enable-rule", dest="disabled", action="store_false",
                     default=None, help="Enable the rule.")
    gre.add_argument("--disable-rule", dest="disabled", action="store_true",
                     help="Disable the rule.")
    gre.set_defaults(func=cmd_gw_rule_edit)

    grm = add_action(grsub, parents, "move",
                     "Reorder a gateway rule (--enable-writes).")
    grm.add_argument("name", help="Rule to reorder.")
    grm.add_argument("--policy", required=True, metavar="NAME",
                     help="Policy containing both rules.")
    grm.add_argument("--before", required=True, metavar="OTHER",
                     help="Move the rule immediately before this rule.")
    grm.set_defaults(func=cmd_gw_rule_move)

    grd = add_action(grsub, parents, "delete",
                     "Delete a gateway rule (--enable-writes).")
    grd.add_argument("name", help="Rule name or id.")
    grd.add_argument("--policy", required=True, metavar="NAME",
                     help="Policy containing the rule.")
    grd.set_defaults(func=cmd_gw_rule_delete)

    gr.set_defaults(func=lambda a, ctx: gr.print_help())


def cmd_gw_policy_list(args, ctx):
    act_gw_policy_list(ctx.sessions, getattr(args, "domain", "default"),
                       ctx.exporter,
                       contains=getattr(args, "contains", None))
    return 0


def cmd_gw_policy_create(args, ctx):
    act_gw_policy_create(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        name=args.name, category=args.category, seq=args.seq,
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
    return 0


def cmd_gw_policy_delete(args, ctx):
    act_gw_policy_delete(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        name=args.name,
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
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


def cmd_gw_rule_create(args, ctx):
    act_gw_rule_create(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        policy=args.policy, name=args.name,
        src=getattr(args, "src", None),
        dst=getattr(args, "dst", None),
        service=getattr(args, "service", None),
        action=getattr(args, "rule_action", "ALLOW"),
        seq=getattr(args, "seq", 10),
        logged=getattr(args, "logged", True),
        disabled=getattr(args, "disabled", False),
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
    return 0


def cmd_gw_rule_edit(args, ctx):
    act_gw_rule_edit(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        policy=args.policy, name=args.name,
        action=getattr(args, "rule_action", None),
        src=getattr(args, "src", None),
        dst=getattr(args, "dst", None),
        service=getattr(args, "service", None),
        logged=getattr(args, "logged", None),
        disabled=getattr(args, "disabled", None),
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
    return 0


def cmd_gw_rule_move(args, ctx):
    act_gw_rule_move(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        policy=args.policy, name=args.name, before=args.before,
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
    return 0


def cmd_gw_rule_delete(args, ctx):
    act_gw_rule_delete(
        ctx.sessions, getattr(args, "domain", "default"), ctx.exporter,
        policy=args.policy, name=args.name,
        enable_writes=getattr(args, "enable_writes", False),
        yes=getattr(args, "yes", False))
    return 0
