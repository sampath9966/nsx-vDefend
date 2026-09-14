"""Commands: segment, edge, bgp."""
from ..actions.topo import act_bgp, act_edge_list, act_segment_list
from . import add_action, add_command


def register_topo(sub, parents):
    # --- segment ---
    seg = add_command(sub, parents, "segment", "Network segments.")
    ssub = seg.add_subparsers(dest="seg_action", metavar="<action>")
    ls = add_action(ssub, parents, "list", "List overlay and VLAN-backed segments.")
    ls.add_argument("--contains", metavar="TEXT",
                    help="Filter segments by name substring.")
    ls.add_argument("--type", dest="seg_type", choices=["overlay", "vlan"],
                    help="Show only overlay or VLAN-backed segments.")
    ls.set_defaults(func=cmd_segment_list)
    seg.set_defaults(func=lambda a, ctx: seg.print_help())

    # --- edge ---
    edge = add_command(sub, parents, "edge", "Edge transport nodes.")
    esub = edge.add_subparsers(dest="edge_action", metavar="<action>")
    el = add_action(esub, parents, "list", "List edge nodes and deployment status.")
    el.set_defaults(func=cmd_edge_list)
    edge.set_defaults(func=lambda a, ctx: edge.print_help())

    # --- bgp ---
    bgp = add_command(sub, parents, "bgp", "BGP neighbour status on T0 gateways.")
    bgp.add_argument("--tier-0", metavar="NAME",
                     help="Limit to one T0 gateway by name.")
    bgp.add_argument("--down-only", action="store_true",
                     help="Show only non-ESTABLISHED neighbours.")
    bgp.set_defaults(func=cmd_bgp)


def cmd_segment_list(args, ctx):
    act_segment_list(ctx.sessions, getattr(args, "domain", "default"),
                     ctx.exporter,
                     contains=getattr(args, "contains", None),
                     seg_type=getattr(args, "seg_type", None))
    return 0


def cmd_edge_list(args, ctx):
    act_edge_list(ctx.sessions, ctx.exporter)
    return 0


def cmd_bgp(args, ctx):
    act_bgp(ctx.sessions, getattr(args, "domain", "default"),
            ctx.exporter,
            tier0=getattr(args, "tier_0", None),
            down_only=getattr(args, "down_only", False))
    return 0
