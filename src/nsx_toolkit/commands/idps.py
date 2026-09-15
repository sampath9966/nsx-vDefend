"""Commands: context-profile, idps."""
from ..actions.idps import (
    act_context_profile_list,
    act_ids_events,
    act_ids_profiles,
)
from . import add_action, add_command


def register_idps(sub, parents):
    # --- context-profile ---
    cp = add_command(sub, parents, "context-profile",
                     "NSX context profiles (L7 app / FQDN signatures).")
    cpsub = cp.add_subparsers(dest="cp_action", metavar="<action>")
    cpl = add_action(cpsub, parents, "list", "List context profiles.")
    cpl.add_argument("--contains", metavar="TEXT",
                     help="Filter by name substring.")
    cpl.set_defaults(func=cmd_context_profile_list)
    cp.set_defaults(func=lambda a, ctx: cp.print_help())

    # --- idps ---
    ip = add_command(sub, parents, "idps", "IDS/IPS profiles and events.")
    ipsub = ip.add_subparsers(dest="idps_action", metavar="<action>")

    ipe = add_action(ipsub, parents, "events",
                     "Show IDS/IPS detection events.")
    ipe.add_argument("--severity", metavar="LEVEL",
                     choices=["critical", "high", "medium", "low"],
                     help="Filter events by severity.")
    ipe.set_defaults(func=cmd_ids_events)

    ipp = add_action(ipsub, parents, "profiles",
                     "List IDS/IPS signature profiles.")
    ipp.set_defaults(func=cmd_ids_profiles)

    ip.set_defaults(func=lambda a, ctx: ip.print_help())


def cmd_context_profile_list(args, ctx):
    act_context_profile_list(ctx.sessions, ctx.exporter,
                             contains=getattr(args, "contains", None))
    return 0


def cmd_ids_events(args, ctx):
    act_ids_events(ctx.sessions, ctx.exporter,
                   severity=getattr(args, "severity", None))
    return 0


def cmd_ids_profiles(args, ctx):
    act_ids_profiles(ctx.sessions, ctx.exporter)
    return 0
