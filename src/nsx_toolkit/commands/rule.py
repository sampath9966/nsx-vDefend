"""DFW rule commands.

`nsxctl rule hygiene` and `nsxctl rule baseline` arrive in Phase 2B. The noun
is registered now so the command tree, its help and the generated shell
completion are stable from the moment nsxctl ships -- rather than the surface
shifting under people one release later.
"""

from ..output import err, say
from . import add_command

RULE_PENDING = ("Not implemented yet -- this lands in the next release.\n"
           "The command is registered now so the surface does not change "
           "under you later.")


def register_rule(sub, parents):
    p = add_command(
        sub, parents, "rule", "Inspect distributed firewall rules.")
    rsub = p.add_subparsers(dest="rule_action", metavar="<action>")

    hy = rsub.add_parser(
        "hygiene", parents=parents,
        help="Report rule hygiene problems. (coming in the next release)",
        description="Find any-any rules, overly broad applied-to scopes, "
                    "rules referencing missing or inert groups, duplicates, "
                    "rules shadowed by an any-any above them, disabled rules, "
                    "and drop rules with logging off.")
    hy.add_argument("--fail-on", choices=("critical", "high", "medium", "low"),
                    help="Exit non-zero when findings at or above this "
                         "severity exist.")
    hy.set_defaults(func=cmd_rule_pending, pending="rule hygiene")

    bl = rsub.add_parser(
        "baseline", parents=parents,
        help="Save or compare rule hit counts. (coming in the next release)",
        description="NSX hit counters are cumulative since the last reset, so "
                    "a single read cannot prove a rule is unused. Saving a "
                    "baseline and comparing later gives zero-hits-between-two-"
                    "timestamps, which is evidence you can attach to a "
                    "deletion request.")
    bl.add_argument("action", choices=("save", "compare"))
    bl.add_argument("--baseline-file", metavar="PATH",
                    help="Baseline to write, or to compare against.")
    bl.set_defaults(func=cmd_rule_pending, pending="rule baseline")

    p.set_defaults(func=_rule_needs_action)


def _rule_needs_action(args, ctx):
    err("Specify what to do: nsxctl rule hygiene  |  nsxctl rule baseline")
    return 2


def cmd_rule_pending(args, ctx):
    err("{}: {}".format(args.pending, RULE_PENDING.splitlines()[0]))
    say("  " + RULE_PENDING.splitlines()[1])
    return 3
