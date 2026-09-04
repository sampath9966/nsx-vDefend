"""Flow-derived rule proposals: `nsxctl recommend flows.csv`."""

from ..actions.recommend import act_recommend
from ..errors import ConfigError, NsxError
from ..flows import DEFAULT_MAX_PORTS
from ..output import err
from . import add_command

RECOMMEND_HELP = """flow export format (CSV or a JSON list of records):

  source,destination,port,protocol,action,count
  10.1.1.10,10.1.2.20,3306,tcp,ALLOW,842
  10.1.1.11,10.1.2.20,3306,tcp,ALLOW,71

Column names are matched loosely -- src/src_ip/source_ip all work, as do
dst_port/destination_port -- because every exporter names them differently
and none of them are wrong. Denied flows are ignored unless --include-denied:
a blocked flow is usually evidence the segmentation is working, not evidence
a rule is missing.
"""


def register_recommend(sub, parents):
    p = add_command(
        sub, parents, "recommend",
        "Propose rules from a flow export.",
        description="Turn traffic that actually happened into a reviewable "
                    "ruleset.\n\n"
                    "Reads a flow export you already have (NSX Intelligence "
                    "export, vRNI, a firewall-log query) rather than calling "
                    "the Intelligence recommendation API, which is licensed "
                    "separately and absent on most estates.\n\n"
                    "Endpoints are resolved against the IP addresses your "
                    "groups declare. An address no group claims is REPORTED, "
                    "never guessed at -- an unclassified workload is the most "
                    "useful thing this finds.\n\n"
                    "Output is an `nsxctl apply` change file. Nothing is "
                    "written to NSX.\n\n" + RECOMMEND_HELP,
        epilog="examples:\n"
               "  nsxctl recommend flows.csv\n"
               "  nsxctl recommend flows.csv --policy app-tier "
               "--out-file proposed.json\n"
               "  nsxctl recommend flows.csv --max-ports 25")
    p.add_argument("flow_file", metavar="FLOWS",
                   help="Flow export (CSV, or a JSON list of records).")
    p.add_argument("--policy", metavar="NAME",
                   help="Policy the proposed rules should go in. Required to "
                        "write a change file.")
    p.add_argument("--out-file", metavar="PATH",
                   help="Write the proposal as an `nsxctl apply` document.")
    p.add_argument("--max-ports", type=int, default=DEFAULT_MAX_PORTS,
                   metavar="N",
                   help="Flag a pair talking on more than N ports instead of "
                        "proposing a rule for it (default {}).".format(
                            DEFAULT_MAX_PORTS))
    p.add_argument("--include-denied", action="store_true",
                   help="Also derive rules from flows that were denied.")
    p.set_defaults(func=cmd_recommend)


def cmd_recommend(args, ctx):
    try:
        proposals, _unresolved, _wide = act_recommend(
            ctx.sessions, args.domain, ctx.exporter, args.flow_file,
            policy=args.policy, out_file=args.out_file,
            max_ports=args.max_ports, include_denied=args.include_denied)
    except (ConfigError, NsxError) as e:
        err(str(e))
        return 2
    return 0 if proposals else 1
