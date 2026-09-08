"""Connectivity trace: `nsxctl trace A B --port 3306`."""

from ..actions.trace import act_trace, report_ambiguous_nic
from ..errors import NsxError
from ..output import err
from ..trace import DEFAULT_PROTO, AmbiguousNic, parse_duration
from . import add_command


def register_trace(sub, parents):
    p = add_command(
        sub, parents, "trace",
        "Can A reach B, and which rule decided it.",
        description="Evaluates the policy, and -- unless --static is given --"
                    " injects a synthetic packet at the source VM's logical "
                    "port and reports what the data plane actually did with "
                    "it.\n\n"
                    "The two answers are printed separately and compared, "
                    "because they answer different questions and can "
                    "legitimately differ. NAT, a partial realization, or a "
                    "rule not yet pushed to a host will all make them "
                    "disagree, and that disagreement is the finding.\n\n"
                    "Traceflow is a Local Manager API: the Global Manager "
                    "does not serve it. With no LM connected, or a "
                    "powered-off source, --static is the only half that can "
                    "run and the report says so.",
        epilog="examples:\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 3306\n"
               "  nsxctl trace web-prod-01 --to 10.20.30.40 --port 443\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 3306 --static\n"
               "  nsxctl trace web-prod-01 db-prod-01 --port 22 --yes"
               "        # unattended\n"
               "  nsxctl trace web-prod-01 db-prod-01 --nic 2 --timeout 30s")
    p.add_argument("source", help="Source VM name, or part of one.")
    p.add_argument("destination", nargs="?",
                   help="Destination VM name. Omit when using --to.")
    p.add_argument("--to", metavar="ADDRESS", dest="to_address",
                   help="Trace to an IP address instead of a VM.")
    p.add_argument("--port", type=int, metavar="N",
                   help="Destination port. Without it, rules restricted to a "
                        "service cannot be decided and are reported as such.")
    p.add_argument("--proto", default=DEFAULT_PROTO,
                   choices=("tcp", "udp", "icmp"),
                   help="Transport protocol (default: {}).".format(DEFAULT_PROTO))
    p.add_argument("--nic", metavar="NIC",
                   help="Which NIC to trace from on a multi-NIC VM: a 1-based "
                        "index, a device name, or a MAC.")
    p.add_argument("--timeout", metavar="DURATION", default=None,
                   help="How long to wait for observations (15s, 2m). "
                        "Default 15s.")
    p.add_argument("--static", action="store_true",
                   help="Evaluate the policy only. Sends no packet, needs no "
                        "confirmation, and works on a GM or a powered-off VM.")
    p.set_defaults(func=cmd_trace)


def cmd_trace(args, ctx):
    if not args.destination and not args.to_address:
        err("Give a destination VM, or an address with --to.")
        return 2
    try:
        timeout = parse_duration(args.timeout)
        outcome = act_trace(
            ctx.sessions, args.source, args.destination, args.domain,
            ctx.exporter, port=args.port, proto=args.proto,
            to_address=args.to_address, static_only=args.static,
            nic=args.nic, timeout=timeout)
    except AmbiguousNic as e:
        report_ambiguous_nic(e)
        return 2
    except NsxError as e:
        # Nothing ran: an endpoint could not be resolved. That is a "could not
        # start" failure, not a finding about the flow.
        err(str(e))
        return 2
    return 0 if outcome.has_verdict else 1
