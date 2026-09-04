"""Turn observed flows into a reviewable ruleset proposal."""

import json
import os

from ..errors import ConfigError
from ..flows import (
    DEFAULT_MAX_PORTS,
    group_display_names,
    proposals_to_change_file,
    propose_rules,
    read_flows,
)
from ..output import (
    cB,
    cBR,
    cBY,
    cC,
    cD,
    hr,
    more_note,
    ok_msg,
    say,
    section,
    table,
    warn,
)
from ..policy import group_inventory

PROPOSAL_HEADERS = ["source", "destination", "protocol", "ports", "flows"]
UNRESOLVED_HEADERS = ["address", "side", "flows"]

RECOMMEND_CONSOLE_LIMIT = 30


def act_recommend(sessions, domain, exporter, flow_file, policy=None,
                  out_file=None, max_ports=DEFAULT_MAX_PORTS,
                  include_denied=False, action="ALLOW"):
    """Read a flow export, propose rules, and write a change file.

    Returns (proposals, unresolved, wide). Nothing is written to NSX: the
    output is an `nsxctl apply` document, because a ruleset derived from an
    observation window is a draft that needs a person to read it.
    """
    section("RULE RECOMMENDATIONS FROM OBSERVED FLOWS")
    flows, problems = read_flows(flow_file, include_denied=include_denied)
    for problem in problems[:10]:
        warn(problem)
    more_note(10, len(problems), "rows skipped")

    groups = group_inventory(sessions, domain)
    names = group_display_names(groups)
    proposals, unresolved, wide = propose_rules(flows, groups,
                                                max_ports=max_ports)

    say("  Flows read     : {}".format(cC(str(len(flows)))))
    say("  Groups known   : {}".format(cC(str(len(groups)))))
    say("  Rules proposed : {}".format(cC(str(len(proposals)))))
    hr()

    def label(paths):
        return ", ".join(names.get(p, p.rsplit("/", 1)[-1]) for p in paths)

    if proposals:
        table(["Source", "Destination", "Proto", "Ports", "Flows"],
              [[cB(label(p.source_groups)), cB(label(p.destination_groups)),
                p.protocol, ",".join(str(x) for x in p.ports),
                str(p.flow_count)]
               for p in proposals[:RECOMMEND_CONSOLE_LIMIT]], indent=4)
        more_note(RECOMMEND_CONSOLE_LIMIT, len(proposals))
    else:
        say("  {}".format(cD("No flow resolved to a pair of known groups.")))

    if wide:
        say("\n  {} {} pair(s) talked on more than {} ports and were NOT "
            "turned into rules:".format(cBY("WIDE:"), len(wide), max_ports))
        for proposal in wide[:10]:
            say("    {} -> {}   {} ports".format(
                label(proposal.source_groups),
                label(proposal.destination_groups), len(proposal.ports)))
        say("  {}".format(cD(
            "That shape is usually a scanner or a monitoring host. One rule "
            "with fifty ports would bury it rather than surface it.")))

    if unresolved:
        say("\n  {} {} address(es) belong to no group:".format(
            cBR("UNCLASSIFIED:"), len(unresolved)))
        for item in unresolved[:RECOMMEND_CONSOLE_LIMIT]:
            say("    {:18s} {:12s} {} flow(s)".format(
                item.address, item.side, item.flow_count))
        more_note(RECOMMEND_CONSOLE_LIMIT, len(unresolved))
        say("  {}".format(cD(
            "These are the most useful rows here: traffic exists and nobody "
            "has classified the workload. No rule is proposed for them.")))

    exporter.stage("flow_proposals", PROPOSAL_HEADERS,
                   [p.row() for p in proposals])
    exporter.stage("flow_unresolved", UNRESOLVED_HEADERS,
                   [u.row() for u in unresolved])

    hr()
    say("  {} this proposes ALLOW rules for traffic that was "
        "observed.".format(cD("note:")))
    say("  {}".format(cD(
        "It never proposes a default-deny: no traffic seen in one window is "
        "not")))
    say("  {}".format(cD(
        "evidence none exists -- the same reason a zero hit count cannot "
        "retire a rule.")))

    if out_file and proposals:
        if not policy:
            raise ConfigError(
                "Writing a change file needs --policy: a rule has to go "
                "somewhere.")
        document = proposals_to_change_file(proposals, policy, action=action)
        _write_change_file(out_file, document)
        ok_msg("Change file: {}".format(out_file))
        say("  {} review it, then:".format(cD("next:")))
        say("    {}".format(cC("nsxctl apply {}".format(out_file))))
        say("    {}".format(cD(
            "(dry run by default; add --enable-writes to commit)")))
    elif out_file:
        say("  {}".format(cD("Nothing to write: no rules proposed.")))
    return proposals, unresolved, wide


def _write_change_file(path, document):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def recommend_summary(proposals, unresolved, wide):
    return {"proposed": len(proposals), "unclassified": len(unresolved),
            "wide": len(wide)}


def clean_estate(unresolved, wide):
    """True when every observed endpoint was classified and nothing was wide."""
    return not unresolved and not wide
