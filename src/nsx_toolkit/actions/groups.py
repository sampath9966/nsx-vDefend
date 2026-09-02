"""Group search: criteria, and optionally VM members."""

from ..api import (
    F_DESCRIPTION,
    F_DISPLAY_NAME,
    F_EXPRESSION,
    F_ID,
    F_PATH,
    ROLE_LABEL,
    p_group_members,
    p_groups,
)
from ..errors import NsxError
from ..output import Spinner, cB, cBY, cC, cD, cR, err, hr, more_note, say, section
from ..render import criteria_summary, describe_expression

CONSOLE_MEMBER_LIMIT = 30

GROUPS_HEADERS = ["manager", "group_id", "display_name", "path", "criteria",
                  "members"]


def act_groups(sessions, domain, needle, show_members, exporter):
    rows = []
    for nsx in sessions:
        try:
            base = nsx.base(domain)
        except NsxError as e:
            err(str(e))
            continue
        section("{}  [{}]".format(nsx.name, ROLE_LABEL.get(nsx.role, "?")))
        with Spinner("Fetching groups from {}".format(nsx.name)):
            try:
                groups = nsx.get_all(p_groups(base, domain))
            except NsxError as e:
                err(str(e))
                continue
        say("  {} group(s).".format(len(groups)))
        if needle:
            n = needle.lower()
            groups = [g for g in groups
                      if n in str(g.get(F_DISPLAY_NAME, "")).lower()
                      or n in str(g.get(F_ID, "")).lower()]
            say("  {} match '{}'.".format(cC(str(len(groups))), needle))
        for g in sorted(groups, key=lambda x: str(x.get(F_DISPLAY_NAME, "")).lower()):
            gid = g.get(F_ID, "?")
            dname = g.get(F_DISPLAY_NAME, gid)
            hr()
            say("  Group        : {}".format(cB(dname)))
            if gid != dname:
                say("  id           : {}   {}".format(gid, cBY("[id != name]")))
            else:
                say("  id           : {}".format(gid))
            say("  path         : {}".format(cD(g.get(F_PATH, "?"))))
            if g.get(F_DESCRIPTION):
                say("  description  : {}".format(g[F_DESCRIPTION]))
            say("  criteria     :")
            for line in describe_expression(g.get(F_EXPRESSION)):
                say("    {}".format(line))
            member_count = ""
            if show_members:
                try:
                    vms = nsx.get_all(p_group_members(base, domain, gid))
                    member_count = str(len(vms))
                    say("  VM members ({}):".format(cC(member_count)))
                    for vm in vms[:CONSOLE_MEMBER_LIMIT]:
                        say("    {}".format(vm.get(F_DISPLAY_NAME, vm.get(F_ID, "?"))))
                    more_note(CONSOLE_MEMBER_LIMIT, len(vms), "member count in export")
                except NsxError as e:
                    say("  VM members: {} ({})".format(cR("error"), e))
                    member_count = "error"
            rows.append([nsx.name, gid, dname, g.get(F_PATH, ""),
                         criteria_summary(g.get(F_EXPRESSION)), member_count])
    hr()
    exporter.stage("groups", GROUPS_HEADERS, rows)
