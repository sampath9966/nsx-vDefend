"""Static vs dynamic group parity -- the core migration progress check.

Both groups are resolved on the SAME manager. Resolving each independently
meant a name present on both the Global Manager and a Local Manager could
silently compare a GM copy against an LM copy, reporting a difference that was
really just two different scopes.
"""

from ..api import F_DISPLAY_NAME, F_ID, ROLE_LABEL, p_group_members, p_groups
from ..errors import NsxError
from ..output import (
    Spinner,
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cR,
    cY,
    err,
    hr,
    more_note,
    progress_bar,
    say,
    section,
)

CONSOLE_LIMIT = 30
PARITY_HEADERS = ["vm_name", "manager", "in_static", "in_dynamic", "status"]


def _groups_on(nsx, domain):
    base = nsx.base(domain)
    return base, nsx.get_all(p_groups(base, domain))


def _match(groups, name):
    n = name.lower()
    return [g for g in groups
            if str(g.get(F_DISPLAY_NAME, "")).lower() == n
            or str(g.get(F_ID, "")).lower() == n]


def resolve_pair(sessions, domain, static_name, dynamic_name):
    """(nsx, base, static_group, dynamic_group). Both from one manager."""
    candidates = []
    for nsx in sessions:
        try:
            base, groups = _groups_on(nsx, domain)
        except NsxError:
            continue
        s_hits = _match(groups, static_name)
        d_hits = _match(groups, dynamic_name)
        if s_hits and d_hits:
            candidates.append((nsx, base, s_hits[0], d_hits[0]))
    if not candidates:
        # Report which side is the problem rather than a bare "not found".
        found_s, found_d = [], []
        for nsx in sessions:
            try:
                _, groups = _groups_on(nsx, domain)
            except NsxError:
                continue
            if _match(groups, static_name):
                found_s.append(nsx.name)
            if _match(groups, dynamic_name):
                found_d.append(nsx.name)
        if not found_s and not found_d:
            raise NsxError("Neither '{}' nor '{}' found on any manager.".format(
                static_name, dynamic_name))
        if not found_s:
            raise NsxError("Static group '{}' not found on any manager "
                           "(dynamic found on: {}).".format(
                               static_name, ", ".join(found_d) or "none"))
        if not found_d:
            raise NsxError("Dynamic group '{}' not found on any manager "
                           "(static found on: {}).".format(
                               dynamic_name, ", ".join(found_s) or "none"))
        raise NsxError(
            "'{}' and '{}' exist but never on the same manager "
            "(static: {}; dynamic: {}). Comparing across managers would be "
            "meaningless.".format(static_name, dynamic_name,
                                  ", ".join(found_s), ", ".join(found_d)))
    if len(candidates) > 1:
        names = ", ".join(c[0].name for c in candidates)
        say("  {} both groups exist on {} -- using {}. "
            "Use --manager to pick another.".format(
                cBY("note:"), names, cC(candidates[0][0].name)))
    return candidates[0]


def act_parity(sessions, domain, static_name, dynamic_name, exporter):
    rows = []
    try:
        nsx, base, gs, gd = resolve_pair(sessions, domain, static_name, dynamic_name)
    except NsxError as e:
        err(str(e))
        exporter.stage("parity", PARITY_HEADERS, rows)
        return

    section("Parity Validation")
    say("  Manager : {}  [{}]".format(cC(nsx.name), ROLE_LABEL.get(nsx.role, "?")))
    say("  Static  : {}".format(cB(gs.get(F_DISPLAY_NAME, "?"))))
    say("  Dynamic : {}".format(cB(gd.get(F_DISPLAY_NAME, "?"))))
    with Spinner("Fetching members"):
        try:
            static_members = nsx.get_all(p_group_members(base, domain, gs.get(F_ID)))
            dynamic_members = nsx.get_all(p_group_members(base, domain, gd.get(F_ID)))
        except NsxError as e:
            err(str(e))
            exporter.stage("parity", PARITY_HEADERS, rows)
            return

    s_map = {str(m.get(F_DISPLAY_NAME, "")).lower(): m for m in static_members}
    d_map = {str(m.get(F_DISPLAY_NAME, "")).lower(): m for m in dynamic_members}
    only_static = sorted(set(s_map) - set(d_map))
    only_dynamic = sorted(set(d_map) - set(s_map))
    both = sorted(set(s_map) & set(d_map))

    say("\n  Static: {}  Dynamic: {}  Both: {}".format(
        cC(str(len(s_map))), cC(str(len(d_map))), cBG(str(len(both)))))
    say("  Only static: {} (need migration)  Only dynamic: {} (unexpected)".format(
        cBR(str(len(only_static))), cBY(str(len(only_dynamic)))))

    # Console listings are capped; every row is exported.
    if only_static:
        say("\n  {}:".format(cBR("Need migration")))
        for n in only_static[:CONSOLE_LIMIT]:
            say("    {} {}".format(cR("x"), s_map[n].get(F_DISPLAY_NAME, n)))
        more_note(CONSOLE_LIMIT, len(only_static))
    if only_dynamic:
        say("\n  {}:".format(cBY("Unexpected")))
        for n in only_dynamic[:CONSOLE_LIMIT]:
            say("    {} {}".format(cY("?"), d_map[n].get(F_DISPLAY_NAME, n)))
        more_note(CONSOLE_LIMIT, len(only_dynamic))

    for n in only_static:
        rows.append([s_map[n].get(F_DISPLAY_NAME, n), nsx.name, "yes", "no",
                     "needs_migration"])
    for n in only_dynamic:
        rows.append([d_map[n].get(F_DISPLAY_NAME, n), nsx.name, "no", "yes",
                     "unexpected"])
    for n in both:
        rows.append([s_map[n].get(F_DISPLAY_NAME, n), nsx.name, "yes", "yes",
                     "migrated"])

    say("\n  Parity: {}".format(progress_bar(len(both), len(s_map))))
    say("  {}".format(cD("{} row(s) staged for export".format(len(rows)))))
    hr()
    exporter.stage("parity", PARITY_HEADERS, rows)
