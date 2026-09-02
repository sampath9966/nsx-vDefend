"""VM tag inspection and interactive add/remove."""

from ..api import F_DISPLAY_NAME, F_EXTERNAL_ID, F_POWER_STATE, ROLE_LABEL, ROLE_LM
from ..errors import NsxError
from ..output import (
    Spinner,
    ask,
    cB,
    cBG,
    cBY,
    cC,
    cD,
    cG,
    confirm,
    cR,
    cY,
    err,
    hr,
    is_interactive,
    more_note,
    ok_msg,
    parallel_run,
    say,
    section,
    warn,
)
from ..render import fmt_tags, fmt_tags_plain, tags_of

CONSOLE_VM_LIMIT = 50
CONSOLE_MATCH_LIMIT = 40

TAGS_HEADERS = ["manager", "vm_name", "external_id", "power_state",
                "tag_scope", "tag_value"]
BY_TAG_HEADERS = ["manager", "vm_name", "external_id", "all_tags"]


def act_vm_tags(sessions, needle, exporter, taxonomy):
    rows = []
    total = 0
    for nsx in sessions:
        section("{}  [{}]".format(nsx.name, ROLE_LABEL.get(nsx.role, "?")))
        with Spinner("Searching VMs on {}".format(nsx.name)):
            try:
                matches = nsx.find_vms(needle)
            except NsxError as e:
                err(str(e))
                continue
        if not matches:
            say("  No VM matching '{}'".format(needle))
            continue
        total += len(matches)
        ordered = sorted(matches,
                         key=lambda v: str(v.get(F_DISPLAY_NAME, "")).lower())
        for i, vm in enumerate(ordered):
            name = vm.get(F_DISPLAY_NAME, "?")
            ext = vm.get(F_EXTERNAL_ID, "?")
            power = vm.get(F_POWER_STATE, "")
            pairs = tags_of(vm)
            # Export every match; only the console listing is capped.
            if pairs:
                for s, t in sorted(pairs):
                    rows.append([nsx.name, name, ext, power, s, t])
            else:
                rows.append([nsx.name, name, ext, power, "", ""])
            if i >= CONSOLE_VM_LIMIT:
                continue
            hr()
            say("  VM           : {}".format(cB(name)))
            say("  external_id  : {}".format(cD(ext)))
            if power:
                say("  power_state  : {}".format(
                    cG(power) if "ON" in power else cY(power)))
            say("  tags ({})    :".format(len(pairs)))
            if pairs:
                for s, t in sorted(pairs):
                    say("    {:30s} = {}".format(cC(s), t))
                clean, issues = taxonomy.validate_vm_tags(pairs)
                say("  taxonomy     : {}".format(
                    cBG("OK") if clean else cBY("{} issue(s)".format(len(issues)))))
                for issue in issues[:5]:
                    warn(issue)
            else:
                say("    {}".format(cD("(none)")))
        more_note(CONSOLE_VM_LIMIT, len(ordered))
    hr()
    say("  {} VM(s) across {} manager(s).".format(cC(str(total)), len(sessions)))
    exporter.stage("vm_tags", TAGS_HEADERS, rows)


def act_vms_by_tag(sessions, scope, tag, exporter):
    crit = " and ".join(x for x in [
        "scope='{}'".format(scope) if scope else "",
        "tag='{}'".format(tag) if tag else ""] if x)
    rows = []
    total = 0
    lms = [s for s in sessions if s.role == ROLE_LM]
    fetched = parallel_run(lms, lambda s: s.all_vms(), label="Scanning inventories")

    def hit(vm):
        for s, t in tags_of(vm):
            if scope and s.lower() != scope.lower():
                continue
            if tag and t.lower() != tag.lower():
                continue
            return True
        return False

    for nsx in lms:
        section(nsx.name)
        vms = fetched.get(nsx.name)
        if isinstance(vms, Exception):
            err(str(vms))
            continue
        if not vms:
            continue
        matches = [v for v in vms if hit(v)]
        total += len(matches)
        say("  {} of {} VM(s) carry {}".format(
            cC(str(len(matches))), len(vms), crit))
        for vm in sorted(matches,
                         key=lambda v: str(v.get(F_DISPLAY_NAME, "")).lower()):
            name = vm.get(F_DISPLAY_NAME, "?")
            say("    {:45s} {}".format(name, fmt_tags(tags_of(vm))))
            rows.append([nsx.name, name, vm.get(F_EXTERNAL_ID, ""),
                         fmt_tags_plain(tags_of(vm))])
    hr()
    say("  {} VM(s) across {} LM(s).".format(cC(str(total)), len(lms)))
    exporter.stage("vms_by_tag", BY_TAG_HEADERS, rows)


def _pick_scope(taxonomy):
    say("\n    {} (* = mandatory):".format(cB("Scopes")))
    scopes = taxonomy.all_scopes
    for i, s in enumerate(scopes, 1):
        mark = cBG("*") if s in taxonomy.mandatory else " "
        vals = taxonomy.values_for(s)
        hint = "  {}".format(cD(", ".join(vals))) if vals else ""
        say("      {:2d}. {} {}{}".format(i, mark, cC(s), hint))
    say("       0. {}".format(cD("custom")))
    c = ask("    Scope [# or name]: ", default="")
    if c.isdigit():
        idx = int(c)
        if idx == 0:
            return ask("    Custom scope: ", default="")
        if 1 <= idx <= len(scopes):
            return scopes[idx - 1]
    return c.lower().strip()


def _pick_value(taxonomy, scope):
    allowed = taxonomy.values_for(scope)
    if not allowed:
        return ask("    Tag value: ")
    say("\n    {} {}:".format(cB("Values for"), cC(scope)))
    for i, v in enumerate(allowed, 1):
        say("      {}. {}".format(i, v))
    say("      0. {}".format(cD("custom")))
    c = ask("    Value [# or name]: ", default="")
    if c.isdigit():
        idx = int(c)
        if idx == 0:
            return ask("    Custom value: ")
        if 1 <= idx <= len(allowed):
            return allowed[idx - 1]
    return c.lower().strip()


def _apply(nsx, vm, new_pairs, old_pairs, audit):
    """Re-read immediately before writing so a concurrent change by another
    operator is detected rather than silently overwritten."""
    fresh = nsx.refresh_vm(vm)
    if fresh is None:
        raise NsxError("VM disappeared from inventory before write.")
    live = sorted(tags_of(fresh))
    if live != sorted(old_pairs):
        raise NsxError(
            "tags changed on NSX since this plan was built "
            "(now: {}). Re-run to pick up the current state.".format(
                fmt_tags_plain(live)))
    nsx.update_vm_tags(fresh, new_pairs)
    audit.log("update_tags", nsx.name, fresh.get(F_DISPLAY_NAME, "?"),
              fresh.get(F_EXTERNAL_ID), old_pairs, new_pairs)


def act_manage_tags(sessions, needle, audit, write_enabled, taxonomy):
    if not write_enabled:
        say("  {}. Toggle with menu 12 or --enable-writes.".format(
            cBY("Writes disabled")))
        return
    if not is_interactive():
        err("Interactive tag management needs a terminal. "
            "Use --bulk-tag for scripted changes.")
        return
    found = []
    for nsx in sessions:
        try:
            for vm in nsx.find_vms(needle):
                found.append((nsx, vm))
        except NsxError as e:
            err(str(e))
    if not found:
        say("  No VM matching '{}'.".format(needle))
        return
    if len(found) == 1:
        nsx, vm = found[0]
    else:
        say("\n  {} matches:".format(len(found)))
        for i, (n, v) in enumerate(found[:CONSOLE_MATCH_LIMIT], 1):
            say("    {}. [{}] {:40s} {}".format(
                i, cC(n.name), v.get(F_DISPLAY_NAME, "?"), fmt_tags(tags_of(v))))
        more_note(CONSOLE_MATCH_LIMIT, len(found), "narrow the search")
        say("    b. back")
        while True:
            c = ask("  Which VM? ")
            if c.isdigit() and 1 <= int(c) <= min(len(found), CONSOLE_MATCH_LIMIT):
                nsx, vm = found[int(c) - 1]
                break
            say("    Invalid.")

    while True:
        current = nsx.refresh_vm(vm) or vm
        pairs = sorted(tags_of(current))
        hr()
        say("  VM  : {}   [{}]".format(
            cB(current.get(F_DISPLAY_NAME, "?")), cC(nsx.name)))
        say("  tags ({}):".format(len(pairs)))
        for i, (s, t) in enumerate(pairs, 1):
            flag = "  {}".format(cBY("!!")) if taxonomy.validate_tag(s, t) else ""
            say("    {:2d}. {:30s} = {}{}".format(i, cC(s), t, flag))
        if not pairs:
            say("      {}".format(cD("(none)")))
        hr()
        say("    1. {}".format(cG("Add")))
        say("    2. {}".format(cR("Remove")))
        say("    b. Back")
        c = ask("  Choice: ", allow_back=False).lower()
        if c == "b":
            return
        if c == "1":
            scope = _pick_scope(taxonomy)
            if not scope:
                say("    Scope required.")
                continue
            value = _pick_value(taxonomy, scope)
            if not value:
                say("    Value required.")
                continue
            warnings = taxonomy.validate_tag(scope, value)
            if warnings:
                for w in warnings:
                    warn(w)
                if not confirm("    Proceed? [y/N]: "):
                    continue
            if (scope, value) in pairs:
                say("    Already has it.")
                continue
            new = pairs + [(scope, value)]
            say("\n    Result ({} tags):".format(len(new)))
            for s, t in sorted(new):
                mark = "  {}".format(cBG("<-- NEW")) if (s, t) == (scope, value) else ""
                say("      {:30s} = {}{}".format(cC(s), t, mark))
            if not confirm("    Apply? [y/N]: "):
                say("    Cancelled.")
                continue
            try:
                _apply(nsx, current, new, pairs, audit)
                ok_msg("Applied.")
            except NsxError as e:
                err(str(e))
        elif c == "2":
            if not pairs:
                say("    No tags.")
                continue
            sel = ask("    Tag # to remove: ")
            if not sel.isdigit() or not (1 <= int(sel) <= len(pairs)):
                say("    Invalid.")
                continue
            victim = pairs[int(sel) - 1]
            new = [p for p in pairs if p != victim]
            say("\n    Removing: {}".format(cR("{}={}".format(*victim))))
            say("    {}: may affect dynamic groups and DFW rules.".format(cBY("NOTE")))
            if not confirm("    Apply? [y/N]: "):
                continue
            try:
                _apply(nsx, current, new, pairs, audit)
                ok_msg("Removed.")
            except NsxError as e:
                err(str(e))
