"""Audit log viewing and single-entry undo."""

from ..api import F_EXTERNAL_ID
from ..errors import NsxError
from ..output import (
    ask,
    cB,
    cBY,
    cC,
    cD,
    cG,
    confirm,
    cR,
    err,
    hr,
    is_interactive,
    ok_msg,
    say,
)
from ..render import fmt_tags_plain, tags_of

AUDIT_HEADERS = ["timestamp", "user", "manager", "action", "vm_name",
                  "added", "removed", "status"]


def _pairs(entries):
    return [(t.get("scope", ""), t.get("tag", "")) for t in (entries or [])]


def act_audit_log(audit, sessions, write_enabled, exporter=None, limit=20):
    entries = audit.last_n(limit)
    if not entries:
        say("  Audit log empty.")
        if exporter is not None:
            exporter.stage("audit_log", AUDIT_HEADERS, [])
        return
    say("\n  Last {} entries:".format(cC(str(len(entries)))))
    hr()
    rows = []
    for i, e in enumerate(entries, 1):
        before = _pairs(e.get("tags_before"))
        after = _pairs(e.get("tags_after"))
        added = [p for p in after if p not in before]
        removed = [p for p in before if p not in after]
        say("  {:5s} {}  {:30s}  [{}]".format(
            cD(str(i) + "."), cD(str(e.get("timestamp", "?"))[:19]),
            e.get("vm_display_name", "?"), cC(e.get("manager", "?"))))
        if added:
            say("        {}".format(cG("+ " + fmt_tags_plain(added))))
        if removed:
            say("        {}".format(cR("- " + fmt_tags_plain(removed))))
        rows.append([e.get("timestamp", ""), e.get("user", ""),
                     e.get("manager", ""), e.get("action", ""),
                     e.get("vm_display_name", ""), fmt_tags_plain(added),
                     fmt_tags_plain(removed), e.get("status", "")])
    if exporter is not None:
        exporter.stage("audit_log", AUDIT_HEADERS, rows)

    if not write_enabled:
        say("\n  {}.".format(cBY("Undo needs write mode")))
        return
    if not is_interactive():
        return
    hr()
    choice = ask("  Undo entry # (or b): ")
    if not choice.isdigit() or not (1 <= int(choice) <= len(entries)):
        say("  Cancelled.")
        return
    target = entries[int(choice) - 1]
    restore_to = _pairs(target.get("tags_before"))
    vm_name = target.get("vm_display_name", "?")
    mgr_name = target.get("manager", "?")
    ext = target.get("vm_external_id", "?")

    nsx = next((s for s in sessions if s.name == mgr_name), None)
    if not nsx:
        err("Manager '{}' is not in this session.".format(mgr_name))
        return
    vm = nsx.get_vm_by_external_id(ext)
    if not vm:
        err("VM '{}' (external_id {}) not found on {}.".format(
            vm_name, ext, mgr_name))
        return
    current = sorted(tags_of(vm))
    say("\n  Restore '{}' on [{}]".format(cB(vm_name), cC(mgr_name)))
    say("    current : {}".format(fmt_tags_plain(current)))
    say("    restore : {}".format(fmt_tags_plain(sorted(restore_to))))
    if current == sorted(restore_to):
        say("  Already in that state -- nothing to undo.")
        return
    if not confirm("  Apply undo? [y/N]: "):
        say("  Cancelled.")
        return
    try:
        fresh = nsx.refresh_vm(vm) or vm
        nsx.update_vm_tags(fresh, restore_to)
        audit.log("undo", nsx.name, vm_name, fresh.get(F_EXTERNAL_ID),
                  current, restore_to, detail="undo of {}".format(
                      target.get("timestamp", "?")))
        ok_msg("Undo applied.")
    except NsxError as e:
        err(str(e))
