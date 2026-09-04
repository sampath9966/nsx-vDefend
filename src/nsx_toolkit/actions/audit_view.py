"""Audit log viewing and single-entry undo.

Two eras of entry live in the log -- VM tag changes, and the group and rule
changes authoring writes -- so everything here reads the normalised shape
`audit.normalise_entry` produces and dispatches undo on `object_type`. A log
written before authoring existed lists and undoes exactly as it always did.

**Undo is asymmetric, and the messages say which case they are in.** Undoing
a create is a delete and undoing a modify is a write of the before-body: both
exact. Undoing a delete recreates an object whose references may have been
cleaned up underneath it, and that cannot be guaranteed -- a snapshot restore
is the reliable way back from a delete.
"""

from ..api import F_EXTERNAL_ID
from ..audit import OBJ_GROUP, OBJ_RULE, OBJ_VM_TAGS, summarise_entry
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
from .author import undo_object_entry

AUDIT_HEADERS = ["timestamp", "user", "manager", "action", "object_type",
                 "object", "added", "removed", "status"]

UNDOABLE_OBJECTS = (OBJ_GROUP, OBJ_RULE)


def _entry_row(entry, added, removed):
    return [entry["timestamp"], entry["user"], entry["manager"],
            entry["action"], entry["object_type"], entry["object_name"],
            fmt_tags_plain(added) if added else "",
            fmt_tags_plain(removed) if removed else "",
            entry["status"]]


def _print_entry(index, entry):
    say("  {:5s} {}  {:28s}  {}  [{}]".format(
        cD(str(index) + "."), cD(str(entry["timestamp"])[:19]),
        str(entry["object_name"])[:28], cD(entry["object_type"]),
        cC(entry["manager"])))
    if entry["object_type"] == OBJ_VM_TAGS:
        added, removed = summarise_entry(entry)
        if added:
            say("        {}".format(cG("+ " + fmt_tags_plain(added))))
        if removed:
            say("        {}".format(cR("- " + fmt_tags_plain(removed))))
        return
    if entry["before"] is None:
        say("        {}".format(cG("created")))
    elif entry["after"] is None:
        say("        {}".format(cR("deleted")))
    else:
        say("        {}".format(cBY("modified")))
    if entry["status"] and entry["status"] != "success":
        say("        {} {}".format(cR(entry["status"]), cD(entry["detail"])))


def act_audit_log(audit, sessions, write_enabled, exporter=None, limit=20,
                  domain="default"):
    entries = audit.last_n_normalised(limit)
    if not entries:
        say("  Audit log empty.")
        if exporter is not None:
            exporter.stage("audit_log", AUDIT_HEADERS, [])
        return
    say("\n  Last {} entries:".format(cC(str(len(entries)))))
    hr()
    rows = []
    for index, entry in enumerate(entries, 1):
        _print_entry(index, entry)
        added, removed = summarise_entry(entry)
        rows.append(_entry_row(entry, added, removed))
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
    try:
        if target["object_type"] == OBJ_VM_TAGS:
            _undo_vm_tags(target, sessions, audit)
        elif target["object_type"] in UNDOABLE_OBJECTS:
            undo_object_entry(target, sessions, domain, audit)
        else:
            err("Entries of type '{}' cannot be undone.".format(
                target["object_type"]))
    except NsxError as e:
        err(str(e))


def _undo_vm_tags(target, sessions, audit):
    """The original tag undo, unchanged in behaviour.

    Reads `before`/`after` off the normalised entry, which for a tag entry
    comes from `tags_before`/`tags_after` whether it was written this release
    or three releases ago.
    """
    restore_to = target["before"] or []
    raw = target["raw"]
    vm_name = raw.get("vm_display_name", target["object_name"])
    mgr_name = target["manager"]
    ext = raw.get("vm_external_id", "?")

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
    fresh = nsx.refresh_vm(vm) or vm
    nsx.update_vm_tags(fresh, restore_to)
    audit.log("undo", nsx.name, vm_name, fresh.get(F_EXTERNAL_ID),
              current, restore_to, detail="undo of {}".format(
                  target.get("timestamp", "?")))
    ok_msg("Undo applied.")
