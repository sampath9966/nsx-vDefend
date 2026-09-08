"""Snapshot and drift: `nsxctl snapshot ...` and `nsxctl drift`.

Both verbs run one engine. `snapshot diff` reads both sides from disk;
`drift` captures the "after" side from live NSX in memory. Nothing else
differs, so the two can never disagree about what counts as a change.
"""

import os

from ..actions.author import act_restore
from ..diff import (
    DRIFT_HEADERS,
    at_impact,
    diff_rows,
    diff_snapshots,
    drift_findings,
    summarise_diff,
)
from ..errors import ConfigError, NsxError
from ..output import cB, cBG, cBR, cBY, cC, cD, cG, err, hr, ok_msg, say, section, table
from ..paths import DEFAULT_SNAPSHOT_DIR
from ..report import write_report
from ..snapshot import (
    capture_snapshot,
    describe_snapshot,
    list_snapshots,
    load_snapshot,
    resolve_snapshot,
    save_snapshot,
)
from . import add_action, add_command

CONSOLE_CHANGE_LIMIT = 40
IMPACT_COLOUR = {"security": cBR, "cosmetic": cD}
STATUS_COLOUR = {"added": cBG, "removed": cBR, "modified": cBY}
# "policies".rstrip("s") gives "policie"; spell the singulars out.
KIND_LABEL = {"groups": "group", "policies": "policy", "rules": "rule",
              "tags": "tags"}


def register_snapshot(sub, parents):
    p = add_command(
        sub, parents, "snapshot",
        "Capture and compare NSX configuration.",
        description="Snapshots are written as a directory of one JSON file "
                    "per object, with volatile fields stripped -- so `git "
                    "diff` on the tree shows real configuration changes and "
                    "nothing else.")
    ssub = p.add_subparsers(dest="snapshot_action", metavar="<action>")

    save = ssub.add_parser(
        "save", parents=parents, help="Capture the current configuration.",
        description="Read groups, policies and rules across every connected "
                    "manager and write them as a snapshot.",
        epilog="examples:\n"
               "  nsxctl snapshot save\n"
               "  nsxctl snapshot save approved-2026-Q1\n"
               "  nsxctl snapshot save --with-tags")
    save.add_argument("name", nargs="?",
                      help="Snapshot name (default: domain plus timestamp).")
    save.add_argument("--with-tags", action="store_true",
                      help="Also capture VM tags. Off by default because "
                           "retagging is routine churn that would bury a "
                           "real rule change.")
    save.add_argument("--snapshot-dir", metavar="DIR",
                      help="Where snapshots live (default: {}).".format(
                          DEFAULT_SNAPSHOT_DIR))
    save.set_defaults(func=cmd_snapshot_save)

    ls = ssub.add_parser("list", parents=parents,
                         help="List the snapshots taken so far.")
    ls.add_argument("--snapshot-dir", metavar="DIR")
    ls.set_defaults(func=cmd_snapshot_list, needs_inventory=False,
                    needs_sessions=False)

    show = ssub.add_parser("show", parents=parents,
                           help="Show one snapshot's manifest.")
    show.add_argument("name")
    show.add_argument("--snapshot-dir", metavar="DIR")
    show.set_defaults(func=cmd_snapshot_show, needs_inventory=False,
                      needs_sessions=False)

    diff = ssub.add_parser(
        "diff", parents=parents, help="Compare two snapshots.",
        description="Compare two stored snapshots. Neither needs a live NSX.",
        epilog="example:\n  nsxctl snapshot diff approved current")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--snapshot-dir", metavar="DIR")
    diff.add_argument("--fail-on-drift", choices=("security", "any"),
                      metavar="LEVEL",
                      help="Exit 1 when changes at this level exist "
                           "(security | any).")
    diff.set_defaults(func=cmd_snapshot_diff, needs_inventory=False,
                      needs_sessions=False)

    rs = add_action(
        ssub, parents, "restore", "Put a snapshot's configuration back.",
        description="Bring live NSX back into line with a stored snapshot, "
                    "one object at a time through the same plan-then-apply "
                    "path as `nsxctl rule edit`.\n\n"
                    "Each object gets a field-level diff you can read, a "
                    "_revision check that refuses to overwrite a concurrent "
                    "edit, and its own audit entry -- so a restore is "
                    "reviewable and individually undoable, not a blind push "
                    "of a whole tree.\n\n"
                    "Objects that exist now but not in the snapshot are LEFT "
                    "ALONE unless --prune is given: a snapshot records what "
                    "was there, it does not assert that nothing else may "
                    "exist, and a group created legitimately since is not "
                    "drift to be erased.\n\n"
                    "Dry run by default.",
        epilog="examples:\n"
               "  nsxctl snapshot restore approved\n"
               "  nsxctl snapshot restore approved --enable-writes\n"
               "  nsxctl snapshot restore approved --prune --enable-writes")
    rs.add_argument("name", nargs="?", help="Snapshot name or path.")
    rs.add_argument("--snapshot-dir", metavar="DIR")
    rs.add_argument("--prune", action="store_true",
                    help="Also DELETE objects that exist now but are not in "
                         "the snapshot.")
    rs.set_defaults(func=cmd_snapshot_restore)

    p.set_defaults(func=_snapshot_needs_action)

    d = add_command(
        sub, parents, "drift",
        "Has anything changed since the last snapshot?",
        description="Compare a snapshot against live NSX. With no name, uses "
                    "the most recent snapshot.\n\n"
                    "Changes are classified security or cosmetic, so a "
                    "scheduled check can stay quiet about a renamed policy "
                    "and be loud about a new any-any rule.",
        epilog="examples:\n"
               "  nsxctl drift\n"
               "  nsxctl drift approved-2026-Q1\n"
               "  nsxctl drift --fail-on-drift security   # for cron\n"
               "  nsxctl drift --out-html drift.html")
    d.add_argument("name", nargs="?",
                   help="Snapshot to compare against (default: newest).")
    d.add_argument("--snapshot-dir", metavar="DIR")
    d.add_argument("--fail-on-drift", choices=("security", "any"),
                   metavar="LEVEL",
                   help="Exit 1 when changes at this level exist "
                        "(security | any).")
    d.set_defaults(func=cmd_drift)


def _snapshot_needs_action(args, ctx):
    err("Specify what to do: nsxctl snapshot save|list|show|diff")
    return 2


def _snapshot_dir(args):
    return getattr(args, "snapshot_dir", None) or DEFAULT_SNAPSHOT_DIR


# === save / list / show ===
def cmd_snapshot_save(args, ctx):
    section("CAPTURE CONFIGURATION SNAPSHOT")
    snapshot = capture_snapshot(ctx.sessions, args.domain,
                                with_tags=args.with_tags)
    root = save_snapshot(snapshot, args.name, root_dir=_snapshot_dir(args))
    describe_snapshot(snapshot)
    ok_msg("Snapshot: {}".format(root))
    say("\n  {} check for changes later with:".format(cD("next:")))
    say("    {}".format(cC("nsxctl drift")))
    return 0


def cmd_snapshot_list(args, ctx):
    found = list_snapshots(_snapshot_dir(args))
    section("SNAPSHOTS")
    if not found:
        say("  None yet in {}.".format(_snapshot_dir(args)))
        say("  Take one with: {}".format(cC("nsxctl snapshot save")))
        return 0
    table(["Name", "Taken", "Domain", "Objects"],
          [[cC(item["name"]), item["taken"], item["domain"],
            ", ".join("{} {}".format(v, k)
                      for k, v in sorted(item["counts"].items()) if v)]
           for item in found])
    return 0


def cmd_snapshot_show(args, ctx):
    root = resolve_snapshot(args.name, _snapshot_dir(args))
    snapshot = load_snapshot(root)
    section("SNAPSHOT {}".format(snapshot["manifest"].get("name", args.name)))
    say("  Root     : {}".format(root))
    describe_snapshot(snapshot)
    return 0


# === diff / drift ===
def cmd_snapshot_restore(args, ctx):
    try:
        root = resolve_snapshot(args.name, args.snapshot_dir)
        snapshot = load_snapshot(root)
    except NsxError as e:
        err(str(e))
        return 2
    try:
        result = act_restore(ctx, snapshot,
                             dry_run=not ctx.write_enabled,
                             force=args.force, prune=args.prune)
    except (NsxError, ConfigError) as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0


def cmd_snapshot_diff(args, ctx):
    directory = _snapshot_dir(args)
    before = load_snapshot(resolve_snapshot(args.before, directory))
    after = load_snapshot(resolve_snapshot(args.after, directory))
    section("SNAPSHOT DIFF")
    say("  Before : {}  ({})".format(args.before,
                                     before["manifest"].get("taken", "?")))
    say("  After  : {}  ({})".format(args.after,
                                     after["manifest"].get("taken", "?")))
    return _report(args, ctx, before, after)


def cmd_drift(args, ctx):
    directory = _snapshot_dir(args)
    root = resolve_snapshot(args.name, directory)
    before = load_snapshot(root)
    section("CONFIGURATION DRIFT")
    say("  Snapshot : {}  ({})".format(
        os.path.basename(root), before["manifest"].get("taken", "?")))
    say("  Against  : {}".format(cC("live NSX")))
    # The "after" side is captured in memory rather than written, so a drift
    # check never leaves a snapshot behind as a side effect.
    after = capture_snapshot(
        ctx.sessions, args.domain,
        with_tags=bool(before["manifest"].get("with_tags")))
    return _report(args, ctx, before, after)


def _report(args, ctx, before, after):
    changes = diff_snapshots(before, after)
    counts = summarise_diff(changes)
    ctx.exporter.stage("drift", DRIFT_HEADERS, diff_rows(changes))
    ctx.exporter.stage_findings("config_drift", drift_findings(changes))
    hr()

    if not changes:
        say("  {} configuration matches the snapshot exactly.".format(
            cBG("No drift:")))
        return 0

    table(["Change", "Count"],
          [[STATUS_COLOUR.get(k, cD)(k), str(counts[k])]
           for k in ("added", "removed", "modified") if counts.get(k)]
          + [[IMPACT_COLOUR.get(k, cD)(k), str(counts[k])]
             for k in ("security", "cosmetic") if counts.get(k)], indent=4)

    for change in changes[:CONSOLE_CHANGE_LIMIT]:
        who = ""
        if change.changed_by:
            who = "   {}".format(cD("by {}".format(change.changed_by)))
        say("\n  {} {} {} {}{}".format(
            STATUS_COLOUR.get(change.status, cD)(change.status.upper()),
            cD(KIND_LABEL.get(change.kind, change.kind)), cB(str(change.name)),
            IMPACT_COLOUR.get(change.impact, cD)("[{}]".format(change.impact)),
            who))
        for field in change.fields[:12]:
            if field.kind == "added":
                say("      {} {}".format(cG("+"), _line(field.field,
                                                        field.after)))
            elif field.kind == "removed":
                say("      {} {}".format(cBR("-"), _line(field.field,
                                                         field.before)))
            else:
                say("      {}: {} -> {}".format(
                    cC(field.field), cD(_short(field.before)),
                    _short(field.after)))
        if len(change.fields) > 12:
            say("      {}".format(cD("... +{} more field(s)".format(
                len(change.fields) - 12))))
    if len(changes) > CONSOLE_CHANGE_LIMIT:
        say("\n  {}".format(cD("... +{} more object(s) (full set in "
                               "export)".format(
                                   len(changes) - CONSOLE_CHANGE_LIMIT))))

    if args.out_html:
        path = write_report(
            args.out_html, "Configuration Drift",
            "{} object(s) changed".format(len(changes)),
            notes=[
                "Volatile fields (revision, timestamps, realization ids) are "
                "stripped before comparison, so everything listed here is a "
                "real configuration change.",
                "security means the change can alter what traffic is "
                "permitted. cosmetic means only a name, description or note "
                "changed.",
            ],
            tiles=[(k, counts.get(k, 0))
                   for k in ("added", "removed", "modified", "security")],
            sections=[("Changes", DRIFT_HEADERS, diff_rows(changes))])
        ok_msg("HTML report: {}".format(path))

    hr()
    if args.fail_on_drift:
        blocking = at_impact(changes, args.fail_on_drift)
        if blocking:
            say("  {} {} change(s) at level '{}'.".format(
                cBR("DRIFT:"), len(blocking), args.fail_on_drift))
            return 1
        say("  {} no changes at level '{}'.".format(
            cBG("PASS:"), args.fail_on_drift))
    return 0


def _short(value, limit=60):
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _line(field, value):
    return "{}: {}".format(field, _short(value))
