"""Drift from the interactive menu.

The CLI path lives in commands/snapshot.py; this is the thin menu wrapper so
option 16 does not need the argparse namespace the command handlers expect.
"""


from ..diff import (
    DRIFT_HEADERS,
    diff_rows,
    diff_snapshots,
    drift_findings,
    summarise_diff,
)
from ..errors import NsxError
from ..output import cB, cBG, cBR, cBY, cC, cD, err, hr, say, section, table
from ..snapshot import capture_snapshot, list_snapshots, load_snapshot

MENU_CHANGE_LIMIT = 25


def act_drift_menu(ctx):
    """Compare the newest snapshot against live NSX."""
    section("CONFIGURATION DRIFT")
    existing = list_snapshots()
    if not existing:
        say("  No snapshots yet.")
        say("  Take one first: {}".format(cC("nsxctl snapshot save")))
        return
    newest = existing[0]
    say("  Snapshot : {}  ({})".format(cC(newest["name"]), newest["taken"]))
    say("  Against  : {}".format(cC("live NSX")))
    try:
        before = load_snapshot(newest["root"])
        after = capture_snapshot(
            ctx.sessions, ctx.domain,
            with_tags=bool(before["manifest"].get("with_tags")))
    except NsxError as e:
        err(str(e))
        return

    changes = diff_snapshots(before, after)
    ctx.exporter.stage("drift", DRIFT_HEADERS, diff_rows(changes))
    ctx.exporter.stage_findings("config_drift", drift_findings(changes))
    hr()
    if not changes:
        say("  {} configuration matches the snapshot exactly.".format(
            cBG("No drift:")))
        return

    counts = summarise_diff(changes)
    table(["Change", "Count"],
          [[k, str(counts[k])] for k in
           ("added", "removed", "modified", "security", "cosmetic")
           if counts.get(k)], indent=4)
    for change in changes[:MENU_CHANGE_LIMIT]:
        colour = cBR if change.impact == "security" else cD
        who = " {}".format(cD("by " + change.changed_by)) \
            if change.changed_by else ""
        say("\n  {} {} {}{}".format(
            cBY(change.status.upper()), cB(str(change.name)),
            colour("[{}]".format(change.impact)), who))
        for field in change.fields[:8]:
            say("      {}: {} -> {}".format(
                cC(field.field), cD(str(field.before)), field.after))
    if len(changes) > MENU_CHANGE_LIMIT:
        say("\n  {}".format(cD("... +{} more (full set in export)".format(
            len(changes) - MENU_CHANGE_LIMIT))))
    hr()
