"""Translation from the pre-4.0 flag interface to `nsxctl <noun> <verb>`.

Old flags keep working. Each one is rewritten to its subcommand, a single
warning naming the replacement goes to **stderr** -- never stdout, so piping
`--json` still yields a parseable document -- and the command runs.

The old interface allowed several actions in one invocation
(`--groups --dashboard --out-csv report.csv`). Subcommands are one per run, so
a multi-action invocation translates into a *sequence* of subcommands sharing
one exporter, which preserves the old behaviour including the multi-file
export. Breaking that would silently change what someone's cron job produces.
"""

import argparse

# old flag -> (subcommand words, how to consume its value)
#   "flag"     : no value
#   "value"    : one positional value
#   "two"      : two positional values
SIMPLE = {
    "init": (["init"], "flag"),
    "verify": (["status"], "flag"),
    "list_managers": (["managers"], "flag"),
    "dashboard": (["compliance"], "flag"),
    "audit_log": (["audit", "list"], "flag"),
    "vm_tags": (["tag", "list"], "value"),
    "reverse_lookup": (["impact"], "value"),
    "change_ticket": (["tag", "ticket"], "value"),
    "parity": (["parity"], "two"),
}

# Presentation order, so a multi-action run is deterministic and matches the
# order the old cli.py executed them in.
ORDER = ["list_managers", "verify", "groups", "vm_tags", "vms_by_tag",
         "dashboard", "parity", "reverse_lookup", "change_ticket",
         "audit_log", "bulk_tag", "init", "set_credentials"]

REPLACEMENT = {
    "--init": "nsxctl init",
    "--verify": "nsxctl status",
    "--list-managers": "nsxctl managers",
    "--set-credentials": "nsxctl login",
    "--groups": "nsxctl group list",
    "--vm-tags": "nsxctl tag list VM",
    "--vms-by-tag": "nsxctl tag find --scope S --tag T",
    "--bulk-tag": "nsxctl tag apply FILE",
    "--change-ticket": "nsxctl tag ticket FILE",
    "--reverse-lookup": "nsxctl impact VM",
    "--parity": "nsxctl parity STATIC DYNAMIC",
    "--dashboard": "nsxctl compliance",
    "--audit-log": "nsxctl audit list",
}


def _legacy_parser():
    """Recognises only the old action flags and the old action-scoped options.

    Global flags are deliberately absent so `parse_known_args` hands them back
    untouched, to be passed through to the new parser.
    """
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--init", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--list-managers", action="store_true")
    p.add_argument("--set-credentials", action="store_true")
    p.add_argument("--dashboard", action="store_true")
    p.add_argument("--audit-log", action="store_true")
    p.add_argument("--groups", action="store_true")
    p.add_argument("--vms-by-tag", action="store_true")
    p.add_argument("--vm-tags", default=None)
    p.add_argument("--reverse-lookup", default=None)
    p.add_argument("--bulk-tag", default=None)
    p.add_argument("--change-ticket", default=None)
    p.add_argument("--parity", nargs=2, default=None)
    # Options that used to be global but now belong to a specific command.
    p.add_argument("--contains", default=None)
    p.add_argument("--members", action="store_true")
    p.add_argument("--scope", default=None)
    p.add_argument("--tag", default=None)
    p.add_argument("--dry-run", action="store_true")
    return p


LEGACY_FLAGS = frozenset(REPLACEMENT) | {
    "--contains", "--members", "--scope", "--tag", "--dry-run"}


def uses_legacy(argv):
    """True when argv contains any pre-4.0 flag."""
    for token in argv:
        head = token.split("=", 1)[0]
        if head in LEGACY_FLAGS:
            return True
    return False


def translate_legacy_argv(argv):
    """(list_of_new_argv, warnings). Raises nothing; unknown args pass through.

    Returns ([], warnings) when a legacy flag was present but named no action
    (for example `--scope` on its own) -- the caller reports that.
    """
    parser = _legacy_parser()
    try:
        known, passthrough = parser.parse_known_args(argv)
    except SystemExit:
        # Malformed legacy input: let the new parser produce the error.
        return None, []

    warnings = []
    commands = []

    def warn_for(flag):
        replacement = REPLACEMENT.get(flag)
        if replacement:
            warnings.append(
                "{} is deprecated and will be removed in 5.0. "
                "use: {}".format(flag, replacement))

    for key in ORDER:
        value = getattr(known, key, None)
        if key == "set_credentials":
            if value:
                warn_for("--set-credentials")
                commands.append(["login"] + list(passthrough))
            continue
        if key == "groups":
            if value:
                warn_for("--groups")
                extra = []
                if known.contains:
                    extra += ["--contains", known.contains]
                if known.members:
                    extra += ["--members"]
                commands.append(["group", "list"] + extra + list(passthrough))
            continue
        if key == "vms_by_tag":
            if value:
                warn_for("--vms-by-tag")
                extra = []
                if known.scope:
                    extra += ["--scope", known.scope]
                if known.tag:
                    extra += ["--tag", known.tag]
                commands.append(["tag", "find"] + extra + list(passthrough))
            continue
        if key == "bulk_tag":
            if value:
                warn_for("--bulk-tag")
                extra = ["--dry-run"] if known.dry_run else []
                commands.append(["tag", "apply", value] + extra
                                + list(passthrough))
            continue
        if key in SIMPLE:
            words, kind = SIMPLE[key]
            flag = "--" + key.replace("_", "-")
            if kind == "flag" and value:
                warn_for(flag)
                commands.append(list(words) + list(passthrough))
            elif kind == "value" and value:
                warn_for(flag)
                commands.append(list(words) + [value] + list(passthrough))
            elif kind == "two" and value:
                warn_for(flag)
                commands.append(list(words) + list(value) + list(passthrough))

    return commands, warnings
