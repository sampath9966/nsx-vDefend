"""Declarative batch: `nsxctl apply changes.yaml`."""

from ..actions.author import act_apply_file
from ..errors import ConfigError, NsxError
from ..output import err
from . import add_command

APPLY_EXAMPLE = """file format (JSON always; YAML if PyYAML is installed):

  groups:
    - id: g-web
      display_name: Web tier
      criteria: 'tag:env=prod AND tag:tier=web'
    - id: g-retired
      state: absent

  rules:
    - id: allow-web-db
      policy: app-tier
      source: [g-web]
      destination: [g-db]
      services: [MySQL]
      action: ALLOW

Every entry needs an id. `state: absent` deletes; the default is present,
which creates the object or brings it into line if it already exists.
"""


def register_apply(sub, parents):
    p = add_command(
        sub, parents, "apply",
        "Apply a declarative file of groups and rules.",
        description="Bring NSX into line with a file describing the groups "
                    "and rules that should exist.\n\n"
                    "Dry run by default: the whole plan is printed as a "
                    "field-level diff, proposed rules are run through the "
                    "hygiene checks, and nothing is written without "
                    "--enable-writes. An entry that already matches NSX "
                    "produces no change at all.\n\n" + APPLY_EXAMPLE,
        epilog="examples:\n"
               "  nsxctl apply changes.yaml\n"
               "  nsxctl apply changes.json --enable-writes --yes")
    p.add_argument("file", help="Change file (JSON, or YAML with PyYAML).")
    p.set_defaults(func=cmd_apply)


def cmd_apply(args, ctx):
    try:
        result = act_apply_file(ctx, args.file, dry_run=not ctx.write_enabled,
                                force=args.force)
    except ConfigError as e:
        err(str(e))
        return 2
    except NsxError as e:
        err(str(e))
        return 2
    return 1 if result.failed else 0
