"""The `nsxctl <noun> <verb>` command tree.

This package is the CLI surface; `actions/` remains the logic layer and is
called unchanged. Each module registers its own subparsers and sets a handler
via `set_defaults(func=...)`.

Global flags work on BOTH sides of the subcommand -- `nsxctl --json compliance`
and `nsxctl compliance --json` are equivalent -- which argparse does not give
you for free. A shared parent parser declares them with
`default=argparse.SUPPRESS` so an unspecified flag leaves no key in the
namespace at all; the top-level value therefore survives the subparser pass,
and `apply_global_defaults` fills in what neither side supplied.
"""

import argparse

from ..api import DEFAULT_DOMAIN
from ..version import TOOL_NAME, TOOL_TAGLINE, VERSION, VERSION_DATE

PROG = "nsxctl"

# Defaults live here rather than on the arguments, because the arguments use
# SUPPRESS so that "not given" is distinguishable from "given the default".
GLOBAL_DEFAULTS = {
    "inventory": None,
    "taxonomy": None,
    "manager": None,
    "all_lm": False,
    "domain": DEFAULT_DOMAIN,
    "ca_bundle": None,
    "store": "auto",
    "json": False,
    "no_color": False,
    "non_interactive": False,
    "debug": False,
    "yes": False,
    "enable_writes": False,
    "force": False,
    "out_csv": None,
    "out_json": None,
    "out_html": None,
}

EPILOG = """
getting started:
  nsxctl init                       guided setup: managers, credentials, a check
  nsxctl status                     can I reach and authenticate everywhere?
  nsxctl                            interactive menu

everyday:
  nsxctl compliance                 tagging posture across every Local Manager
  nsxctl tag find --scope env --tag prod
  nsxctl impact web-prod-01         what breaks if I retag this VM
  nsxctl group list --contains web
  nsxctl tag apply changes.csv      dry run; add --enable-writes --yes to commit

Run `nsxctl <command> --help` for a command's options and examples.
"""


def add_global_args(parser):
    """Flags accepted before or after the subcommand."""
    cfg = parser.add_argument_group("configuration")
    cfg.add_argument("--inventory", metavar="PATH", default=argparse.SUPPRESS,
                     help="Inventory file (default: ./inventory.json, then "
                          "~/.nsx_toolkit/inventory.json).")
    cfg.add_argument("--taxonomy", metavar="PATH", default=argparse.SUPPRESS,
                     help="Tag taxonomy file (JSON, or YAML with PyYAML).")
    cfg.add_argument("--manager", metavar="NAME", default=argparse.SUPPRESS,
                     help="Target one manager by name.")
    cfg.add_argument("--all-lm", action="store_true", default=argparse.SUPPRESS,
                     help="Target every Local Manager.")
    cfg.add_argument("--domain", metavar="NAME", default=argparse.SUPPRESS,
                     help="NSX domain (default: {}).".format(DEFAULT_DOMAIN))
    cfg.add_argument("--ca-bundle", metavar="PATH", default=argparse.SUPPRESS,
                     help="CA bundle for TLS verification on all managers.")
    cfg.add_argument("--store", choices=("auto", "keyring", "plaintext", "none"),
                     default=argparse.SUPPRESS,
                     help="Where prompted credentials are saved.")

    wr = parser.add_argument_group("writes")
    wr.add_argument("--enable-writes", action="store_true",
                    default=argparse.SUPPRESS,
                    help="Permit changes. Without it everything is read-only.")
    wr.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS,
                    help="Skip confirmation prompts. Required to write "
                         "non-interactively.")
    wr.add_argument("--force", action="store_true", default=argparse.SUPPRESS,
                    help="Apply even if state changed since the plan was built.")

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                     help="Structured JSON on stdout. Implies "
                          "--non-interactive.")
    out.add_argument("--out-csv", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write results to CSV.")
    out.add_argument("--out-json", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write results to JSON.")
    out.add_argument("--out-html", metavar="PATH", default=argparse.SUPPRESS,
                     help="Write a shareable HTML report where supported.")
    out.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                     help="Disable colored output.")
    out.add_argument("--non-interactive", action="store_true",
                     default=argparse.SUPPRESS,
                     help="Never prompt; fail rather than ask.")
    out.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                     help="Log HTTP method, URL, status and timing to stderr.")
    return parser


def apply_global_defaults(args):
    """Fill in globals neither the top level nor the subcommand supplied."""
    for key, value in GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    return args


def build_parser():
    from .analysis import register_analysis
    from .group import register_group
    from .rule import register_rule
    from .setup import register_setup
    from .shell import register_shell
    from .tag import register_tag

    global_parent = argparse.ArgumentParser(add_help=False)
    add_global_args(global_parent)

    parser = argparse.ArgumentParser(
        prog=PROG,
        parents=[global_parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="{} v{} -- {}".format(TOOL_NAME, VERSION, TOOL_TAGLINE),
        epilog=EPILOG)
    parser.add_argument(
        "--version", action="version",
        version="{} v{} ({})".format(TOOL_NAME, VERSION, VERSION_DATE))

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    parents = [global_parent]
    for register in (register_setup, register_group, register_tag,
                     register_rule, register_analysis, register_shell):
        register(sub, parents)
    return parser


def add_command(sub, parents, name, help_text, description=None, epilog=None):
    """Consistent subparser construction, so every command's help looks alike."""
    return sub.add_parser(
        name, parents=parents, help=help_text,
        description=description or help_text,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
