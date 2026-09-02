"""Command-line entry point."""

import argparse
import json
import os
import platform
import sys

from .actions.audit_view import act_audit_log
from .actions.bulk import act_bulk_tag
from .actions.change_ticket import act_change_ticket
from .actions.dashboard import act_dashboard
from .actions.groups import act_groups
from .actions.parity import act_parity
from .actions.reverse import act_reverse_lookup
from .actions.tags import act_vm_tags, act_vms_by_tag
from .actions.verify import act_verify
from .api import DEFAULT_DOMAIN, ROLE_LM
from .audit import AuditLog
from .config import find_inventory, load_inventory
from .creds import credentials_for, force_set_credentials, set_store_policy
from .errors import ConfigError, NsxError, UserAbort
from .export import Exporter
from .http import Nsx, have_requests, make_transport
from .menu import AppContext, interactive
from .output import (
    W,
    assume_yes,
    cB,
    cBC,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cG,
    confirm,
    err,
    is_interactive,
    say,
    section,
    set_assume_yes,
    set_color,
    set_debug,
    set_interactive,
    set_json_mode,
    table,
)
from .paths import (
    DATA_DIR,
    DEFAULT_EXPORT_DIR,
    DEFAULT_TAXONOMY_NAMES,
    config_search_dirs,
    utc_now_iso,
)
from .taxonomy import load_taxonomy
from .version import TOOL_NAME, TOOL_TAGLINE, VERSION, VERSION_DATE
from .wizard import maybe_bootstrap, run_wizard

EPILOG = """
first run:
  nsx-toolkit                    guided setup, then the interactive menu
  nsx-toolkit --init             re-run guided setup at any time

inventory.json  (current directory, {data_dir}, or --inventory <path>):
  {{"managers": [
    {{"name": "gm", "role": "gm", "host": "gm.example.com", "port": 443,
     "verify_ssl": false, "auth": "session",
     "username_env": "NSX_GM_USER", "password_env": "NSX_GM_PASS"}}
  ]}}

taxonomy (optional; built-in default is used when absent):
  taxonomy.json next to inventory.json, or --taxonomy <path>.
  See examples/taxonomy.example.json.

credentials:
  Resolved from the environment, then the OS keyring, then a local file.
  Prompted once and stored (keyring where available; on disk only if you
  say yes). To change them:  nsx-toolkit --set-credentials

bulk tagging CSV:  vm_name,scope,tag,action     (action = add | remove)

examples:
  nsx-toolkit --verify
  nsx-toolkit --manager gm --groups --contains web-prod
  nsx-toolkit --all-lm --vms-by-tag --scope env --tag prod
  nsx-toolkit --dashboard --json
  nsx-toolkit --bulk-tag changes.csv --dry-run
  nsx-toolkit --bulk-tag changes.csv --enable-writes --yes
  nsx-toolkit --all-lm --vm-tags cuc --out-csv results.csv
""".format(data_dir=DATA_DIR)


def build_parser():
    p = argparse.ArgumentParser(
        prog="nsx-toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="{} v{} -- {}\n\nRun with no arguments for the "
                    "interactive menu.".format(TOOL_NAME, VERSION, TOOL_TAGLINE),
        epilog=EPILOG)
    p.add_argument("--version", action="version",
                   version="{} v{} ({})".format(TOOL_NAME, VERSION, VERSION_DATE))

    g = p.add_argument_group("configuration")
    g.add_argument("--init", action="store_true",
                   help="Run guided setup and exit.")
    g.add_argument("--inventory", default=None, metavar="PATH")
    g.add_argument("--taxonomy", default=None, metavar="PATH",
                   help="Tag taxonomy file (JSON, or YAML with PyYAML).")
    g.add_argument("--manager", default=None, metavar="NAME")
    g.add_argument("--all-lm", action="store_true",
                   help="Target every Local Manager.")
    g.add_argument("--domain", default=DEFAULT_DOMAIN)
    g.add_argument("--ca-bundle", default=None, metavar="PATH",
                   help="CA bundle for TLS verification on all managers.")
    g.add_argument("--set-credentials", action="store_true",
                   help="Prompt for and overwrite stored credentials, then exit.")
    g.add_argument("--store", choices=("auto", "keyring", "plaintext", "none"),
                   default="auto",
                   help="Where prompted credentials are saved (default: auto).")

    a = p.add_argument_group("actions")
    a.add_argument("--groups", action="store_true")
    a.add_argument("--members", action="store_true",
                   help="With --groups, also list VM members.")
    a.add_argument("--contains", default=None, metavar="TEXT")
    a.add_argument("--vm-tags", metavar="VM", default=None)
    a.add_argument("--vms-by-tag", action="store_true")
    a.add_argument("--scope", default=None)
    a.add_argument("--tag", default=None)
    a.add_argument("--verify", action="store_true")
    a.add_argument("--dashboard", action="store_true",
                   help="Taxonomy compliance posture.")
    a.add_argument("--parity", nargs=2, metavar=("STATIC", "DYNAMIC"))
    a.add_argument("--reverse-lookup", metavar="VM", default=None,
                   help="VM -> groups -> DFW rules impact analysis. Group "
                        "match is member-type agnostic; rules are scanned on "
                        "GM + all LMs and deduped by rule path.")
    a.add_argument("--bulk-tag", metavar="CSV", default=None)
    a.add_argument("--change-ticket", metavar="CSV", default=None)
    a.add_argument("--audit-log", action="store_true",
                   help="Show recent audited writes.")
    a.add_argument("--list-managers", action="store_true")

    w = p.add_argument_group("writes")
    w.add_argument("--dry-run", action="store_true",
                   help="Preview only. Default for --bulk-tag.")
    w.add_argument("--enable-writes", action="store_true")
    w.add_argument("--yes", "-y", action="store_true",
                   help="Skip confirmation prompts. Required to write "
                        "non-interactively.")
    w.add_argument("--force", action="store_true",
                   help="Apply even if a VM's tags changed since the plan "
                        "was computed.")

    o = p.add_argument_group("output")
    o.add_argument("--out-csv", metavar="PATH", default=None)
    o.add_argument("--out-json", metavar="PATH", default=None)
    o.add_argument("--json", action="store_true",
                   help="Structured JSON on stdout. Implies non-interactive.")
    o.add_argument("--no-color", action="store_true")
    o.add_argument("--non-interactive", action="store_true",
                   help="Never prompt; use defaults and fail rather than ask.")
    o.add_argument("--debug", action="store_true",
                   help="Log HTTP method, URL, status and timing to stderr.")
    return p


def banner(inv_path, mgr_count, audit_path, taxonomy, write_enabled):
    say(cBC("=" * W))
    say("  {} v{}    ({})".format(cB(TOOL_NAME), VERSION, VERSION_DATE))
    say("  {}".format(cC(TOOL_TAGLINE)))
    say(cD("-" * W))
    say("  Inventory  : {}  ({} manager(s))".format(cC(inv_path), mgr_count))
    say("  Taxonomy   : {}".format(taxonomy.source))
    say("  Audit log  : {}".format(audit_path))
    say("  Exports    : {}".format(DEFAULT_EXPORT_DIR))
    mode = (cBG("READ-WRITE") if write_enabled
            else cBY("READ-ONLY") + " (--enable-writes)")
    say("  Mode       : {}".format(mode))
    say("  Transport  : {}".format("requests" if have_requests() else "stdlib urllib"))
    say("  Platform   : {} / Python {}".format(
        platform.node(), platform.python_version()))
    say(cBC("=" * W))


def connect_all(managers, only=None, ca_bundle=None):
    say("\n  {} ...".format(cB("Authenticating")))
    sessions, failed = [], []
    transport = make_transport()
    for m in managers:
        name = m.get("name", "?")
        if only and name not in only:
            continue
        if ca_bundle:
            m = dict(m)
            m["ca_bundle"] = ca_bundle
            m["verify_ssl"] = True
        try:
            user, pwd, src = credentials_for(m, allow_prompt=True)
            sessions.append(Nsx(m, user, pwd, transport=transport))
            say("    {:26s}  credentials {}".format(cC(name), cG(src)))
        except UserAbort:
            raise
        except NsxError as e:
            failed.append(name)
            err(str(e))
    if failed:
        say("    ({} unavailable: {})".format(cBR(str(len(failed))),
                                              ", ".join(failed)))
    return sessions


def _write_gate(what):
    """A write from the CLI needs --yes, or an interactive confirmation."""
    if assume_yes():
        return True
    if not is_interactive():
        err("Refusing to {} without confirmation. Re-run with --yes "
            "(or --dry-run to preview).".format(what))
        return False
    return confirm("  {} [y/N]: ".format(cB("Apply {} for real?".format(what))))


def _emit_json(exporter, errors, rc):
    payload = {"tool": TOOL_NAME, "version": VERSION,
               "timestamp": utc_now_iso(), "exit_code": rc,
               "results": exporter.json_payload()}
    if errors:
        payload["errors"] = errors
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    print()


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.no_color:
        set_color(False)
    if args.json:
        set_json_mode(True)
    if args.non_interactive:
        set_interactive(False)
    if args.yes:
        set_assume_yes(True)
    if args.debug:
        set_debug(True)
    set_store_policy(args.store)

    os.makedirs(DATA_DIR, exist_ok=True)

    # --- inventory -------------------------------------------------------
    inv_path = find_inventory(args.inventory, config_search_dirs())
    if args.init:
        return 0 if run_wizard(args.inventory or inv_path) else 1
    if not inv_path:
        inv_path = maybe_bootstrap(args.inventory, config_search_dirs())
        if not inv_path:
            return 2
    try:
        managers = load_inventory(inv_path)
    except ConfigError as e:
        err(str(e))
        return 2

    # --- taxonomy --------------------------------------------------------
    try:
        taxonomy = load_taxonomy(
            args.taxonomy,
            search_dirs=[os.path.dirname(os.path.abspath(inv_path))]
            + config_search_dirs(),
            names=DEFAULT_TAXONOMY_NAMES + ("taxonomy.json",))
    except ConfigError as e:
        err(str(e))
        return 2

    # --- manager selection ----------------------------------------------
    only = None
    if args.manager:
        only = {args.manager}
        if not any(m.get("name") == args.manager for m in managers):
            err("'{}' is not in {}. Known: {}".format(
                args.manager, inv_path,
                ", ".join(m.get("name", "?") for m in managers)))
            return 2
    elif args.all_lm:
        only = {m.get("name") for m in managers if m.get("role") == ROLE_LM}
        if not only:
            err('No managers with "role": "lm" in {}.'.format(inv_path))
            return 2

    if args.set_credentials:
        return force_set_credentials(managers, only=only)

    audit = AuditLog()
    exporter = Exporter()
    write_enabled = args.enable_writes

    wants_cli = any([args.groups, args.vm_tags, args.vms_by_tag, args.verify,
                     args.bulk_tag, args.dashboard, args.parity,
                     args.change_ticket, args.reverse_lookup, args.audit_log,
                     args.list_managers])

    banner(inv_path, len(managers), audit.path, taxonomy, write_enabled)

    try:
        sessions = connect_all(managers, only=only, ca_bundle=args.ca_bundle)
    except UserAbort:
        err("Credentials required.")
        return 2
    if not sessions:
        err("No manager could be authenticated.")
        return 2

    ctx = AppContext(sessions, audit, exporter, taxonomy,
                     write_enabled=write_enabled, domain=args.domain)

    if not wants_cli:
        try:
            return interactive(ctx)
        except (KeyboardInterrupt, EOFError, UserAbort):
            say("\n  Bye.")
            return 0
        finally:
            ctx.close()

    errors = []
    rc = 0
    try:
        if args.list_managers:
            section("Managers")
            table(["Name", "Host", "Role", "Auth", "Verify"],
                  [[s.name, s.host, s.role, s.auth_mode, str(s.verify)]
                   for s in sessions])

        if args.verify and not act_verify(sessions, args.domain):
            rc = 1

        if args.groups:
            act_groups(sessions, args.domain, args.contains,
                       show_members=args.members, exporter=exporter)

        lms = ctx.lms()

        if args.vm_tags:
            if not lms:
                err("--vm-tags needs a Local Manager.")
                return 2
            act_vm_tags(lms, args.vm_tags, exporter, taxonomy)

        if args.vms_by_tag:
            if not lms:
                err("--vms-by-tag needs a Local Manager.")
                return 2
            if not args.scope and not args.tag:
                err("--vms-by-tag needs --scope and/or --tag.")
                return 2
            act_vms_by_tag(lms, args.scope, args.tag, exporter)

        if args.dashboard:
            act_dashboard(sessions, exporter, taxonomy)

        if args.parity:
            act_parity(sessions, args.domain, args.parity[0], args.parity[1],
                       exporter)

        if args.reverse_lookup:
            # Always the full session set -- GM + every LM. See the docstring
            # on act_reverse_lookup.
            act_reverse_lookup(sessions, args.reverse_lookup, args.domain,
                               exporter)

        if args.change_ticket:
            act_change_ticket(sessions, args.change_ticket, exporter)

        if args.audit_log:
            act_audit_log(audit, sessions, write_enabled, exporter)

        if args.bulk_tag:
            if not lms:
                err("--bulk-tag needs a Local Manager.")
                return 2
            # Dry run always happens first, then the real apply is gated.
            act_bulk_tag(lms, args.bulk_tag, audit, write_enabled,
                         dry_run=True, taxonomy=taxonomy)
            if not args.dry_run:
                if not write_enabled:
                    say("\n  {} -- add --enable-writes to apply.".format(
                        cBY("READ-ONLY")))
                elif _write_gate("bulk tagging"):
                    result = act_bulk_tag(lms, args.bulk_tag, audit,
                                          write_enabled, dry_run=False,
                                          taxonomy=taxonomy, force=args.force)
                    if result["failed"]:
                        rc = 1
                else:
                    say("  Cancelled -- nothing written.")

        if args.out_csv and exporter.has_staged():
            for path in exporter.to_csv(args.out_csv):
                say("  Exported: {}".format(path))
        if args.out_json and exporter.has_staged():
            for path in exporter.to_json(args.out_json):
                say("  Exported: {}".format(path))

        if args.json:
            _emit_json(exporter, errors, rc)
        return rc

    except UserAbort:
        say("\n  Cancelled.")
        return 130
    except NsxError as e:
        errors.append(str(e))
        err(str(e))
        if args.json:
            _emit_json(exporter, errors, 1)
        return 1
    except KeyboardInterrupt:
        say("\n  Cancelled.")
        return 130
    finally:
        ctx.close()


def entry():
    sys.exit(main())
