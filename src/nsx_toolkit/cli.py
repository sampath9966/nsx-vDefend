"""Entry point: assemble configuration, connect, dispatch a subcommand."""

import json
import os
import platform
import sys

from .api import ROLE_LM
from .audit import AuditLog
from .commands import apply_global_defaults, build_parser
from .config import (
    IMPLICIT_PROFILE,
    find_inventory,
    load_inventory,
    resolve_profile,
)
from .creds import credentials_for, set_store_policy
from .errors import ConfigError, NsxError, UserAbort
from .export import Exporter
from .http import Nsx, have_requests, make_transport
from .legacy import translate_legacy_argv, uses_legacy
from .menu import AppContext, interactive
from .output import (
    W,
    cB,
    cBC,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    cG,
    drop_buffered,
    err,
    flush_buffered,
    is_interactive,
    say,
    set_assume_yes,
    set_color,
    set_debug,
    set_interactive,
    set_json_mode,
    start_buffering,
)
from .paths import DATA_DIR, DEFAULT_EXPORT_DIR, config_search_dirs, utc_now_iso
from .sinks import (
    changed_since_last,
    fingerprint,
    post_webhook,
    render_junit,
    render_metrics,
    render_sarif,
    save_state,
    summarise_findings,
    webhook_payload,
    write_text,
)
from .taxonomy import load_taxonomy
from .version import TOOL_NAME, TOOL_TAGLINE, VERSION, VERSION_DATE
from .wizard import maybe_bootstrap

TAXONOMY_NAMES = ("taxonomy.json", "taxonomy.yaml", "taxonomy.yml")


def banner(inv_path, mgr_count, audit_path, taxonomy, write_enabled,
           profile=None, project=None):
    say(cBC("=" * W))
    say("  {} v{}    ({})".format(cB(TOOL_NAME), VERSION, VERSION_DATE))
    say("  {}".format(cC(TOOL_TAGLINE)))
    say(cD("-" * W))
    say("  Inventory  : {}  ({} manager(s))".format(cC(inv_path), mgr_count))
    say("  Profile    : {}".format(cC(profile or IMPLICIT_PROFILE)))
    if project:
        say("  Project    : {}  {}".format(
            cC(project), cD("(default infra is not visible from here)")))
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


def connect_all(managers, only=None, ca_bundle=None, quiet=True,
                project=None):
    """Authenticate against each manager. Quiet by default: a one-shot command
    should print its results, not a login transcript."""
    if not quiet:
        say("\n  {} ...".format(cB("Authenticating")))
    sessions, failed = [], []
    transport = make_transport()
    for m in managers:
        name = m.get("name", "?")
        if only and name not in only:
            continue
        if ca_bundle or project:
            m = dict(m)
            if ca_bundle:
                m["ca_bundle"] = ca_bundle
                m["verify_ssl"] = True
            if project:
                m["project"] = project
        try:
            user, pwd, src = credentials_for(m, allow_prompt=True)
            sessions.append(Nsx(m, user, pwd, transport=transport))
            if not quiet:
                say("    {:26s}  credentials {}".format(cC(name), cG(src)))
        except UserAbort:
            raise
        except NsxError as e:
            failed.append(name)
            err(str(e))
    if failed:
        say("    ({} unavailable: {})".format(
            cBR(str(len(failed))), ", ".join(failed)))
    return sessions


def _write_sinks(args, exporter, command, profile, project, changed):
    """Machine-readable outputs. Each failure is reported, never fatal.

    A hygiene report that found real problems must not be thrown away because
    a metrics directory was read-only.
    """
    findings = exporter.findings
    if args.out_junit:
        try:
            say("  Exported: {}".format(write_text(
                args.out_junit, render_junit(exporter.findings_by_suite()))))
        except OSError as e:
            err("could not write JUnit XML: {}".format(e))
    if args.out_sarif:
        try:
            say("  Exported: {}".format(write_text(
                args.out_sarif, render_sarif(findings))))
        except OSError as e:
            err("could not write SARIF: {}".format(e))
    if args.out_metrics:
        try:
            say("  Exported: {}".format(write_text(
                args.out_metrics, render_metrics(command, findings))))
        except OSError as e:
            err("could not write metrics: {}".format(e))
    if args.notify:
        payload = webhook_payload(command, findings, changed, profile, project)
        try:
            status = post_webhook(args.notify, payload)
            say("  Notified: HTTP {}".format(status))
        except NsxError as e:
            err(str(e))


def _emit_json(exporter, errors, rc):
    payload = {"tool": TOOL_NAME, "version": VERSION,
               "timestamp": utc_now_iso(), "exit_code": rc,
               "results": exporter.json_payload()}
    if errors:
        payload["errors"] = errors
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    print()


def _parse(parser, argv_list):
    out = []
    for argv in argv_list:
        out.append(apply_global_defaults(parser.parse_args(argv)))
    return out


def _apply_modes(args):
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


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)

    # --- pre-4.0 flags: translate, warn, continue -------------------------
    legacy_warnings = []
    argv_list = [raw]
    if uses_legacy(raw):
        translated, legacy_warnings = translate_legacy_argv(raw)
        if translated:
            argv_list = translated

    parser = build_parser()
    try:
        parsed = _parse(parser, argv_list)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    first = parsed[0]
    _apply_modes(first)
    for warning in legacy_warnings:
        print("warning: {}".format(warning), file=sys.stderr)

    os.makedirs(DATA_DIR, exist_ok=True)

    menu_mode = getattr(first, "command", None) is None
    if menu_mode and not is_interactive():
        parser.print_help()
        return 2

    needs_inventory = menu_mode or any(
        getattr(ns, "needs_inventory", True) for ns in parsed)
    needs_sessions = menu_mode or any(
        getattr(ns, "needs_sessions", True) for ns in parsed)

    exporter = Exporter()
    audit = AuditLog()
    errors = []

    # --- configuration ----------------------------------------------------
    managers, inv_path, taxonomy = [], None, None
    profile = None
    if needs_inventory:
        inv_path = find_inventory(first.inventory, config_search_dirs())
        if not inv_path:
            inv_path = maybe_bootstrap(first.inventory, config_search_dirs())
            if not inv_path:
                return 2
        try:
            profile, _why = resolve_profile(inv_path, first.profile)
            managers = load_inventory(inv_path, profile=profile)
        except ConfigError as e:
            err(str(e))
            return 2

    try:
        taxonomy = load_taxonomy(
            first.taxonomy,
            search_dirs=([os.path.dirname(os.path.abspath(inv_path))]
                         if inv_path else []) + config_search_dirs(),
            names=TAXONOMY_NAMES)
    except ConfigError as e:
        err(str(e))
        return 2

    only = None
    if needs_inventory and first.manager:
        only = {first.manager}
        if not any(m.get("name") == first.manager for m in managers):
            err("'{}' is not in {}. Known: {}".format(
                first.manager, inv_path,
                ", ".join(m.get("name", "?") for m in managers)))
            return 2
    elif needs_inventory and first.all_lm:
        only = {m.get("name") for m in managers if m.get("role") == ROLE_LM}
        if not only:
            err('No managers with "role": "lm" in {}.'.format(inv_path))
            return 2

    # --- connect ----------------------------------------------------------
    sessions = []
    if needs_sessions:
        if menu_mode:
            banner(inv_path, len(managers), audit.path, taxonomy,
                   first.enable_writes, profile=profile,
                   project=first.project)
        try:
            sessions = connect_all(managers, only=only,
                                   ca_bundle=first.ca_bundle,
                                   quiet=not menu_mode,
                                   project=first.project)
        except UserAbort:
            err("Credentials required.")
            return 2
        if not sessions:
            err("No manager could be authenticated.")
            return 2

    ctx = AppContext(sessions, audit, exporter, taxonomy,
                     write_enabled=first.enable_writes, domain=first.domain,
                     managers=managers, profile=profile,
                     project=first.project, inventory_path=inv_path)

    # --- dispatch ---------------------------------------------------------
    rc = 0
    try:
        if menu_mode:
            try:
                return interactive(ctx)
            except (KeyboardInterrupt, EOFError, UserAbort):
                say("\n  Bye.")
                return 0

        # --only-on-change collects the report rather than printing it, so a
        # run that turns out to have found nothing new can be discarded before
        # it reaches stdout. Cron then sends mail only when something moved.
        if first.only_on_change and not first.json:
            start_buffering()

        for ns in parsed:
            handler = getattr(ns, "func", None)
            if handler is None:
                if first.only_on_change and not first.json:
                    flush_buffered()
                parser.print_help()
                return 2
            result = handler(ns, ctx)
            if result:
                rc = result

        command = getattr(first, "command", None) or "nsxctl"
        changed, previous = True, {}
        # State belongs to --only-on-change, and is written only when it is
        # asked for. A plain interactive run that quietly primed it would make
        # the FIRST scheduled run silent -- with forty findings sitting there
        # unreported, which is the exact failure this feature exists to avoid.
        if first.only_on_change:
            state_root = os.path.join(DATA_DIR, "state")
            changed, previous = changed_since_last(
                command, exporter.findings, profile, first.project,
                root=state_root)
            save_state(command, fingerprint(exporter.findings),
                       summarise_findings(exporter.findings),
                       profile, first.project, root=state_root)
        if first.only_on_change and not first.json:
            if changed:
                flush_buffered()
            else:
                drop_buffered()
                if first.debug:
                    err("unchanged since {}; output suppressed".format(
                        previous.get("last_run", "the last run")))
                return rc

        if first.out_csv and exporter.has_staged():
            for path in exporter.to_csv(first.out_csv):
                say("  Exported: {}".format(path))
        if first.out_json and exporter.has_staged():
            for path in exporter.to_json(first.out_json):
                say("  Exported: {}".format(path))
        if any((first.out_junit, first.out_sarif, first.out_metrics,
                first.notify)):
            _write_sinks(first, exporter, command, profile, first.project,
                         changed)
        if first.json:
            _emit_json(exporter, errors, rc)
        return rc

    except UserAbort:
        say("\n  Cancelled.")
        return 130
    except NsxError as e:
        errors.append(str(e))
        err(str(e))
        if first.json:
            _emit_json(exporter, errors, 1)
        return 1
    except KeyboardInterrupt:
        say("\n  Cancelled.")
        return 130
    finally:
        ctx.close()


def entry():
    sys.exit(main())
