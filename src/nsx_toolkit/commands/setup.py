"""Setup and introspection: init, status, managers, login, config."""

import os
import sys

from ..actions.doctor import act_doctor
from ..actions.verify import act_verify
from ..api import F_DISPLAY_NAME, F_ID, ROLE_LABEL, p_projects
from ..config import (
    IMPLICIT_PROFILE,
    find_inventory,
    list_profiles,
    load_inventory,
    resolve_profile,
)
from ..creds import creds_file_path, force_set_credentials, keyring_available
from ..errors import ConfigError, NsxError
from ..launcher import module_command, path_status, repair_path
from ..output import (
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    confirm,
    err,
    hr,
    ok_msg,
    say,
    section,
    table,
)
from ..paths import (
    DATA_DIR,
    DEFAULT_AUDIT_FILE,
    DEFAULT_EXPORT_DIR,
    DEFAULT_SNAPSHOT_DIR,
    DEFAULT_TICKET_DIR,
    config_search_dirs,
)
from ..taxonomy import load_taxonomy
from ..wizard import run_wizard
from . import add_command

PROFILE_HEADERS = ["profile", "in_effect", "managers"]
PROJECT_HEADERS = ["manager", "id", "name", "description"]


def register_setup(sub, parents):
    p = add_command(
        sub, parents, "init", "Guided first-run setup.",
        epilog="Asks for each NSX manager, stores credentials, and proves\n"
               "every one is reachable before finishing.")
    p.set_defaults(func=cmd_init, needs_inventory=False, needs_sessions=False)

    p = add_command(
        sub, parents, "status",
        "Check every manager is reachable and authenticated.",
        epilog="examples:\n"
               "  nsxctl status\n"
               "  nsxctl status --manager gm --debug")
    p.set_defaults(func=cmd_status)

    p = add_command(
        sub, parents, "doctor",
        "What does this NSX actually serve?",
        description="Probe every API surface the toolkit depends on and "
                    "report, per manager, which are available.\n\n"
                    "The toolkit degrades rather than fails when a surface is "
                    "absent -- statistics may 404, traceflow is Local Manager "
                    "only, Projects may not exist -- which means a missing "
                    "feature and a bug in the tool look identical until you "
                    "run this.\n\n"
                    "Every probe is a bounded read. Nothing is written, and "
                    "traceflow is checked by listing, never by injecting a "
                    "packet.",
        epilog="examples:\n"
               "  nsxctl doctor\n"
               "  nsxctl doctor --json          # paste this into a bug report\n"
               "  nsxctl doctor --fail-on-missing   # for a pipeline")
    p.add_argument("--fail-on-missing", action="store_true",
                   help="Exit 1 if any capability is missing or unreadable.")
    p.set_defaults(func=cmd_doctor)

    p = add_command(
        sub, parents, "setup-path", "Make `nsxctl` runnable from any terminal.",
        description="Put the directory pip installed the launcher into onto "
                    "your PATH.\n\n"
                    "A wheel cannot do this at install time -- there is no "
                    "install hook to do it from -- so on a Python installed "
                    "without \"Add Python to PATH\", `nsxctl` is installed and "
                    "unreachable at the same time, and the shell just says "
                    "command not found.\n\n"
                    "Only the per-user PATH is touched, never the system one, "
                    "and the previous value is saved first.",
        epilog="examples:\n"
               "  nsxctl setup-path\n"
               "  nsxctl setup-path --check      # report only; 1 if unreachable\n"
               "  py -m nsx_toolkit setup-path   # when `nsxctl` will not run yet")
    p.add_argument("--check", action="store_true",
                   help="Report and change nothing. Exit 1 if unreachable.")
    p.set_defaults(func=cmd_setup_path, needs_inventory=False,
                   needs_sessions=False)

    p = add_command(sub, parents, "managers", "List the configured managers.")
    p.set_defaults(func=cmd_managers)

    p = add_command(
        sub, parents, "profiles", "List the estates this inventory defines.",
        description="An inventory can name several estates and select one "
                    "with --profile. A flat single-estate inventory has none, "
                    "and still works exactly as it always did.",
        epilog="examples:\n"
               "  nsxctl profiles\n"
               "  nsxctl --profile dr status\n"
               "  NSX_PROFILE=dr nsxctl compliance")
    p.set_defaults(func=cmd_profiles, needs_sessions=False)

    p = add_command(
        sub, parents, "projects", "List NSX Projects on each manager.",
        description="NSX Projects are multi-tenancy: each has its own infra "
                    "tree, so objects in the default infra are NOT visible "
                    "from inside a project and vice versa. Scope a run with "
                    "--project.",
        epilog="examples:\n"
               "  nsxctl projects\n"
               "  nsxctl --project tenant-a group list")
    p.set_defaults(func=cmd_projects)

    p = add_command(
        sub, parents, "login", "Store or replace credentials for a manager.",
        epilog="examples:\n"
               "  nsxctl login              all managers\n"
               "  nsxctl login lm-london    just that one")
    p.add_argument("name", nargs="?", help="Manager name (default: all).")
    p.set_defaults(func=cmd_login, needs_sessions=False)

    p = add_command(
        sub, parents, "config", "Show or check the configuration in effect.")
    csub = p.add_subparsers(dest="config_action", metavar="<action>")
    c = csub.add_parser("show", parents=parents,
                        help="Configuration currently in effect.")
    c.set_defaults(func=cmd_config_show)
    c = csub.add_parser("path", parents=parents,
                        help="Where every file lives.")
    c.set_defaults(func=cmd_config_path)
    c = csub.add_parser("validate", parents=parents,
                        help="Validate inventory and taxonomy; non-zero on error.")
    c.set_defaults(func=cmd_config_validate)
    p.set_defaults(func=cmd_config_show, config_action="show")
    for c in csub.choices.values():
        c.set_defaults(needs_inventory=False, needs_sessions=False)
    p.set_defaults(needs_inventory=False, needs_sessions=False)


def cmd_init(args, ctx):
    return 0 if run_wizard(args.inventory) else 1


def cmd_setup_path(args, ctx):
    st = path_status()
    section("LAUNCHER")
    say("  Interpreter : {}".format(cC(sys.executable)))
    say("  Scripts dir : {}".format(cC(st.directory)))
    say("  Launcher    : {}".format(
        cC(st.launcher) if st.installed else cBR("not found")))
    say("  On PATH     : {}".format(
        cBG("yes") if st.reachable else cBR("no")))
    if st.resolved and st.shadowed:
        say("  `nsxctl` is : {}".format(cBY(st.resolved)))
    hr()

    # A different copy earlier on PATH answers to the name. Appending ours
    # cannot beat it -- PATH is first-match -- so this is reported, not
    # "fixed" in a way that would leave the same copy winning.
    if st.shadowed:
        err("`nsxctl` already resolves to another file:\n"
            "    {}\n"
            "  Adding {} to PATH would not change that: the other copy comes\n"
            "  first and would still win. Remove it, or call this one by its\n"
            "  full path.".format(st.resolved, st.directory))
        return 1

    if st.reachable:
        ok_msg("`nsxctl` runs from any terminal. Nothing to do.")
        return 0

    say("  {}".format(cD(
        "The launcher is installed but its directory is not on PATH, so the\n"
        "  shell cannot find it. pip warns about this and the warning scrolls\n"
        "  past. Until it is fixed, this works from anywhere:")))
    say("\n      {}\n".format(cB(module_command())))

    if args.check:
        return 1
    if not st.installed:
        err("No launcher to put on PATH -- install the package for this "
            "interpreter first.")
        return 2
    if not confirm("  Add {} to your PATH? [y/N] ".format(cC(st.directory))):
        say("\n  Nothing changed.")
        return 1

    try:
        changed, detail = repair_path(st)
    except ConfigError as e:
        err(str(e))
        return 2
    hr()
    if changed:
        ok_msg("PATH updated -- {}".format(detail))
    else:
        say("  {}".format(detail))
    say("  {}".format(cD(
        "A running shell keeps the environment it started with, so this one\n"
        "  is unchanged. Open a NEW terminal and run `nsxctl version`.")))
    return 0


def cmd_status(args, ctx):
    return 0 if act_verify(ctx.sessions, args.domain) else 1


def cmd_managers(args, ctx):
    section("Managers")
    table(["Name", "Host", "Role", "Auth", "Verify TLS"],
          [[cC(s.name), s.host, ROLE_LABEL.get(s.role, "?"), s.auth_mode,
            str(s.verify)] for s in ctx.sessions])
    return 0


def cmd_doctor(args, ctx):
    _probes, healthy = act_doctor(ctx.sessions, args.domain, ctx.exporter)
    if args.fail_on_missing and not healthy:
        return 1
    return 0


def cmd_profiles(args, ctx):
    section("Profiles")
    if not ctx.inventory_path:
        err("No inventory in effect.")
        return 2
    names = list_profiles(ctx.inventory_path)
    say("  Inventory: {}".format(cC(ctx.inventory_path)))
    if not names:
        say("\n  {} -- a single-estate inventory.".format(cD("No profiles")))
        say("  {}".format(cD(
            "Add a 'profiles' object to name several estates; see "
            "`nsxctl profiles --help`.")))
        ctx.exporter.stage("profiles", PROFILE_HEADERS,
                           [[IMPLICIT_PROFILE, "yes", ""]])
        return 0
    active, why = resolve_profile(ctx.inventory_path, args.profile)
    rows = []
    for name in names:
        try:
            count = len(load_inventory(ctx.inventory_path, profile=name))
        except ConfigError:
            count = 0
        rows.append([name, "yes" if name == active else "", str(count)])
    table(["Profile", "In effect", "Managers"],
          [[cC(r[0]), cBG(r[1]) if r[1] else "", r[2]] for r in rows],
          indent=4)
    say("\n  {} selected by {}.".format(cB(str(active)), cD(why)))
    ctx.exporter.stage("profiles", PROFILE_HEADERS, rows)
    return 0


def cmd_projects(args, ctx):
    section("NSX Projects")
    rows = []
    for nsx in ctx.sessions:
        try:
            found = nsx.get_all(p_projects(nsx.org))
        except NsxError as e:
            say("  {:22s}  {}".format(cC(nsx.name), cD(
                "no project API ({})".format(str(e)[:70]))))
            continue
        if not found:
            say("  {:22s}  {}".format(cC(nsx.name), cD("no projects")))
            continue
        for project in found:
            rows.append([nsx.name, project.get(F_ID, "?"),
                         project.get(F_DISPLAY_NAME, ""),
                         project.get("description", "")])
    if rows:
        table(["Manager", "Id", "Name", "Description"],
              [[cC(r[0]), cB(r[1]), r[2], cD(r[3])] for r in rows], indent=4)
        say("\n  {}".format(cD(
            "Scope a run to one with --project ID. Objects in the default "
            "infra are not visible from inside a project.")))
    ctx.exporter.stage("projects", PROJECT_HEADERS, rows)
    return 0


def cmd_login(args, ctx):
    only = {args.name} if args.name else None
    if only and not any(m.get("name") in only for m in ctx.managers):
        err("'{}' is not in the inventory. Known: {}".format(
            args.name, ", ".join(m.get("name", "?") for m in ctx.managers)))
        return 2
    return force_set_credentials(ctx.managers, only=only)


def _resolve(args):
    inv = find_inventory(args.inventory, config_search_dirs())
    tax = load_taxonomy(
        args.taxonomy,
        search_dirs=([os.path.dirname(os.path.abspath(inv))] if inv else [])
        + config_search_dirs(),
        names=("taxonomy.json", "taxonomy.yaml", "taxonomy.yml"))
    return inv, tax


def cmd_config_path(args, ctx):
    inv, tax = _resolve(args)
    section("Paths")
    rows = [
        ["inventory", inv or cD("(none found)")],
        ["taxonomy", tax.source],
        ["credentials", creds_file_path()],
        ["audit log", DEFAULT_AUDIT_FILE],
        ["exports", DEFAULT_EXPORT_DIR],
        ["change plans", DEFAULT_TICKET_DIR],
        ["snapshots", DEFAULT_SNAPSHOT_DIR],
        ["data dir", DATA_DIR],
    ]
    table(["What", "Where"], rows)
    say("")
    say("  Searched for inventory.json in: {}".format(
        cD(", ".join(config_search_dirs()))))
    return 0


def cmd_config_show(args, ctx):
    inv, tax = _resolve(args)
    section("Configuration in effect")
    say("  Inventory : {}".format(cC(inv) if inv else cBR("none found")))
    say("  Taxonomy  : {}".format(cC(tax.source)))
    say("  Keyring   : {}".format(
        cBG("available") if keyring_available() else cD("not available")))
    if inv:
        try:
            managers = load_inventory(inv)
        except ConfigError as e:
            err(str(e))
            return 1
        say("\n  {}".format(cB("Managers")))
        table(["Name", "Host", "Role", "Auth", "Verify TLS"],
              [[m.get("name", "?"), m.get("host", "?"),
                ROLE_LABEL.get(m.get("role"), "?"), m.get("auth", "session"),
                str(m.get("verify_ssl", True))] for m in managers], indent=4)
    say("\n  {}".format(cB("Tag taxonomy")))
    rows = []
    for scope in tax.all_scopes:
        allowed = tax.values_for(scope)
        rows.append([scope,
                     "yes" if scope in tax.mandatory else "no",
                     ", ".join(allowed) if allowed else cD("(any)")])
    table(["Scope", "Required", "Allowed values"], rows, indent=4)
    return 0


def cmd_config_validate(args, ctx):
    inv, _ = _resolve(args)
    problems = 0
    if not inv:
        err("No inventory found. Run: nsxctl init")
        return 2
    try:
        managers = load_inventory(inv)
        ok_msg("inventory: {} manager(s) in {}".format(len(managers), inv))
    except ConfigError as e:
        err(str(e))
        problems += 1
    try:
        tax = load_taxonomy(
            args.taxonomy,
            search_dirs=[os.path.dirname(os.path.abspath(inv))]
            + config_search_dirs(),
            names=("taxonomy.json", "taxonomy.yaml", "taxonomy.yml"))
        ok_msg("taxonomy: {} required, {} optional scope(s) from {}".format(
            len(tax.mandatory), len(tax.conditional), tax.source))
    except ConfigError as e:
        err(str(e))
        problems += 1
    hr()
    if problems:
        say("  {} problem(s).".format(cBR(str(problems))))
        return 1
    say("  {}".format(cBG("Configuration is valid.")))
    return 0
