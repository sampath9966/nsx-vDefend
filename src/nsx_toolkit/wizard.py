"""First-run setup.

The old behaviour on a machine with no inventory.json was to print
"No inventory file found." and exit 2, which is where most people gave up.
This asks the handful of questions needed to build one, stores credentials,
and proves each manager is reachable before it finishes.
"""

import os

from .api import ROLE_GM, ROLE_LM
from .config import default_env_names, validate_manager, write_inventory
from .creds import credentials_for, keyring_available
from .errors import NsxError, UserAbort
from .http import Nsx, have_requests, make_transport
from .output import (
    W,
    ask,
    cB,
    cBC,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    confirm,
    err,
    hr,
    is_interactive,
    ok_msg,
    say,
    warn,
)
from .paths import DATA_DIR, DEFAULT_INVENTORY_NAME, config_search_dirs
from .version import TOOL_NAME, VERSION


def _intro():
    say(cBC("=" * W))
    say("  {} v{} -- {}".format(cB(TOOL_NAME), VERSION, cB("first-run setup")))
    say(cBC("=" * W))
    say("")
    say("  No inventory was found, so let's build one. You'll be asked for")
    say("  each NSX manager you want the toolkit to talk to.")
    say("")
    say("  {} the Global Manager (if you have one), then each".format(cD("Add")))
    say("  {} Local Manager. Tags and VM inventory live on Local".format(cD("")))
    say("  Managers; groups and policies exist on both.")
    say("")
    if not have_requests():
        say("  {} 'requests' is not installed -- using the built-in".format(
            cD("note:")))
        say("        stdlib transport. Everything works; client-certificate")
        say("        authentication is the one feature that needs requests.")
        say("")


def _ask_role():
    while True:
        say("    1. Local Manager  {}".format(cD("(VMs, tags, local policy)")))
        say("    2. Global Manager {}".format(cD("(federated groups and policy)")))
        c = ask("  Role [1]: ", default="1").strip().lower()
        if c in ("1", "lm", "local"):
            return ROLE_LM
        if c in ("2", "gm", "global"):
            return ROLE_GM
        say("    Pick 1 or 2.")


def _ask_manager(index, used_names):
    say("\n  {}".format(cB("Manager #{}".format(index))))
    hr()
    host = ask("  Hostname or IP: ").strip()
    if not host:
        return None
    default_name = host.split(".")[0][:24] or "nsx{}".format(index)
    while True:
        name = ask("  Short name [{}]: ".format(default_name),
                   default=default_name).strip()
        if name not in used_names:
            break
        say("    '{}' is already used -- pick another.".format(name))
    role = _ask_role()
    port = ask("  Port [443]: ", default="443").strip()
    verify = confirm("  Verify the TLS certificate? "
                     "[y/N] (N is usual for self-signed): ")
    entry = {
        "name": name,
        "role": role,
        "host": host,
        "port": int(port) if port.isdigit() else 443,
        "verify_ssl": bool(verify),
        "auth": "session",
    }
    if verify:
        ca = ask("  CA bundle path (blank = system trust store): ",
                 default="").strip()
        if ca:
            entry["ca_bundle"] = ca
    u_env, p_env = default_env_names(name)
    entry["username_env"] = u_env
    entry["password_env"] = p_env
    problems = validate_manager(entry, index)
    for p in problems:
        warn(p)
    return entry


def _test(entry):
    """Authenticate and make one real call. Returns True when it works."""
    name = entry.get("name", "?")
    say("\n  Testing {} ...".format(cC(name)))
    try:
        user, pwd, src = credentials_for(entry, allow_prompt=True)
    except (NsxError, UserAbort) as e:
        err("{}: {}".format(name, e))
        return False
    say("    credentials {}".format(cD(src)))
    try:
        nsx = Nsx(entry, user, pwd, transport=make_transport())
        base = nsx.base(verbose=True)
        version = nsx.version()
        say("    api base    {}".format(cD(base)))
        if version:
            say("    nsx version {}".format(cD("{}.{}".format(*version))))
        ok_msg("{}: reachable and authenticated.".format(name))
        nsx.close()
        return True
    except NsxError as e:
        err("{}: {}".format(name, str(e)[:200]))
        return False


def run_wizard(explicit_path=None):
    """Build an inventory interactively. Returns its path, or None."""
    if not is_interactive():
        err("No inventory file found, and this is not an interactive terminal.")
        say("")
        say("  Create one and re-run. Minimal example:")
        say(cD('    {"managers": [{"name": "lm1", "role": "lm",'))
        say(cD('       "host": "nsx.example.com", "verify_ssl": false,'))
        say(cD('       "username_env": "NSX_LM1_USER",'))
        say(cD('       "password_env": "NSX_LM1_PASS"}]}'))
        say("")
        say("  Save it as {} in the current directory or in {},".format(
            cC(DEFAULT_INVENTORY_NAME), cC(DATA_DIR)))
        say("  or pass --inventory <path>. Run with a terminal for guided setup.")
        return None

    _intro()
    managers = []
    used = set()
    while True:
        entry = _ask_manager(len(managers) + 1, used)
        if entry is None:
            if managers:
                break
            say("  A hostname is required.")
            continue
        managers.append(entry)
        used.add(entry["name"])
        if not confirm("\n  Add another manager? [y/N]: "):
            break

    if not managers:
        err("No managers configured.")
        return None

    default_dir = explicit_path and os.path.dirname(os.path.abspath(explicit_path))
    if not default_dir:
        default_dir = DATA_DIR
    target = explicit_path or os.path.join(default_dir, DEFAULT_INVENTORY_NAME)
    say("\n  {}".format(cB("Where should the inventory live?")))
    say("    1. {}  {}".format(
        os.path.join(DATA_DIR, DEFAULT_INVENTORY_NAME),
        cD("(found from anywhere)")))
    say("    2. {}  {}".format(
        os.path.join(os.getcwd(), DEFAULT_INVENTORY_NAME),
        cD("(this directory only)")))
    choice = ask("  Choice [1]: ", default="1").strip()
    if choice == "2":
        target = os.path.join(os.getcwd(), DEFAULT_INVENTORY_NAME)
    elif not explicit_path:
        target = os.path.join(DATA_DIR, DEFAULT_INVENTORY_NAME)

    if os.path.exists(target) and not confirm(
            "  {} exists. Overwrite? [y/N]: ".format(target)):
        say("  Cancelled -- nothing written.")
        return None

    write_inventory(target, managers)
    ok_msg("Wrote {}".format(target))

    if not keyring_available():
        say("  {} no OS keyring here, so you'll be asked whether to".format(
            cD("note:")))
        say("        store credentials on disk when you enter them.")

    say("\n  {}".format(cB("Connectivity check")))
    hr()
    results = [(m.get("name"), _test(m)) for m in managers]
    good = [n for n, k in results if k]
    bad = [n for n, k in results if not k]

    hr()
    if bad:
        say("  {} {} of {} manager(s) failed: {}".format(
            cBY("WARNING:"), len(bad), len(results), ", ".join(bad)))
        say("  The inventory was still written -- fix the entry and re-run")
        say("  {} to retest, or {} to re-enter credentials.".format(
            cC("--verify"), cC("--set-credentials")))
    else:
        say("  {} all {} manager(s) reachable.".format(cBG("Ready:"), len(good)))
    say("")
    say("  Next: {}   {}".format(cC("nsx-toolkit"), cD("(interactive menu)")))
    say("        {}   {}".format(cC("nsx-toolkit --dashboard"),
                                 cD("(compliance posture)")))
    say("")
    return target


def maybe_bootstrap(explicit_path, search_dirs=None):
    """Called when no inventory was found. Returns a path or None."""
    search_dirs = search_dirs or config_search_dirs()
    if explicit_path:
        say("  {} {}".format(cBR("Inventory not found:"), explicit_path))
    else:
        looked = ", ".join(os.path.join(d, DEFAULT_INVENTORY_NAME)
                           for d in search_dirs)
        say("  {} looked in: {}".format(cD("No inventory found."), cD(looked)))
    return run_wizard(explicit_path)
