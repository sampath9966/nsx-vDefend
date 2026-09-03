"""Credential resolution and storage.

Resolution order: environment variable, then OS keyring, then the local
credential file. Environment wins so CI and scheduled runs can inject
credentials without touching disk.

Storage is keyring-first. The previous behaviour -- silently writing the
password to a plaintext file on first prompt -- is gone: plaintext now
requires explicit consent, and when consent is given the path is shown so the
operator knows what they are responsible for.
"""

import getpass
import os

from .errors import NsxError, UserAbort
from .output import ask, cB, cC, cD, cG, err, is_interactive, ok_msg, say, warn
from .paths import DEFAULT_CREDS_FILE

KEYRING_SERVICE = "nsx-toolkit"

# "auto" | "keyring" | "plaintext" | "none"
_store_policy = "auto"
_creds_cache = None
_consent_cache = None


def set_store_policy(policy):
    global _store_policy
    _store_policy = policy or "auto"


def creds_file_path():
    return os.environ.get("NSX_TOOLKIT_CREDENTIALS_FILE", DEFAULT_CREDS_FILE)


def reset_cache():
    global _creds_cache, _consent_cache
    _creds_cache = None
    _consent_cache = None


# === KEYRING ===
def _keyring():
    try:
        import keyring
        # A keyring with no usable backend raises only on use, so probe it.
        keyring.get_keyring()
        return keyring
    except Exception:
        return None


def keyring_available():
    return _keyring() is not None


def _keyring_get(var):
    kr = _keyring()
    if not kr:
        return None
    try:
        return kr.get_password(KEYRING_SERVICE, var)
    except Exception:
        return None


def _keyring_set(var, value):
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.set_password(KEYRING_SERVICE, var, value)
        return True
    except Exception:
        return False


# === PLAINTEXT FILE ===
def _secure_file(path):
    """Best-effort lockdown: owner-only on POSIX, single-user ACL on Windows."""
    try:
        if os.name == "nt":
            import subprocess
            user = os.environ.get("USERNAME", "")
            domain = os.environ.get("USERDOMAIN", "")
            subprocess.run(["icacls", path, "/inheritance:r"],
                           capture_output=True, timeout=10)
            if user:
                subprocess.run(
                    ["icacls", path, "/grant:r",
                     "{}\\{}:F".format(domain, user) if domain else "{}:F".format(user)],
                    capture_output=True, timeout=10)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass  # hardening is best-effort; never block a write on it


def _load_creds_file():
    global _creds_cache
    if _creds_cache is not None:
        return _creds_cache
    creds = {}
    path = creds_file_path()
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    creds[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            pass
    _creds_cache = creds
    return creds


def _write_creds_file(updates):
    global _creds_cache
    path = creds_file_path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    existing = dict(_load_creds_file())
    existing.update({k: v for k, v in updates.items() if k})
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Managed by nsx-toolkit -- do not edit by hand.\n")
        f.write("# Use --set-credentials to update entries.\n")
        for k, v in existing.items():
            f.write('{}="{}"\n'.format(k, v))
    _secure_file(path)
    _creds_cache = None
    return path


# === RESOLVE / STORE ===
def resolve_secret(var):
    if not var:
        return None
    return (os.environ.get(var)
            or _keyring_get(var)
            or _load_creds_file().get(var))


def _plaintext_consent():
    """Ask once per run whether plaintext storage is acceptable."""
    global _consent_cache
    if _consent_cache is not None:
        return _consent_cache
    if not is_interactive():
        _consent_cache = False
        return False
    say("\n  {} No OS keyring is available on this machine.".format(cD("note:")))
    say("  Credentials can be saved to {} (readable by".format(cC(creds_file_path())))
    say("  your user account only), or not saved at all -- you would then be")
    say("  prompted each run, or set the environment variables yourself.")
    answer = ask("  Save credentials to that file? [y/N]: ",
                 default="n", allow_back=False).lower()
    _consent_cache = answer in ("y", "yes")
    return _consent_cache


def store_secrets(updates):
    """Persist {env_var: value}. Returns a short description of where they went."""
    updates = {k: v for k, v in updates.items() if k and v}
    if not updates or _store_policy == "none":
        return "not saved"
    if _store_policy in ("auto", "keyring"):
        stored = [k for k in updates if _keyring_set(k, updates[k])]
        if len(stored) == len(updates):
            return "saved to OS keyring"
        if _store_policy == "keyring":
            warn("keyring unavailable -- credentials were not saved.")
            return "not saved"
    if _store_policy == "plaintext" or _plaintext_consent():
        path = _write_creds_file(updates)
        return "saved to {}".format(path)
    return "not saved (will prompt again next run)"


def credentials_for(entry, allow_prompt=True):
    """(user, password, source) for one manager entry."""
    name = entry.get("name", "?")
    u_env = entry.get("username_env")
    p_env = entry.get("password_env")
    user, pwd = resolve_secret(u_env), resolve_secret(p_env)
    if user and pwd:
        return user, pwd, "stored"
    if not allow_prompt or not is_interactive():
        raise NsxError(
            "No credentials available for '{}'. Set {} and {}, or run "
            "--set-credentials.".format(name, u_env or "<username_env>",
                                        p_env or "<password_env>"))
    try:
        if not user:
            user = input("    username for {}: ".format(name)).strip()
        if not pwd:
            pwd = getpass.getpass("    password for {}: ".format(name))
    except (EOFError, KeyboardInterrupt):
        raise UserAbort() from None
    if not (user and pwd):
        raise NsxError("Credentials not provided for '{}'.".format(name))
    where = store_secrets({u_env: user, p_env: pwd})
    return user, pwd, "prompted, {}".format(where)


def force_set_credentials(managers, only=None):
    """--set-credentials: always prompt and overwrite whatever is stored."""
    targets = [m for m in managers if not only or m.get("name") in only]
    if not targets:
        err("No matching managers in inventory.")
        return 2
    if not is_interactive():
        err("--set-credentials needs an interactive terminal.")
        return 2
    say("\n  {} ({} manager(s)) ...".format(
        cB("Updating stored credentials"), len(targets)))
    updated = 0
    for m in targets:
        name = m.get("name", "?")
        u_env, p_env = m.get("username_env"), m.get("password_env")
        if not (u_env or p_env):
            warn("{}: no username_env/password_env in inventory, skipped.".format(name))
            continue
        try:
            user = input("    username for {}: ".format(name)).strip()
            pwd = getpass.getpass("    password for {}: ".format(name))
        except (EOFError, KeyboardInterrupt):
            raise UserAbort() from None
        if not (user and pwd):
            warn("{}: empty input, skipped.".format(name))
            continue
        where = store_secrets({u_env: user, p_env: pwd})
        ok_msg("{}: {}.".format(name, where))
        updated += 1
    say("\n  {} of {} updated.".format(cG(str(updated)), len(targets)))
    return 0
