"""Where pip put the console script, and whether the shell can find it.

`pip install nsxctl` writes `nsxctl` (or `nsxctl.exe`) into the interpreter's
scripts directory. **Nothing in a wheel can then put that directory on PATH**
-- wheels have no install-time hook, by design -- so on a Python installed
without "Add Python to PATH", the command is present and unreachable, and the
only symptom is `nsxctl: command not found` straight after an install that
reported success. pip prints a warning about it that scrolls past.

This module answers the two questions that state raises -- where is the
launcher, and why can't the shell see it -- and applies the fix per platform.
It is deliberately import-light and touches no NSX: it has to work on a machine
where nothing else about the toolkit works yet.
"""

import os
import shutil
import sys
import sysconfig

from .errors import ConfigError
from .paths import DATA_DIR, local_stamp

# Both console scripts this package installs. The first is the one we put on
# PATH for; the second is the continuity alias and lands in the same place.
LAUNCHER_NAMES = ("nsxctl", "nsx-toolkit")

# Written into the shell rc file so a second run recognises its own work
# rather than appending the same line again.
MARKER = "# added by `nsxctl setup-path`"


def _norm_dir(directory):
    """Normalise a directory for comparison the way PATH lookup treats it.

    Variables are expanded because the Windows *user* PATH is stored raw in
    the registry -- `%USERPROFILE%\\...` -- while the PATH this process
    inherited is already expanded. Comparing the two without expanding is how
    you conclude a directory is missing when it is already configured.
    """
    if not directory or not directory.strip():
        return ""
    expanded = os.path.expanduser(os.path.expandvars(directory.strip()))
    trimmed = expanded.rstrip("\\/") or expanded
    return os.path.normcase(os.path.normpath(trimmed))


def path_entries(env_path=None):
    """The directories on PATH, in order, empties dropped."""
    raw = os.environ.get("PATH", "") if env_path is None else env_path
    return [entry for entry in raw.split(os.pathsep) if entry.strip()]


def on_path(directory, env_path=None):
    target = _norm_dir(directory)
    if not target:
        return False
    return any(_norm_dir(entry) == target for entry in path_entries(env_path))


def _user_scheme():
    """The sysconfig scheme `pip install --user` writes into."""
    try:
        return sysconfig.get_preferred_scheme("user")   # 3.10+
    except AttributeError:
        return "nt_user" if os.name == "nt" else "posix_user"


def candidate_dirs():
    """Every directory a console script for THIS interpreter could be in.

    There is more than one because the answer depends on how the toolkit was
    installed: the default scheme for a plain `pip install`, the user scheme
    for `pip install --user`, and the interpreter's own directory inside a
    virtualenv. Guessing one and reporting on it would be wrong for the other
    two, so all three are searched and the one actually holding a launcher
    wins.
    """
    found, seen = [], set()

    def add(directory):
        key = _norm_dir(directory)
        if key and key not in seen:
            seen.add(key)
            found.append(directory)

    add(sysconfig.get_path("scripts"))
    try:
        add(sysconfig.get_path("scripts", _user_scheme()))
    except (KeyError, ValueError):
        pass          # an unusual scheme name is not worth failing over
    add(os.path.dirname(os.path.abspath(sys.executable)))
    return found


def _launcher_suffixes():
    # On Windows pip writes a real .exe launcher; -script.py appears with some
    # older installers. Elsewhere the script has no extension at all.
    return (".exe", "-script.py", "") if os.name == "nt" else ("",)


def launcher_in(directory):
    """The path of a console script inside `directory`, or None."""
    if not directory or not os.path.isdir(directory):
        return None
    for name in LAUNCHER_NAMES:
        for suffix in _launcher_suffixes():
            candidate = os.path.join(directory, name + suffix)
            if os.path.isfile(candidate):
                return candidate
    return None


class PathStatus:
    """What the shell can and cannot currently see.

    `reachable` is the only thing that decides whether typing `nsxctl` works.
    The rest exists to explain why not, because "command not found" for a
    command that is definitely installed is the confusing part.
    """

    def __init__(self, directory, launcher, reachable, resolved):
        self.directory = directory
        self.launcher = launcher
        self.reachable = reachable
        self.resolved = resolved

    @property
    def installed(self):
        return self.launcher is not None

    @property
    def shadowed(self):
        """Reachable, but the name resolves to a different file than ours.

        An older copy earlier on PATH answers to `nsxctl` and the fix for
        every other problem here would not touch it.
        """
        if not self.resolved or not self.launcher:
            return False
        return _norm_dir(os.path.dirname(self.resolved)) != _norm_dir(self.directory)


def path_status(env_path=None):
    directory, launcher = None, None
    for candidate in candidate_dirs():
        found = launcher_in(candidate)
        if found:
            directory, launcher = candidate, found
            break
    if directory is None:
        # Nothing installed anywhere we can see. Report where it *would* go,
        # so the message can still say something useful.
        directory = sysconfig.get_path("scripts")
    return PathStatus(directory=directory, launcher=launcher,
                  reachable=on_path(directory, env_path),
                  resolved=shutil.which(LAUNCHER_NAMES[0]))


# === APPLYING THE FIX ===
def _backup_path_value(kind, value):
    """Keep the previous value before changing it.

    Editing PATH is the kind of change that is hard to undo from memory if it
    goes wrong, and this runs on a machine where the user is already confused
    about why something does not work.
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        path = os.path.join(
            DATA_DIR, "path-backup-{}-{}.txt".format(kind, local_stamp()))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(value)
        return path
    except OSError:
        return None      # a missing backup must not stop the repair


def _win_read_user_path():
    """(raw value, registry type) of the per-user PATH.

    Read raw on purpose: QueryValueEx does not expand REG_EXPAND_SZ, so
    `%USERPROFILE%\\bin` comes back intact and gets written back intact. A
    round trip through an expanded value would hard-code this machine's paths
    into the user's environment.
    """
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        try:
            value, kind = winreg.QueryValueEx(key, "Path")
            return value or "", kind
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ


def _win_broadcast():
    """Tell running processes the environment changed.

    Without this the new PATH reaches nothing until the next logon. Explorer
    picks the broadcast up and passes it to the shells it starts, so a newly
    opened terminal sees it. It cannot reach the shell that is running us --
    a process's environment is fixed once it starts -- which is why the
    caller still says to open a new one.
    """
    try:
        import ctypes
        result = ctypes.c_void_p()
        ctypes.windll.user32.SendMessageTimeoutW(
            0xFFFF,          # HWND_BROADCAST
            0x001A,          # WM_SETTINGCHANGE
            0,
            ctypes.c_wchar_p("Environment"),
            0x0002,          # SMTO_ABORTIFHUNG
            5000,
            ctypes.byref(result))
        return True
    except Exception:        # noqa: BLE001 - cosmetic; a new shell works regardless
        return False


def _win_apply(directory):
    import winreg
    current, kind = _win_read_user_path()
    if on_path(directory, current):
        return False, ("already in your user PATH -- open a NEW terminal for "
                       "it to take effect")
    backup = _backup_path_value("user", current)
    joined = (current.rstrip(os.pathsep) + os.pathsep + directory
              if current.strip() else directory)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                        winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, kind, joined)
    _win_broadcast()
    return True, ("added to your user PATH" +
                  (" (previous value saved to {})".format(backup)
                   if backup else ""))


def rc_file():
    """The shell startup file to append to, chosen from $SHELL.

    Guessed rather than asked for, but never guessed silently: the caller
    prints the file it picked before writing to it.
    """
    shell = os.path.basename(os.environ.get("SHELL", "")).lower()
    home = os.path.expanduser("~")
    if "fish" in shell:
        return os.path.join(home, ".config", "fish", "config.fish")
    if "zsh" in shell:
        return os.path.join(home, ".zshrc")
    if "bash" in shell:
        # macOS bash reads .bash_profile for a login shell, which is what
        # Terminal.app starts; Linux reads .bashrc.
        if sys.platform == "darwin":
            return os.path.join(home, ".bash_profile")
        return os.path.join(home, ".bashrc")
    return None


def rc_line(directory, path=None):
    """The line that puts `directory` on PATH, in the rc file's own syntax."""
    if path and path.endswith(".fish"):
        return 'fish_add_path "{}"'.format(directory)
    return 'export PATH="{}:$PATH"'.format(directory)


def _posix_apply(directory):
    path = rc_file()
    if not path:
        raise ConfigError(
            "Cannot tell which shell you use ($SHELL is unset or unknown), so "
            "there is no file to edit safely.\n"
            "  Add this line to your shell's startup file yourself:\n"
            "    {}".format(rc_line(directory)))
    line = rc_line(directory, path)
    existing = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as handle:
            existing = handle.read()
    if line in existing:
        return False, ("already in {} -- run `exec $SHELL` or open a new "
                       "terminal".format(path))
    backup = _backup_path_value("rc", existing) if existing else None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    prefix = "" if (not existing or existing.endswith("\n")) else "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{}\n{}\n{}\n".format(prefix, MARKER, line))
    return True, ("appended to {}".format(path) +
                  (" (previous contents saved to {})".format(backup)
                   if backup else ""))


def repair_path(st):
    """Put the launcher's directory on PATH. Returns (changed, detail).

    Refuses rather than guesses in the one case that matters: if no launcher
    was found, adding the directory would put an empty directory on the user's
    PATH and fix nothing, while looking like it had worked.
    """
    if not st.installed:
        raise ConfigError(
            "No nsxctl launcher found for this interpreter ({}).\n"
            "  Nothing would be gained by adding {} to PATH.\n"
            "  Install it first:  {} -m pip install --user nsxctl".format(
                sys.executable, st.directory, os.path.basename(sys.executable)))
    if os.name == "nt":
        return _win_apply(st.directory)
    return _posix_apply(st.directory)


def module_command():
    """How to invoke the toolkit when the console script is unreachable.

    `py` on Windows and the running interpreter everywhere else -- `py` is
    installed into C:\\Windows, so it is on PATH even when Python itself is
    not, which is exactly the situation this hint is printed in.
    """
    launcher = "py" if os.name == "nt" else sys.executable
    return "{} -m nsx_toolkit".format(launcher)
