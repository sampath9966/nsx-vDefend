"""Whether the shell can find the command pip just installed.

The failure this covers is the first thing a Windows user hits and the one
thing a green test suite would never notice: `pip install nsxctl` succeeds,
writes `nsxctl.exe`, and the shell says command not found because the scripts
directory was never on PATH. Nothing in the wheel can fix that at install
time, so the repair is a command -- and a repair that reports success without
repairing anything is worse than no repair at all.
"""

import os

import pytest

from nsx_toolkit import launcher
from nsx_toolkit.errors import ConfigError


@pytest.fixture
def scripts(tmp_path):
    """A scripts directory with a launcher in it, as pip would leave one."""
    d = tmp_path / "Scripts"
    d.mkdir()
    (d / "nsxctl").write_text("#!/usr/bin/env python\n", encoding="utf-8")
    return str(d)


# --- is the directory on PATH ------------------------------------------
def test_a_directory_on_path_is_recognised(scripts):
    assert launcher.on_path(scripts, os.pathsep.join(["/usr/bin", scripts]))
    assert not launcher.on_path(scripts, "/usr/bin")


def test_a_trailing_separator_is_still_the_same_directory(scripts):
    """PATH entries are written by hand and by installers, and the two do not
    agree about trailing slashes. Treating them as different directories
    would add a duplicate entry to the user's PATH every run."""
    assert launcher.on_path(scripts, scripts + os.sep)
    assert launcher.on_path(scripts + os.sep, scripts)


def test_an_unexpanded_variable_is_resolved_before_comparing(monkeypatch,
                                                             scripts):
    """The Windows user PATH is stored raw in the registry, so it can contain
    %USERPROFILE%\\... while the PATH this process inherited is expanded.
    Comparing them literally reports a directory as missing when it is
    already configured, and appends it a second time.
    """
    monkeypatch.setenv("NSXTEST_HOME", scripts)
    raw = "%NSXTEST_HOME%" if os.name == "nt" else "$NSXTEST_HOME"
    assert launcher.on_path(scripts, raw)


def test_empty_path_entries_are_ignored():
    assert launcher.path_entries(os.pathsep.join(["/a", "", "  ", "/b"])) == \
        ["/a", "/b"]


# --- finding the launcher ----------------------------------------------
def test_a_launcher_is_found_in_the_scripts_directory(scripts):
    assert launcher.launcher_in(scripts) == os.path.join(scripts, "nsxctl")


def test_an_empty_or_missing_directory_holds_no_launcher(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert launcher.launcher_in(str(empty)) is None
    assert launcher.launcher_in(str(tmp_path / "nope")) is None
    assert launcher.launcher_in(None) is None


def test_status_reports_the_directory_that_actually_holds_the_launcher(
        monkeypatch, tmp_path, scripts):
    """Several directories could hold it -- the default scheme, the --user
    scheme, a virtualenv -- so the one that does is the one to report on."""
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setattr(launcher, "candidate_dirs",
                        lambda: [str(other), scripts])
    st = launcher.path_status(env_path="/usr/bin")
    assert st.directory == scripts
    assert st.installed
    assert not st.reachable


def test_status_is_reachable_once_the_directory_is_on_path(monkeypatch,
                                                           scripts):
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    st = launcher.path_status(env_path=os.pathsep.join(["/usr/bin", scripts]))
    assert st.reachable


def test_a_launcher_earlier_on_path_is_reported_as_shadowing(monkeypatch,
                                                             tmp_path, scripts):
    """First match wins on PATH, so an older copy in front of ours answers to
    the name. Appending our directory cannot beat it, and saying "fixed"
    would leave the same copy winning."""
    older = tmp_path / "older"
    older.mkdir()
    (older / "nsxctl").write_text("", encoding="utf-8")
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setattr(launcher.shutil, "which",
                        lambda _n: str(older / "nsxctl"))
    st = launcher.path_status(env_path=scripts)
    assert st.shadowed


# --- applying the fix ---------------------------------------------------
def test_it_refuses_to_put_an_empty_directory_on_path(monkeypatch, tmp_path):
    """Adding a directory with no launcher in it changes nothing and looks
    like it worked, which is the one outcome worth refusing outright."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [str(empty)])
    st = launcher.path_status(env_path="/usr/bin")
    assert not st.installed
    with pytest.raises(ConfigError) as excinfo:
        launcher.repair_path(st)
    assert "pip install" in str(excinfo.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX rc-file path")
def test_the_rc_file_gets_one_line_and_only_one(monkeypatch, tmp_path,
                                                scripts):
    rc = tmp_path / ".zshrc"
    rc.write_text("# existing\n", encoding="utf-8")
    monkeypatch.setattr(launcher, "rc_file", lambda: str(rc))
    monkeypatch.setattr(launcher, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    st = launcher.path_status(env_path="/usr/bin")

    changed, detail = launcher.repair_path(st)
    assert changed and str(rc) in detail
    body = rc.read_text(encoding="utf-8")
    assert "# existing" in body                 # nothing was overwritten
    assert launcher.MARKER in body
    assert scripts in body

    # Running it twice is the normal case: the user re-runs it because the
    # terminal they were in still cannot see the command.
    changed_again, _ = launcher.repair_path(st)
    assert not changed_again
    assert rc.read_text(encoding="utf-8").count(launcher.MARKER) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX rc-file path")
def test_the_previous_rc_contents_are_backed_up_before_editing(
        monkeypatch, tmp_path, scripts):
    rc = tmp_path / ".bashrc"
    rc.write_text("# precious\n", encoding="utf-8")
    data = tmp_path / "data"
    monkeypatch.setattr(launcher, "rc_file", lambda: str(rc))
    monkeypatch.setattr(launcher, "DATA_DIR", str(data))
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    launcher.repair_path(launcher.path_status(env_path="/usr/bin"))
    backups = list(data.glob("path-backup-*.txt"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "# precious\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX rc-file path")
def test_an_unknown_shell_is_refused_rather_than_guessed(monkeypatch, scripts):
    """Writing to the wrong startup file leaves the user with an edit they
    did not make and a command that still does not work."""
    monkeypatch.setenv("SHELL", "/usr/bin/somethingelse")
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    st = launcher.path_status(env_path="/usr/bin")
    with pytest.raises(ConfigError) as excinfo:
        launcher.repair_path(st)
    assert "export PATH" in str(excinfo.value)


@pytest.mark.parametrize("shell,expected", [
    ("/bin/zsh", ".zshrc"),
    ("/usr/bin/fish", "config.fish"),
])
def test_the_rc_file_follows_the_shell(monkeypatch, shell, expected):
    monkeypatch.setenv("SHELL", shell)
    assert launcher.rc_file().endswith(expected)


def test_fish_gets_fish_syntax():
    """`export PATH=...` is not valid fish, and a broken startup file breaks
    every future shell, not just this command."""
    assert launcher.rc_line("/x", "/home/u/.config/fish/config.fish") == \
        'fish_add_path "/x"'
    assert "export PATH" in launcher.rc_line("/x", "/home/u/.zshrc")


def test_the_fallback_command_names_an_interpreter_that_is_on_path():
    """The whole point of the hint: it has to work in the situation that
    produced it. On Windows `py` lives in C:\\Windows, which is on PATH even
    when Python's own directory is not."""
    command = launcher.module_command()
    assert command.endswith("-m nsx_toolkit")
    assert command.startswith("py " if os.name == "nt" else os.sep)


# --- the command ---------------------------------------------------------
def test_check_exits_nonzero_when_the_command_is_unreachable(monkeypatch,
                                                             scripts):
    """--check is what a script or a support ticket runs: it must report the
    problem in the exit code, and it must not change anything."""
    from nsx_toolkit import cli

    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setenv("PATH", "/usr/bin")
    assert cli.main(["setup-path", "--check"]) == 1


def test_check_exits_zero_when_it_is_reachable(monkeypatch, scripts):
    from nsx_toolkit import cli

    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setattr(launcher.shutil, "which",
                        lambda _n: os.path.join(scripts, "nsxctl"))
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", scripts]))
    assert cli.main(["setup-path", "--check"]) == 0


def test_it_changes_nothing_without_a_confirmation(monkeypatch, tmp_path,
                                                   scripts):
    """Editing PATH is a change to the user's environment, so it goes through
    the same confirmation gate as everything else that writes."""
    from nsx_toolkit import cli

    rc = tmp_path / ".zshrc"
    rc.write_text("# untouched\n", encoding="utf-8")
    monkeypatch.setattr(launcher, "rc_file", lambda: str(rc))
    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setenv("PATH", "/usr/bin")

    # Non-interactive without --yes is a refusal, never an assumed yes.
    assert cli.main(["setup-path", "--non-interactive"]) == 1
    assert rc.read_text(encoding="utf-8") == "# untouched\n"


def test_the_module_hint_fires_only_for_a_stranded_install(monkeypatch, capsys,
                                                           scripts):
    """`python -m nsx_toolkit` is the tell-tale of an install the shell cannot
    find -- but only when it really cannot find it, or the hint is noise on
    every run."""
    from nsx_toolkit import cli

    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)

    monkeypatch.setenv("PATH", "/usr/bin")
    cli._module_launch_hint([])
    assert "setup-path" in capsys.readouterr().err

    monkeypatch.setattr(launcher.shutil, "which",
                        lambda _n: os.path.join(scripts, "nsxctl"))
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", scripts]))
    cli._module_launch_hint([])
    assert capsys.readouterr().err == ""


def test_the_module_hint_stays_out_of_json_output(monkeypatch, capsys,
                                                  scripts):
    """--json output gets parsed. A helpful line in the middle of it is a
    broken pipeline."""
    from nsx_toolkit import cli

    monkeypatch.setattr(launcher, "candidate_dirs", lambda: [scripts])
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin")
    cli._module_launch_hint(["--json", "compliance"])
    assert capsys.readouterr().err == ""
