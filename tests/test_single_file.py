"""The generated single file must always match the package.

The single file is what people download and run, so a stale one is worse than
no build step at all. These tests are the reason the generated-artifact
approach is safe.
"""

import ast
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER = os.path.join(ROOT, "tools", "build_single_file.py")
SINGLE = os.path.join(ROOT, "nsx-toolkit.py")


def test_single_file_is_in_sync_with_the_package():
    result = subprocess.run(
        [sys.executable, BUILDER, "--check"],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, (
        "nsx-toolkit.py is stale.\n"
        "Run: python3 tools/build_single_file.py\n" + result.stdout + result.stderr)


def test_single_file_parses():
    with open(SINGLE, encoding="utf-8") as f:
        ast.parse(f.read(), filename=SINGLE)


def test_no_relative_imports_survive_the_build():
    """A relative import left anywhere in the amalgamated file raises
    ImportError the moment that code path runs."""
    with open(SINGLE, encoding="utf-8") as f:
        source = f.read()
    leftovers = re.findall(r"^\s*from\s+\.\S*\s+import", source, re.MULTILINE)
    assert leftovers == []


def test_single_file_runs_standalone():
    result = subprocess.run(
        [sys.executable, SINGLE, "--version"],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0
    assert "NSX Toolkit" in result.stdout


def test_single_file_help_lists_the_commands():
    result = subprocess.run(
        [sys.executable, SINGLE, "--help"],
        capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0
    for command in ("init", "status", "group", "tag", "rule", "impact",
                    "parity", "compliance", "audit", "completion"):
        assert command in result.stdout
    for flag in ("--taxonomy", "--yes", "--debug", "--json"):
        assert flag in result.stdout


def test_every_command_has_its_own_help():
    """`nsxctl <command> --help` must work for all of them, not just the root."""
    for command in ("init", "status", "managers", "login", "config", "group",
                    "tag", "rule", "impact", "parity", "compliance", "audit",
                    "menu", "completion", "version"):
        result = subprocess.run(
            [sys.executable, SINGLE, command, "--help"],
            capture_output=True, text=True, cwd=ROOT)
        assert result.returncode == 0, "{}: {}".format(command, result.stderr)
        assert "usage: nsxctl {}".format(command) in result.stdout


def test_first_run_without_an_inventory_gives_guidance_not_a_bare_error(tmp_path):
    """The single most common reason a tool gets abandoned."""
    envvars = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    result = subprocess.run(
        [sys.executable, SINGLE, "--dashboard", "--non-interactive"],
        capture_output=True, text=True, cwd=str(tmp_path), env=envvars)
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "inventory.json" in combined
    assert "managers" in combined       # a copyable example
    assert "--inventory" in combined    # and the way out


def test_no_top_level_name_collisions_between_modules():
    """Separate modules have separate namespaces; the single file has one.

    A name defined in two modules is invisible in the package and silently
    wrong in the single file, where the last definition wins for everyone.
    A shared EXPORT_HEADERS once made the dashboard's CSV come out with the
    audit log's column names.
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_single_file

    clashes = build_single_file.check_collisions()
    assert clashes == {}, "collisions: " + ", ".join(
        "{} in {}".format(n, "+".join(m)) for n, m in clashes.items())


def test_builder_refuses_to_build_when_names_collide(tmp_path, monkeypatch):
    """The guard itself must work, not just happen to find nothing today."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_single_file

    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text('"""A."""\nSHARED = 1\n', encoding="utf-8")
    b.write_text('"""B."""\nSHARED = 2\n', encoding="utf-8")
    monkeypatch.setattr(build_single_file, "PKG", str(tmp_path))
    monkeypatch.setattr(build_single_file, "MODULES", ["a.py", "b.py"])

    assert build_single_file.check_collisions() == {"SHARED": ["a.py", "b.py"]}
    with pytest.raises(SystemExit) as exc:
        build_single_file.build()
    assert "SHARED" in str(exc.value)
