"""What `pip install nsxctl` actually gives someone.

The failure this guards against is specific and has happened in this repo
before, in the amalgamator: a new module is added, nothing imports it at
collection time, and it is silently left out of the shipped artefact. The
package equivalent is a subdirectory with no `__init__.py` -- setuptools'
`packages.find` simply does not see it, the wheel is built without complaint,
and the command dies with ImportError on a machine that is not the developer's.

These tests do not build a wheel. Building needs an isolated environment and a
network, which makes it the wrong shape for the default suite. They assert the
invariants a build would depend on, so a break is caught in milliseconds
rather than in someone else's `pip install`.

The end-to-end counterpart -- build a wheel, install it into a clean
virtualenv, drive the installed console script against a fake NSX -- lives in
`tools/verify_install.py`, which is run before a release.
"""

import ast
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
PKG = os.path.join(SRC, "nsx_toolkit")


def _package_dirs():
    """Every directory under src/ that holds Python modules."""
    found = []
    for dirpath, dirnames, filenames in os.walk(PKG):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        if any(f.endswith(".py") for f in filenames):
            found.append(dirpath)
    return sorted(found)


def test_every_directory_of_modules_is_an_importable_package():
    """A directory of modules without __init__.py is invisible to the build.

    setuptools finds packages, not files. A subdirectory that is missing its
    __init__.py is not a package, so nothing in it reaches the wheel -- and
    the only symptom is an ImportError for the user, long after the build
    reported success.
    """
    missing = [os.path.relpath(d, SRC) for d in _package_dirs()
               if not os.path.isfile(os.path.join(d, "__init__.py"))]
    assert not missing, (
        "these directories ship modules but are not packages, so setuptools "
        "will leave them out of the wheel: {}".format(missing))


def _declared_scripts():
    """{command: "module:attr"} from pyproject's [project.scripts]."""
    path = os.path.join(ROOT, "pyproject.toml")
    scripts, in_section = {}, False
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("["):
                in_section = line == "[project.scripts]"
                continue
            if not in_section or not line or line.startswith("#"):
                continue
            name, _, target = line.partition("=")
            scripts[name.strip()] = target.strip().strip('"')
    return scripts


def test_console_scripts_are_declared():
    """The whole point of the package: `nsxctl` on PATH after an install."""
    scripts = _declared_scripts()
    assert "nsxctl" in scripts, "pyproject declares no nsxctl command"
    # The single-file name kept working on purpose; dropping it silently
    # would break anyone's existing scripts.
    assert "nsx-toolkit" in scripts, "the nsx-toolkit continuity alias was dropped"


@pytest.mark.parametrize("command", sorted(_declared_scripts()))
def test_each_console_script_points_at_something_real(command):
    """An entry point naming a function that does not exist still installs.

    pip is perfectly happy to write a launcher for `module:attr` where attr
    was renamed. It fails at the moment the user runs it, which is the worst
    possible time to find out.
    """
    module, _, attr = _declared_scripts()[command].partition(":")
    relative = os.path.join(*module.split(".")) + ".py"
    source_file = os.path.join(SRC, relative)
    assert os.path.isfile(source_file), (
        "{} points at module {}, which is not in src/".format(command, module))

    # Parsed rather than imported: this must hold for the file as shipped,
    # without depending on import side effects or optional dependencies.
    with open(source_file, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=source_file)
    defined = {node.name for node in tree.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                    ast.ClassDef))}
    defined.update(target.id for node in tree.body
                   if isinstance(node, ast.Assign)
                   for target in node.targets if isinstance(target, ast.Name))
    assert attr in defined, (
        "{} points at {}:{}, which that module does not define".format(
            command, module, attr))


def test_the_package_declares_no_mandatory_dependencies():
    """The toolkit must install on a jumpbox with no package access.

    A stdlib-only transport is the reason this holds; a dependency added
    without noticing would quietly break the environments this tool exists
    to work in. Optional extras are fine -- a hard requirement is not.
    """
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        text = f.read()
    body = text.split("dependencies = ", 1)[1].lstrip()
    assert body.startswith("[]"), (
        "a mandatory dependency was added; the toolkit is meant to install "
        "and run with the standard library alone")


def test_the_declared_version_matches_the_shipped_one():
    """pyproject decides what PyPI records; version.py decides what the tool
    prints. A mismatch ships a package whose own `--version` disagrees with
    the index it came from, and nothing else catches it.
    """
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        declared = None
        for line in f:
            if line.startswith("version = "):
                declared = line.partition("=")[2].strip().strip('"')
                break
    assert declared, "pyproject declares no version"

    source = os.path.join(PKG, "version.py")
    with open(source, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=source)
    shipped = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "VERSION":
                    shipped = node.value.value
    assert shipped == declared, (
        "pyproject says {} but version.py says {}".format(declared, shipped))
