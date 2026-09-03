#!/usr/bin/env python3
"""Amalgamate src/nsx_toolkit/ into the single-file nsx-toolkit.py.

The package exists so the code can be tested and maintained in pieces. The
single file exists because that is what people actually run: download one
file, run it, done. Nobody should have to pip install anything to try the
toolkit on a locked-down jumpbox.

    python3 tools/build_single_file.py            regenerate nsx-toolkit.py
    python3 tools/build_single_file.py --check    fail if it is out of date

CI runs --check, so the committed file can never drift from the package.
"""

import argparse
import ast
import collections
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "src", "nsx_toolkit")
OUTPUT = os.path.join(ROOT, "nsx-toolkit.py")

# Dependency order. Anything referenced at module level (constants, defaults
# baked into f-strings) must appear before the module that reads it.
MODULES = [
    "version.py",
    "errors.py",
    "paths.py",
    "output.py",
    "api.py",
    "taxonomy.py",
    "config.py",
    "creds.py",
    "http.py",
    "audit.py",
    "export.py",
    "render.py",
    "policy.py",
    "actions/groups.py",
    "actions/verify.py",
    "actions/dashboard.py",
    "actions/tags.py",
    "actions/bulk.py",
    "actions/reverse.py",
    "actions/parity.py",
    "actions/change_ticket.py",
    "actions/audit_view.py",
    "wizard.py",
    "menu.py",
    "commands/__init__.py",
    "commands/setup.py",
    "commands/group.py",
    "commands/tag.py",
    "commands/rule.py",
    "commands/analysis.py",
    "commands/shell.py",
    "legacy.py",
    "cli.py",
]

HEADER = '''#!/usr/bin/env python3
"""
nsx-toolkit.py -- NSX Zero Trust Segmentation Toolkit

GENERATED FILE -- do not edit directly.
Built from src/nsx_toolkit/ by tools/build_single_file.py.
Edit the package and rebuild; CI fails if this file is out of date.

Single file, no install required. Works with the 'requests' library when it is
present and falls back to the Python standard library when it is not.

    python3 nsx-toolkit.py              guided setup, then interactive menu
    python3 nsx-toolkit.py --help       every non-interactive flag
    python3 nsx-toolkit.py --dashboard  taxonomy compliance posture

DESIGN NOTES
  - API CONTRACT: every path, parameter and field is declared once, in the
    API CONTRACT section. A future NSX release changes ONE constant.
  - Credentials resolve before anything else runs, and are never printed.
  - Scope follows the action: tag ops = LMs only; group/rule ops = GM + LMs.
  - Writes are audit-logged with before/after state, and are undoable.
  - Console listings truncate for readability; exports never do.
"""
'''

FOOTER = '''

if __name__ == "__main__":
    sys.exit(main())
'''


def split_module(path):
    """(hoistable_import_lines, body_lines) with relative imports removed."""
    with open(path, encoding="utf-8") as f:
        source = f.read()
    lines = source.splitlines()
    tree = ast.parse(source, filename=path)

    drop = set()
    hoist = []
    doc_end = 0

    body = list(tree.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        doc_end = body[0].end_lineno

    # Walk the WHOLE tree, not just the top level: a relative import deferred
    # inside a function to break an import cycle is meaningless once every
    # module shares one namespace, and leaving it in produces a file that
    # raises ImportError the moment that function is called.
    replace = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        span = range(node.lineno, node.end_lineno + 1)
        if isinstance(node, ast.ImportFrom) and node.level:
            # `from . import mod` binds a MODULE object. Stripping it leaves
            # `mod.thing` as a NameError in the single file. The same syntax
            # importing a name out of __init__.py is fine, so only reject the
            # form whose target is actually one of our modules.
            for alias in node.names:
                if alias.asname:
                    raise SystemExit(
                        "{}:{}: `import {} as {}` cannot be amalgamated -- "
                        "the alias does not exist once modules share one "
                        "namespace.\n"
                        "Rename the function at its definition instead, and "
                        "import it unaliased.".format(
                            os.path.relpath(path, PKG), node.lineno,
                            alias.name, alias.asname))
            if not node.module:
                for alias in node.names:
                    if alias.name in module_basenames():
                        raise SystemExit(
                            "{}:{}: `from . import {}` cannot be amalgamated "
                            "-- it binds a module object, and the single file "
                            "has no modules.\n"
                            "Import the names instead: "
                            "`from .{} import <name>`".format(
                                os.path.relpath(path, PKG), node.lineno,
                                alias.name, alias.name))
            for ln in span:
                drop.add(ln)
            if node.col_offset:
                # Keep the enclosing block syntactically valid.
                replace[node.lineno] = " " * node.col_offset + "pass"
        elif node.col_offset == 0:
            for ln in span:
                drop.add(ln)
            hoist.append("\n".join(lines[node.lineno - 1:node.end_lineno]))

    out = []
    for i, line in enumerate(lines, 1):
        if i <= doc_end:
            continue
        if i in drop:
            if i in replace:
                out.append(replace[i])
            continue
        out.append(line)
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return hoist, out


def module_title(path):
    """First line of the module docstring, for the section banner."""
    with open(path, encoding="utf-8") as f:
        doc = ast.get_docstring(ast.parse(f.read())) or ""
    return doc.strip().splitlines()[0] if doc.strip() else ""


def module_basenames():
    """Module names that `from . import X` could be targeting."""
    return {os.path.splitext(os.path.basename(rel))[0] for rel in MODULES}


def top_level_names(path):
    """Names a module binds at module level, which become globals once every
    module shares one namespace."""
    names = []
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=path)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            names.extend(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return names


def check_collisions():
    """Two modules defining the same top-level name is invisible in the
    package (separate namespaces) and silently wrong in the single file, where
    the last definition wins for everybody. Caught here rather than in
    production: a shared EXPORT_HEADERS once made one action's CSV come out
    with another action's column names.
    """
    seen = collections.defaultdict(list)
    for rel in MODULES:
        for name in top_level_names(os.path.join(PKG, rel)):
            seen[name].append(rel)
    return {n: mods for n, mods in seen.items() if len(mods) > 1}


def build():
    clashes = check_collisions()
    if clashes:
        lines = ["Top-level name collisions between modules:"]
        for name, mods in sorted(clashes.items()):
            lines.append("  {} defined in {}".format(name, ", ".join(mods)))
        lines.append("Rename them: the single file shares one namespace, so the "
                     "last definition would silently win.")
        raise SystemExit("\n".join(lines))
    imports = []
    seen = set()
    chunks = []
    for rel in MODULES:
        path = os.path.join(PKG, rel)
        if not os.path.isfile(path):
            raise SystemExit("missing module: {}".format(path))
        hoist, body = split_module(path)
        for imp in hoist:
            if imp not in seen:
                seen.add(imp)
                imports.append(imp)
        title = module_title(path)
        banner = "# {}\n# {}  --  {}\n# {}".format(
            "=" * 74, rel, title, "=" * 74)
        chunks.append("{}\n\n{}".format(banner, "\n".join(body)))

    parts = [HEADER, "", "\n".join(sorted(set(imports))), "", ""]
    parts.append("\n\n\n".join(chunks))
    parts.append(FOOTER)
    text = "\n".join(parts)
    if not text.endswith("\n"):
        text += "\n"
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="Exit non-zero if nsx-toolkit.py is out of date.")
    ap.add_argument("--output", default=OUTPUT)
    args = ap.parse_args()

    text = build()
    # Fail fast on a build that produced something unparseable.
    ast.parse(text, filename=args.output)

    if args.check:
        if not os.path.isfile(args.output):
            print("MISSING: {} has never been built.".format(args.output))
            return 1
        with open(args.output, encoding="utf-8") as f:
            current = f.read()
        if current != text:
            print("STALE: {} does not match src/nsx_toolkit/.".format(args.output))
            print("Run: python3 tools/build_single_file.py")
            return 1
        print("OK: {} matches the package.".format(os.path.basename(args.output)))
        return 0

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(args.output, 0o755)
    except OSError:
        pass
    lines = text.count("\n")
    print("Wrote {} ({} lines from {} modules).".format(
        args.output, lines, len(MODULES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
