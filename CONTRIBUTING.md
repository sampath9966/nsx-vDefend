# Contributing

## Development setup

```sh
git clone https://github.com/sampath9966/nsx-vDefend.git
cd nsx-vDefend
pip install -e ".[dev]"
```

This installs `pytest`, `ruff`, and `requests` (used by the optional HTTP transport). No other dependencies are needed.

---

## Running the test suite

```sh
# Full suite
pytest

# Specific file
pytest tests/test_hygiene.py -v

# Stop on first failure
pytest -x
```

The suite uses a real `ThreadingHTTPServer` (no mocking frameworks) to simulate NSX managers. Tests run entirely in-process — no external network access is required.

CI runs pytest across **Python 3.9, 3.10, 3.11, 3.12 and 3.13**. Keep all five green.

---

## Lint

```sh
ruff check src/ tests/
```

`ruff` is configured in `pyproject.toml`. The line length is 90. The target is Python 3.9, so f-strings must not use features introduced after 3.9.

Autofix safe violations:

```sh
ruff check src/ tests/ --fix
```

---

## Single-file build

`nsxctl` ships as both a package and a zero-dependency amalgam (`nsx-toolkit.py`). The build tool concatenates all source modules in dependency order into one file:

```sh
python tools/build_single_file.py
```

CI verifies that the committed `nsx-toolkit.py` is in sync with the source tree:

```sh
python tools/build_single_file.py --check
```

**If you add a new source file** under `src/nsx_toolkit/`, add it to the `MODULES` list in `tools/build_single_file.py` in dependency order (imports first). CI will fail until the check passes.

---

## Project structure

```
src/nsx_toolkit/
├── api.py            # Path constants, field name constants, path-builder functions
├── http.py           # Nsx session class — all REST calls go through here
├── policy.py         # High-level policy helpers (group inventory, rule sweep)
├── authoring.py      # Revision-checked write engine
├── output.py         # say(), table(), section(), colours, parallel_run()
├── export.py         # Exporter — --out-csv / --out-json / --out-html / ...
├── actions/          # One file per feature area (read-only logic)
├── commands/         # One file per command noun (CLI wiring)
└── cli.py            # Entry point, context object

tests/
├── conftest.py       # lm, make_session fixtures
├── fake_nsx.py       # FakeNsx — ThreadingHTTPServer NSX simulator
└── test_*.py         # One test file per feature area

tools/
└── build_single_file.py   # Amalgam builder
```

---

## Adding a command

1. Create `src/nsx_toolkit/actions/<feature>.py` — pure logic, no argparse.
2. Create `src/nsx_toolkit/commands/<feature>.py` — CLI wiring via `add_command()` / `add_action()`.
3. Add the `register_<feature>` import and registration in `src/nsx_toolkit/commands/__init__.py`.
4. Add both files to `MODULES` in `tools/build_single_file.py`.
5. Add fake NSX routes (new state fields + GET handlers) in `tests/fake_nsx.py`.
6. Write tests in `tests/test_<feature>.py`.
7. Run `pytest` and `python tools/build_single_file.py --check`.

---

## Coding conventions

- **No runtime dependencies.** Use `stdlib` only. `requests` is an optional transport; new code must work without it.
- **Read by default.** Mutating actions must gate on `enable_writes` and use `confirm()` or `--yes`.
- **All structured output through `exporter.stage()`.** CLI output uses `say()`, `table()`, `section()` from `output.py`.
- **`parallel_run()` for fan-out.** All per-session fetches should use `parallel_run()` from `output.py`.
- **Top-level names in the amalgam share one namespace.** Check for collisions before adding a module-level name that might exist elsewhere.
- **No comments explaining what the code does.** Add a comment only when the *why* is non-obvious: a hidden constraint, a workaround, a subtle invariant.

---

## Pull request checklist

- [ ] `pytest` passes on all five Python versions locally (or CI is green)
- [ ] `ruff check src/ tests/` is clean
- [ ] `python tools/build_single_file.py --check` passes
- [ ] New API endpoints have a matching route in `tests/fake_nsx.py`
- [ ] New commands are registered in `commands/__init__.py` and listed in `MODULES`
