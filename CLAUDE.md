# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
# Install for development
pip install -e ".[dev]"

# Run all tests (~540, ~3 min)
pytest

# Run a single test file
pytest tests/test_hygiene.py -v

# Stop on first failure
pytest -x

# Lint
ruff check src/ tests/

# Autofix lint
ruff check src/ tests/ --fix

# Verify the single-file amalgam is in sync (CI will fail if stale)
python tools/build_single_file.py --check

# Regenerate the amalgam after any source change
python tools/build_single_file.py
```

**Every PR must pass all five of these before merge:** `pytest` (3.9–3.13), `ruff check`, and `build_single_file.py --check`.

---

## Architecture

### Dual-distribution model

The package ships two ways simultaneously:

1. **Installable package** — `src/nsx_toolkit/` consumed via `pip install nsxctl`.
2. **Zero-dependency amalgam** — `nsx-toolkit.py`, a single file built by `tools/build_single_file.py` that concatenates all modules in dependency order. All new modules must be added to the `MODULES` list in that builder.

Because `nsx-toolkit.py` is a flat namespace, every module-level name must be globally unique across the whole codebase.

### Transport layer (`http.py`)

`Nsx` is the only class that issues HTTP calls. Two transports plug in:

- `RequestsTransport` — used when `requests` is installed (connection pool, keep-alive).
- `UrllibTransport` — stdlib fallback; no third-party deps required.

All calls go through `Nsx._req()` which handles retry/backoff for 429/50x. Key caches on `Nsx`:

| Cache | Invalidated by |
|---|---|
| Session token (`_ensure_auth`) | Never within a process |
| Policy base URL (`base()`) | Never within a process |
| NSX version (`version()`) | Never within a process |
| VM index (`all_vms()`) | `invalidate_vms()` after a tag write |

### Fan-out pattern

`parallel_run()` in `output.py` is the standard way to issue the same call across multiple managers concurrently. All per-manager fetches — policies, rules, groups, services — must go through `parallel_run()`. Serial loops over sessions are an N+1 bug.

### GM/LM deduplication (`policy.py`)

GM-authored policies are realized read-only on every Local Manager beneath the Global Manager. `sweep_rules()` deduplicates by NSX `path`, scanning GM sessions first so GM-origin rules are attributed to the GM once and never re-listed per LM. Any traversal that reads policies+rules across multiple managers must use this sweep or implement equivalent dedup.

### Actions vs commands split

- `src/nsx_toolkit/actions/<feature>.py` — pure logic: fetches data, builds rows, calls `exporter.stage()`. No argparse.
- `src/nsx_toolkit/commands/<feature>.py` — CLI wiring only: `add_command()` / `add_action()`, argparse flags, calls the action function.
- `src/nsx_toolkit/commands/__init__.py` — registers every command; new commands must be added here.

### Output discipline

All terminal output goes through `output.py`: `say()`, `table()`, `section()`, `hr()`. All structured output (CSV, JSON, HTML, JUnit, SARIF, Prometheus) goes through `exporter.stage()`. Never print directly.

### Write guard

All mutating commands must gate on `ctx.enable_writes`. Omitting `--enable-writes` produces a dry-run preview with no API side-effects.

### Test infrastructure (`tests/`)

Tests use a real `ThreadingHTTPServer` (`fake_nsx.py`) that simulates NSX manager APIs — no mocking frameworks. When adding a new API endpoint, add a matching route in `fake_nsx.py` before writing tests. The `lm` and `make_session` fixtures in `conftest.py` wire the fake server to an `Nsx` session.

### No runtime dependencies

`stdlib` only at runtime. `requests` is an optional transport — all new code must work without it. Never add a runtime dependency to `pyproject.toml [project.dependencies]`.
