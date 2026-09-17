# Code Style

Applies to: `src/**`, `tests/**`, `tools/**`

- Line length: 90 characters (enforced by ruff).
- Target: Python 3.9. No f-string features or syntax introduced after 3.9. Use `.format()` for string formatting.
- No runtime dependencies. `stdlib` only. `requests` is an optional transport; every code path must work without it.
- No comments that explain *what* the code does. Comments only when the *why* is non-obvious: a hidden constraint, a workaround, a subtle invariant.
- All terminal output through `say()`, `table()`, `section()`, `hr()` from `output.py`. Never `print()` directly.
- All structured output (CSV, JSON, HTML, JUnit, SARIF, Prometheus) through `exporter.stage()`.
- All per-manager fan-out through `parallel_run()` from `output.py`. Serial loops over sessions are an N+1 bug.
- Mutating actions must gate on `ctx.enable_writes` or `enable_writes` parameter.
- Module-level names are globally unique across the whole codebase (the single-file amalgam is a flat namespace).
