# API Conventions

Applies to: `src/nsx_toolkit/actions/**`, `src/nsx_toolkit/commands/**`

## Actions vs commands split

- `actions/<feature>.py` — pure logic only: fetch, compute, call `exporter.stage()`. No argparse, no `ctx` attributes beyond what the action needs.
- `commands/<feature>.py` — CLI wiring only: argparse flags via `add_command()` / `add_action()`, then call the action function.
- Every new command must be registered in `commands/__init__.py` and both files added to `MODULES` in `tools/build_single_file.py`.

## HTTP calls

- All REST calls go through `Nsx` methods (`get`, `post`, `put`, `patch`, `delete`, `get_all`).
- `get_all()` paginates to exhaustion using NSX cursors — use it when you need all results.
- To get only a count, use `nsx.get(path, params={PARAM_PAGE_SIZE: 1})` and read `result_count` from the response. Never paginate just to `len()` the result.
- Never call the same endpoint twice in a function when one call suffices.

## Caching

- `nsx.all_vms()` — VM inventory; cached per `Nsx` instance. Call `invalidate_vms()` after a tag write.
- `nsx.base(domain)` — policy base URL; cached per `Nsx` instance (probed once).
- `nsx.version()` — NSX version string; cached per `Nsx` instance.
- Do not cache groups, policies, or rules across calls — stale data risk.

## GM/LM deduplication

- GM-authored policies are replicated read-only on every Local Manager. Any sweep across GM + LMs must deduplicate by NSX `path`.
- Use `sweep_rules()` from `policy.py` for DFW rule traversal. GM sessions are always processed before LM sessions — preserve this order.
- `ordered_sessions(sessions)` returns `(gm_sessions, lm_sessions)` in the correct order.

## Test coverage

- Every new NSX API endpoint needs a matching route in `tests/fake_nsx.py` before tests can be written.
- Tests use a real `ThreadingHTTPServer`, not mocks. Do not introduce mocking frameworks.
