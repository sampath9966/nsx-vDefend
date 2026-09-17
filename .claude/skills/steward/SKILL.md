# PR Steward — nsxctl

This skill governs how Claude Code drives PRs in this repository to a mergeable state.

## Verifier (the gate — non-optional)

A PR is not done until all of these pass on the head commit:

1. `ruff check src/ tests/` — lint, 90-char limit, py3.9 target
2. `python tools/build_single_file.py --check` — amalgam in sync
3. `pytest` across py3.9–3.13 — all 540 tests green

If the amalgam is stale after any source change: run `python tools/build_single_file.py` and commit `nsx-toolkit.py` alongside the source change. Forgetting this is the single most common CI failure.

## Sub-agent split (maker vs checker)

- **Writer agent** drafts the change.
- **Reviewer agent** (separate context) grades it against the rules in `.claude/rules/`.
- Do not merge maker and checker into the same context.

## Posture

- Never skip, disable, or quarantine a test. A failing test is a bug, not an infra flake.
- Never push an empty commit to kick CI.
- A serial loop over NSX sessions is always an N+1 bug — use `parallel_run()`.
- New source files must be added to `MODULES` in `tools/build_single_file.py` or CI will fail.
- No runtime dependencies — stdlib only at runtime.

## Connectors in use

- GitHub (PR creation, CI status, review comments) — via `mcp__github__*` tools.

## Loop schedule

For watched PRs: check in every 30 minutes while CI is running, every hour while waiting on reviewer.
