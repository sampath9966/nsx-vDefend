# Testing

Applies to: `tests/**`

## Verifier (non-optional)

The verifier is the gate. Every change must pass all three before it is done:

```sh
pytest                                     # 540 tests across py3.9–3.13
ruff check src/ tests/                     # lint — 90 char limit, py3.9 target
python tools/build_single_file.py --check  # amalgam must stay in sync
```

If the amalgam is stale, regenerate it: `python tools/build_single_file.py`.

## Test infrastructure

- `tests/fake_nsx.py` — `FakeNsx`: a real `ThreadingHTTPServer` that simulates NSX manager HTTP responses. State is held in plain dicts on the server instance.
- `tests/conftest.py` — `lm` fixture (a running `FakeNsx` + bound `Nsx` session) and `make_session` (factory for additional sessions).
- One test file per feature area, mirroring `src/nsx_toolkit/actions/`.

## Rules

- A failing test is never an infrastructure flake. Root-cause it; never skip or disable a test.
- New API endpoints require a new route in `fake_nsx.py` before writing tests.
- Tests must not make external network calls.
- Keep `filterwarnings = ["error::DeprecationWarning"]` — do not suppress warnings.
- Run `pytest -x` locally to stop on first failure and tighten the feedback loop.
