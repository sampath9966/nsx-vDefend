# /hygiene

Run the full verifier suite for this project — the three checks CI requires.

```sh
ruff check src/ tests/ && \
python tools/build_single_file.py --check && \
pytest -q
```

Runs lint first (fastest), then single-file sync, then the full test suite. Exits non-zero on any failure.
