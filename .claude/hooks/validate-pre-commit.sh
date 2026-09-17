#!/usr/bin/env bash
# Pre-commit verifier: runs the three CI gates locally before any commit.
# Wire this up via .git/hooks/pre-commit or a git hooks manager.
set -euo pipefail

echo "==> lint"
ruff check src/ tests/

echo "==> single-file sync"
python tools/build_single_file.py --check

echo "==> tests (fast subset — changed files only)"
# Run only tests related to changed source files if pytest-changed is available,
# otherwise run the full suite.
if python -c "import pytest_changed" 2>/dev/null; then
    pytest -q --changed
else
    pytest -q
fi

echo "==> all checks passed"
