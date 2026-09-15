## What

Brief description of what this PR changes and why.

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] `pytest` passes locally across Python 3.9–3.13 (or CI is green)
- [ ] `ruff check src/ tests/` is clean
- [ ] `python tools/build_single_file.py --check` passes
- [ ] New API endpoints have a matching route in `tests/fake_nsx.py`
- [ ] New commands registered in `commands/__init__.py` and `MODULES` list
- [ ] `CHANGELOG.md` updated (new feature or fix)
