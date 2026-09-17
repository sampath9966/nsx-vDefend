# /add-command

Scaffold a new nsxctl command. Steps (in order — do not skip any):

1. Create `src/nsx_toolkit/actions/<feature>.py` — pure logic, no argparse.
2. Create `src/nsx_toolkit/commands/<feature>.py` — CLI wiring via `add_command()` / `add_action()`.
3. Register in `src/nsx_toolkit/commands/__init__.py`.
4. Add both files to `MODULES` in `tools/build_single_file.py` (in dependency order — imports first).
5. Add fake NSX routes to `tests/fake_nsx.py`.
6. Write tests in `tests/test_<feature>.py`.
7. Run `/hygiene` to verify everything is green.

Check module-level names for collisions with the flat amalgam namespace before adding any.
