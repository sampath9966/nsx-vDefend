# NSX Toolkit

A single-file command-line tool for working with VMware NSX groups, tags and
distributed firewall rules across a Global Manager and any number of Local
Managers.

No installation. Download one file and run it.

```bash
curl -O https://raw.githubusercontent.com/sampath9966/nsx-vDefend/main/nsx-toolkit.py
python3 nsx-toolkit.py
```

The first run has nothing to configure by hand: it asks for your managers,
stores your credentials, checks it can reach each one, and drops you into the
menu. `requests` is used when it is installed and the standard library is used
when it is not, so this works on a locked-down jumpbox with no pip access.

---

## What it does

**Inspect**
- Search groups on GM and LMs, with their membership criteria and VM members
- Show every tag on a VM, validated against your taxonomy
- Find every VM carrying a given tag scope and/or value
- Compliance dashboard: per-scope coverage and per-manager tagging progress

**Analyse**
- Reverse lookup: VM → groups → the DFW rules that reference them, so you can
  see the blast radius before changing a tag
- Parity validation: which members a static group has that its dynamic
  replacement does not, which is the actual measure of migration progress

**Change**
- Add and remove tags interactively, or in bulk from a CSV
- Every write is dry-run first, audit-logged with before/after state, and
  undoable
- Generate a change plan document, validated against live NSX

Everything exports to CSV or JSON. Everything works non-interactively for
scripts and scheduled jobs.

---

## Quickstart

```bash
python3 nsx-toolkit.py                 # guided setup, then the menu
python3 nsx-toolkit.py --verify        # can I reach and authenticate everywhere?
python3 nsx-toolkit.py --dashboard     # tagging posture across all LMs
```

Common non-interactive runs:

```bash
# Which VMs are tagged env=prod?
nsx-toolkit.py --all-lm --vms-by-tag --scope env --tag prod --out-csv prod.csv

# What would break if I retag this VM?
nsx-toolkit.py --reverse-lookup web-prod-01

# Preview a bulk change, then apply it
nsx-toolkit.py --bulk-tag changes.csv --dry-run
nsx-toolkit.py --bulk-tag changes.csv --enable-writes --yes

# Feed a monitoring system
nsx-toolkit.py --dashboard --json
```

`--debug` logs every HTTP method, URL, status and timing to stderr. It is the
first thing to reach for when an API path behaves differently on your NSX
version.

---

## Configuration

### inventory.json

Looked for in the current directory, then `~/.nsx_toolkit/`. Override with
`--inventory <path>`. The setup wizard writes it for you; see
[`examples/inventory.example.json`](examples/inventory.example.json).

```json
{"managers": [
  {"name": "lm-london", "role": "lm", "host": "lm-lon.example.com",
   "port": 443, "verify_ssl": false, "auth": "session",
   "username_env": "NSX_LM_LONDON_USER",
   "password_env": "NSX_LM_LONDON_PASS"}
]}
```

| Field | Meaning |
|---|---|
| `name` | Short label used everywhere in output and in `--manager` |
| `role` | `gm` or `lm`. Tags and VM inventory are LM-only; groups and policies exist on both |
| `host`, `port` | Manager address. Port defaults to 443 |
| `verify_ssl` | `false` for self-signed certificates. TLS warnings are suppressed only for the managers that set this |
| `ca_bundle` | CA bundle to verify against, when `verify_ssl` is true |
| `auth` | `session` (default), `basic`, `token`, or `cert` |
| `timeout` | Per-request seconds. Default 30 |
| `username_env`, `password_env` | Environment variable names the credentials resolve from |

### taxonomy.json (optional)

Your tag scheme. Without one, the built-in default is used. Save it next to
`inventory.json` or pass `--taxonomy <path>`. See
[`examples/taxonomy.example.json`](examples/taxonomy.example.json).

```json
{
  "format": "^[a-z0-9][a-z0-9\\-]*$",
  "allow_unknown_scopes": false,
  "scopes": {
    "business-unit": {"required": true},
    "zone":          {"required": true, "values": ["red", "amber", "green"]},
    "owner":         {"required": false}
  }
}
```

`required` scopes drive the compliance dashboard. `values`, when present,
restricts what a scope may be set to. YAML is also accepted if you happen to
have PyYAML installed; JSON is used everywhere else so nothing needs
installing.

### Bulk tagging CSV

```csv
vm_name,scope,tag,action
web-prod-01,env,prod,add
web-prod-01,env,dev,remove
```

`action` is `add` or `remove`. Rows with an unknown VM or a malformed action
are reported individually rather than failing the whole file. See
[`examples/bulk-tags.example.csv`](examples/bulk-tags.example.csv).

### Credentials

Resolved in this order:

1. Environment variables named by `username_env` / `password_env`
2. The OS keyring
3. A local credentials file

Environment wins, so CI and scheduled jobs can inject credentials without
touching disk. When you are prompted, the values are stored in the OS keyring
where one exists. If there is no keyring, you are asked whether to write them
to a file — it is never done silently. `--store keyring|plaintext|none`
overrides that decision, and `--set-credentials` re-enters them.

---

## Safety model

- **Read-only by default.** Writes need `--enable-writes` (or menu option 12).
- **Dry run always runs first.** `--bulk-tag` prints the full plan before
  anything is applied, in both the CLI and the menu.
- **Non-interactive writes need `--yes`.** Without a terminal and without
  `--yes`, the toolkit refuses rather than assuming consent.
- **Concurrent edits are detected.** Each VM is re-read immediately before it
  is written; if its tags changed since the plan was computed, the row fails
  instead of overwriting someone else's change. `--force` overrides.
- **Every write is audited.** `~/.nsx_toolkit/audit.log` records who, when,
  which manager, and the full before/after tag state. Menu option 11 (or
  `--audit-log`) reviews it and can undo an entry.
- **Console output truncates; exports never do.** Long listings are capped on
  screen for readability, but the CSV and JSON always contain every row.

---

## Scope: what runs where

| Action | Global Manager | Local Managers |
|---|---|---|
| Group search and criteria | yes | yes |
| VM inventory and tags | no | yes |
| Security policies and rules | yes | yes (including GM rules realized locally) |

Reverse lookup deliberately sweeps every connected manager. GM-authored rules
are realized read-only onto each LM, so a naive scan reports the same rule once
per site; rules are deduped by their NSX path and attributed to the GM once.

---

## Development

The single file is generated. Edit the package, then rebuild.

```bash
git clone https://github.com/sampath9966/nsx-vDefend
cd nsx-vDefend
pip install -e ".[dev]"

pytest -q                                  # full suite, no NSX required
ruff check src tests tools
python3 tools/build_single_file.py         # regenerate nsx-toolkit.py
python3 tools/build_single_file.py --check # CI runs this
```

```
src/nsx_toolkit/
  version.py errors.py paths.py output.py   foundations
  api.py                                    every NSX path and field, declared once
  taxonomy.py config.py creds.py            configuration
  http.py                                   transport, retry, auth, VM index
  audit.py export.py render.py              cross-cutting services
  actions/                                  one module per operation
  wizard.py menu.py cli.py                  entry points
tools/build_single_file.py                  amalgamator
tests/fake_nsx.py                           in-process fake NSX manager
```

Tests run against `tests/fake_nsx.py`, a real in-process HTTP server with
Global and Local Manager personalities. That means the suite exercises the
actual transport, cursor pagination, retry loop and session authentication
rather than a stub. No NSX is needed to develop or to run CI.

`tools/build_single_file.py --check` fails if `nsx-toolkit.py` has drifted from
the package, so the file people download can never be stale.

## Requirements

Python 3.9 or newer. `requests` is optional.

## License

See [LICENSE](LICENSE).
