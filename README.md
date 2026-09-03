# nsxctl

A command-line tool for VMware NSX groups, tags and distributed firewall rules,
across a Global Manager and any number of Local Managers.

```bash
pipx install nsxctl
nsxctl init          # guided setup: managers, credentials, a reachability check
nsxctl compliance    # tagging posture across every Local Manager
```

Or download one file and run it — no install, no dependencies, nothing to
configure by hand:

```bash
curl -O https://raw.githubusercontent.com/sampath9966/nsx-vDefend/main/nsx-toolkit.py
python3 nsx-toolkit.py
```

Both paths are fully supported and tested. The single file exists for the
locked-down jumpbox where you cannot install anything; `requests` is used when
present and the Python standard library when it is not.

---

## Commands

```
nsxctl                                  interactive menu
nsxctl init                             guided first-run setup
nsxctl status                           reachability, auth and API base per manager
nsxctl managers                         list configured managers
nsxctl login [NAME]                     set or replace stored credentials
nsxctl config show | path | validate    what config is in effect, and from where

nsxctl group list [--contains X] [--members]
nsxctl group show NAME

nsxctl tag list VM                      every tag on a VM, checked against your taxonomy
nsxctl tag find --scope S --tag T       every VM carrying a tag
nsxctl tag edit VM                      interactive add/remove
nsxctl tag apply FILE.csv               bulk change (dry run by default)
nsxctl tag ticket FILE.csv              change-plan document, validated against live NSX

nsxctl impact VM                        what breaks if I change this VM
nsxctl parity STATIC DYNAMIC            static vs dynamic group migration progress
nsxctl compliance                       tagging posture across every Local Manager
nsxctl audit list | undo                audited writes, and undo one

nsxctl completion bash | zsh | fish     shell completion
nsxctl version
```

`nsxctl <command> --help` shows a command's options and examples.

Global flags work on either side of the subcommand — `nsxctl --json compliance`
and `nsxctl compliance --json` are the same thing.

### The three you'll actually use daily

```bash
# Is my tagging where I think it is?
nsxctl compliance

# What breaks if I retag this VM?
nsxctl impact web-prod-01

# Which VMs are tagged env=prod?
nsxctl tag find --scope env --tag prod --out-csv prod.csv
```

`--debug` logs every HTTP method, URL, status and timing to stderr. It is the
first thing to reach for when an API behaves differently on your NSX version.

---

## Installing

| Method | Command | When |
|---|---|---|
| pipx | `pipx install nsxctl` | Recommended. Isolated, on PATH. |
| pip | `pip install --user nsxctl` | If you don't have pipx. |
| Single file | download `nsx-toolkit.py` | No install possible. No dependencies. |
| Binary | download from [Releases](https://github.com/sampath9966/nsx-vDefend/releases) | No Python at all. |
| Module | `python -m nsx_toolkit` | Console scripts awkward to reach. |

Shell completion:

```bash
nsxctl completion bash > /etc/bash_completion.d/nsxctl
nsxctl completion zsh  > "${fpath[1]}/_nsxctl"
nsxctl completion fish > ~/.config/fish/completions/nsxctl.fish
```

The completion script is generated from the live command tree, so it always
matches the commands your build actually has.

---

## Configuration

### inventory.json

Looked for in the current directory, then `~/.nsx_toolkit/`. Override with
`--inventory`. `nsxctl init` writes it for you; `nsxctl config path` tells you
which one is in effect. See
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
| `name` | Short label used in output and in `--manager` |
| `role` | `gm` or `lm`. Tags and VM inventory are LM-only; groups and policies exist on both |
| `host`, `port` | Manager address. Port defaults to 443 |
| `verify_ssl` | `false` for self-signed certificates. TLS warnings are suppressed only for the managers that set this |
| `ca_bundle` | CA bundle to verify against, when `verify_ssl` is true |
| `auth` | `session` (default), `basic`, `token`, or `cert` |
| `timeout` | Per-request seconds. Default 30 |
| `username_env`, `password_env` | Environment variable names the credentials resolve from |

### taxonomy.json (optional)

Your tag scheme. Without one, a sensible default is used. Save it next to
`inventory.json` or pass `--taxonomy`. See
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

`required` scopes drive `nsxctl compliance`. `values`, when present, restricts
what a scope may be set to. YAML is accepted if PyYAML happens to be installed;
JSON is used everywhere else so nothing needs installing.

`nsxctl config show` prints the taxonomy currently in effect.

### Bulk tagging CSV

```csv
vm_name,scope,tag,action
web-prod-01,env,prod,add
web-prod-01,env,dev,remove
```

Rows with an unknown VM or a malformed action are reported individually rather
than failing the whole file. See
[`examples/bulk-tags.example.csv`](examples/bulk-tags.example.csv).

### Credentials

Resolved in order: environment variable, OS keyring, local credentials file.
Environment wins, so CI and scheduled jobs can inject credentials without
touching disk.

When prompted, values are stored in the OS keyring where one exists. With no
keyring, you are asked whether to write them to a file — never done silently.
`--store keyring|plaintext|none` overrides; `nsxctl login` re-enters them.

---

## Safety

- **Read-only by default.** Changes need `--enable-writes`.
- **Dry run always runs first.** `nsxctl tag apply` prints the full plan before
  anything is written.
- **Non-interactive writes need `--yes`.** Without a terminal and without
  `--yes`, it refuses rather than assuming consent.
- **Concurrent edits are detected.** Each VM is re-read immediately before it is
  written; if its tags changed since the plan was computed, that row fails
  instead of overwriting someone else's change. `--force` overrides.
- **Every write is audited.** `~/.nsx_toolkit/audit.log` records who, when,
  which manager, and full before/after state. `nsxctl audit list` reviews it;
  `nsxctl audit undo` reverts an entry.
- **Console output truncates; exports never do.** Long listings are capped on
  screen, but CSV and JSON always contain every row.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The command ran and found a problem (failed writes, validation errors, unreachable managers) |
| 2 | Could not start (bad arguments, no inventory, unknown manager) |
| 3 | Command not implemented in this release |
| 130 | Cancelled |

---

## Scope: what runs where

| Action | Global Manager | Local Managers |
|---|---|---|
| Group search and criteria | yes | yes |
| VM inventory and tags | no | yes |
| Security policies and rules | yes | yes (including GM rules realized locally) |

`nsxctl impact` deliberately sweeps every connected manager. GM-authored rules
are realized read-only onto each LM, so a naive scan reports the same rule once
per site; rules are deduped by their NSX path and attributed to the GM once.

---

## Upgrading from 3.x

Every old flag still works and prints the replacement:

```
$ nsx-toolkit.py --dashboard
warning: --dashboard is deprecated and will be removed in 5.0.
         use: nsxctl compliance
```

| Was | Now |
|---|---|
| `--verify` | `nsxctl status` |
| `--dashboard` | `nsxctl compliance` |
| `--groups [--contains X] [--members]` | `nsxctl group list [--contains X] [--members]` |
| `--vm-tags VM` | `nsxctl tag list VM` |
| `--vms-by-tag --scope S --tag T` | `nsxctl tag find --scope S --tag T` |
| `--bulk-tag FILE` | `nsxctl tag apply FILE` |
| `--change-ticket FILE` | `nsxctl tag ticket FILE` |
| `--reverse-lookup VM` | `nsxctl impact VM` |
| `--parity A B` | `nsxctl parity A B` |
| `--audit-log` | `nsxctl audit list` |
| `--list-managers` | `nsxctl managers` |
| `--set-credentials` | `nsxctl login` |
| `--init` | `nsxctl init` |

Running several actions in one invocation (`--groups --dashboard`) still works
and still writes one export file per result set.

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
  commands/                                 the nsxctl command tree
  legacy.py                                 pre-4.0 flag translation
  wizard.py menu.py cli.py                  entry points
tools/build_single_file.py                  amalgamator
tests/fake_nsx.py                           in-process fake NSX manager
```

`commands/` is the CLI surface; `actions/` is the logic. A new command wires
argument parsing to an existing `act_*` function.

Tests run against `tests/fake_nsx.py`, a real in-process HTTP server with
Global and Local Manager personalities, so the suite exercises the actual
transport, cursor pagination, retry loop and session authentication rather than
a stub. No NSX is needed to develop or to run CI.

**The amalgamator enforces three rules** that a package hides but a single
shared namespace does not tolerate. The build fails, with the fix in the error
message, if you:
- define the same top-level name in two modules,
- write `from . import some_module` (binds a module object),
- write `from .x import y as z` (the alias does not survive flattening).

## Requirements

Python 3.9 or newer. `requests` is optional.

## License

See [LICENSE](LICENSE).
