# nsxctl

**NSX Toolkit — distributed firewall, groups, tags and operational health from the command line.**

`nsxctl` is a read-first, write-gated CLI for VMware NSX. It talks to a Global Manager and every Local Manager simultaneously, surfaces policy intent alongside live state, and guards every change behind an audited write gate. The tool ships as both a standard Python package and a zero-dependency single-file script for jumpbox use.

[![CI](https://github.com/sampath9966/nsx-vDefend/actions/workflows/ci.yml/badge.svg)](https://github.com/sampath9966/nsx-vDefend/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/nsxctl/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

---

## Contents

- [Why nsxctl](#why-nsxctl)
- [Feature overview](#feature-overview)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Writing changes](#writing-changes)
- [VCF integration](#vcf-integration)
- [CI and automation](#ci-and-automation)
- [Contributing](#contributing)
- [License](#license)

---

## Why nsxctl

NSX ships with a capable UI and a REST API, but neither is optimised for an engineer who needs to answer operational questions quickly across a fleet of managers, or who wants change control baked into the workflow rather than bolted on. `nsxctl` fills that gap:

- **Read by default.** Every command is read-only unless `--enable-writes` is passed. There are no accidental mutations.
- **Audited writes.** Every change is logged with its author, timestamp and before/after diff. `nsxctl audit` lists history; `nsxctl audit undo` rolls back individual changes.
- **Fan-out.** A single invocation queries the Global Manager and all Local Managers in parallel and merges the results.
- **No API sprawl.** The tool maps a small set of composable flags (`--manager`, `--all-lm`, `--domain`, `--project`) onto the correct API paths so you don't have to.
- **Zero dependencies on a jumpbox.** The `nsx-toolkit.py` amalgam runs with only the Python standard library.

---

## Feature overview

| Area | Commands |
|---|---|
| **Configuration** | `init`, `status`, `login`, `config`, `managers`, `profiles`, `projects` |
| **Groups** | `group list`, `group show`, `group members` |
| **Tags** | `tag show`, `tag set`, `tag bulk` |
| **Distributed Firewall** | `rule list`, `rule show`, `policy list`, `service list`, `rule hygiene`, `rule search` |
| **Gateway Firewall** | `gw-policy list`, `gw-rule list`, `gw-rule hygiene` |
| **Tracing** | `trace` — static evaluation + live NSX traceflow |
| **Impact analysis** | `impact`, `parity`, `compliance`, `vm groups` |
| **Recommendations** | `recommend` — propose rules from a flow export |
| **Snapshots & drift** | `snapshot save/restore`, `drift` |
| **Declarative apply** | `apply` — idempotent group and rule authoring from YAML/JSON |
| **Operational health** | `alarms`, `cert list`, `capacity` |
| **Network topology** | `segment list`, `edge list`, `bgp` |
| **Advanced security** | `context-profile list`, `idps events`, `idps profile list` |
| **Terraform export** | `terraform export` — HCL per manager for the NSX Terraform provider |
| **VCF integration** | `vcf import` — discover Local Managers from SDDC Manager |
| **Audit & undo** | `audit list`, `audit undo` |
| **Automation** | `--out-csv`, `--out-json`, `--out-html`, `--out-junit`, `--out-sarif`, `--out-metrics`, `--notify` |

---

## Installation

### pip (recommended)

```sh
pip install nsxctl
```

### Single-file script — no dependencies, works on any jumpbox

```sh
curl -LO https://github.com/sampath9966/nsx-vDefend/releases/latest/download/nsx-toolkit.py
python3 nsx-toolkit.py --help
```

### From source

```sh
git clone https://github.com/sampath9966/nsx-vDefend.git
cd nsx-vDefend
pip install -e ".[dev]"
```

**Requirements:** Python 3.9 or later. No runtime dependencies. `requests` is used automatically when present; the stdlib `urllib` transport is the fallback.

---

## Quick start

```sh
# 1. Create an inventory file
nsxctl init

# 2. Verify connectivity
nsxctl status

# 3. List all security groups across every manager
nsxctl group list

# 4. List DFW rules, filtered by policy name
nsxctl rule list --policy web-tier

# 5. Trace a flow between two VMs
nsxctl trace web-prod-01 db-prod-01 --port 5432

# 6. Show open alarms
nsxctl alarms

# 7. Export configuration as Terraform HCL
nsxctl terraform export --out ./tf-export

# 8. Discover NSX managers from VCF SDDC Manager
nsxctl vcf import --vcf-host sddc-mgr.example.com
```

---

## Command reference

Full per-command documentation lives in [`docs/commands.md`](docs/commands.md).

A shell completion script is available for bash, zsh and fish:

```sh
# bash
nsxctl completion bash >> ~/.bash_completion

# zsh
nsxctl completion zsh >> ~/.zshrc
```

---

## Configuration

`nsxctl` reads an **inventory file** that describes the managers in your estate. By default it looks for `./inventory.json` and then `~/.nsx_toolkit/inventory.json`.

```jsonc
// inventory.json
{
  "managers": [
    {
      "name": "gm",
      "role": "gm",
      "host": "gm.nsx.example.com",
      "port": 443,
      "verify_ssl": true,
      "auth": "session",
      "username_env": "NSX_GM_USER",
      "password_env": "NSX_GM_PASS"
    },
    {
      "name": "lm-london",
      "role": "lm",
      "host": "lm-lon.nsx.example.com",
      "verify_ssl": true,
      "ca_bundle": "/etc/pki/tls/certs/corp-ca.pem",
      "auth": "session",
      "username_env": "NSX_LM_LONDON_USER",
      "password_env": "NSX_LM_LONDON_PASS"
    }
  ]
}
```

See [`docs/configuration.md`](docs/configuration.md) for the full schema, credential storage options (keyring, plaintext, environment variables), multi-profile inventories, NSX Projects scoping, and CA bundle configuration.

---

## Writing changes

All write commands require `--enable-writes`. Without it, every mutating path is a dry run that shows what would change.

```sh
# Preview what would change
nsxctl apply groups.yaml

# Apply the change
nsxctl apply groups.yaml --enable-writes

# Review the audit log
nsxctl audit list

# Roll back a specific change
nsxctl audit undo <change-id> --enable-writes
```

See [`docs/authoring.md`](docs/authoring.md) for the declarative file format, change-ticket integration, and the write-gate design.

---

## VCF integration

In a VMware Cloud Foundation environment, `nsxctl vcf import` queries the SDDC Manager API and populates `inventory.json` automatically:

```sh
nsxctl vcf import \
  --vcf-host sddc-mgr.corp.example.com \
  --vcf-user administrator@vsphere.local \
  --out inventory.json \
  --enable-writes
```

The command discovers every SDDC's NSX Local Manager, merges new entries into the existing inventory without duplicating hosts already present, and prints a status table. Omit `--enable-writes` for a dry-run preview.

See [`docs/vcf.md`](docs/vcf.md) for TLS options and multi-SDDC fleet patterns.

---

## CI and automation

`nsxctl` is designed to run unattended. Key flags for pipelines:

| Flag | Purpose |
|---|---|
| `--non-interactive` | Never prompt; fail fast instead |
| `--no-color` | Plain output for log aggregators |
| `--only-on-change` | Exit 0 silently when nothing changed (drift, hygiene) |
| `--out-junit PATH` | JUnit XML for test reporters |
| `--out-sarif PATH` | SARIF for GitHub Code Scanning |
| `--out-metrics PATH` | Prometheus text format for push-gateway |
| `--notify URL` | POST a JSON summary to a webhook after each run |

Example: nightly drift detection in GitHub Actions:

```yaml
- name: Check NSX drift
  run: |
    nsxctl drift \
      --non-interactive \
      --no-color \
      --only-on-change \
      --out-sarif drift.sarif
  env:
    NSX_GM_USER: ${{ secrets.NSX_GM_USER }}
    NSX_GM_PASS: ${{ secrets.NSX_GM_PASS }}
```

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, the test suite, the single-file build, and the coding conventions.

The short version:

```sh
git clone https://github.com/sampath9966/nsx-vDefend.git
cd nsx-vDefend
pip install -e ".[dev]"
pytest
ruff check src/ tests/
python tools/build_single_file.py --check
```

All PRs must keep the full test suite green across Python 3.9–3.13 and pass the single-file sync check.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
