<div align="center">

# nsxctl

**NSX Toolkit — distributed firewall, groups, tags and operational health from the command line.**

[![CI](https://github.com/sampath9966/nsx-vDefend/actions/workflows/ci.yml/badge.svg)](https://github.com/sampath9966/nsx-vDefend/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13-3776ab?logo=python&logoColor=white)](https://pypi.org/project/nsxctl/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![540 tests](https://img.shields.io/badge/tests-540%20passing-brightgreen)](https://github.com/sampath9966/nsx-vDefend/actions)

</div>

---

Query every NSX manager in your estate in a single command. Trace flows. Audit and roll back every change. Export as Terraform. No dependencies — runs on a jumpbox with nothing but Python.

```
$ nsxctl rule hygiene --fail-on high

  DFW hygiene (12 checks) ─────────────────────────────────────────

  CRITICAL  any-any-allow     [default] Emergency-Access         any → any ALLOW
  HIGH      drop-not-logged   [lm-lon]  Block-Untrusted          any → Untrusted DROP
  HIGH      shadowed          [lm-fra]  Allow-HTTPS              shadowed by Emergency-Access above it
  soft      disabled-rule     [lm-lon]  Old-Allow-RDP            disabled, 90+ days

  3 findings at HIGH or above.

$ echo $?
1
```

---

## Contents

- [Why nsxctl](#why-nsxctl)
- [What it does](#what-it-does)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Writing changes](#writing-changes)
- [VCF integration](#vcf-integration)
- [CI and pipelines](#ci-and-pipelines)
- [Contributing](#contributing)

---

## Why nsxctl

The NSX UI answers one question at a time. The API answers whatever you can script. `nsxctl` sits between them: a read-first CLI built for the engineers who maintain NSX rather than the ones who deployed it.

- **Read by default.** Nothing mutates unless you pass `--enable-writes`. No accidental changes.
- **Audited writes.** Every change is logged with before/after diff and a change ticket. One command to roll back.
- **Fan-out.** One invocation hits the GM and every LM in parallel and merges results.
- **No dependencies.** The `nsx-toolkit.py` amalgam runs on Python standard library only — drop it on a jumpbox and use it immediately.
- **Pipeline-native.** JUnit, SARIF, Prometheus metrics, and webhook notification built in.

---

## What it does

<table>
<tr><th>Area</th><th>Commands</th></tr>
<tr><td><b>Connectivity</b></td><td><code>init</code> · <code>status</code> · <code>login</code> · <code>config</code> · <code>managers</code> · <code>profiles</code></td></tr>
<tr><td><b>Groups</b></td><td><code>group list</code> · <code>group show</code> · <code>group members</code></td></tr>
<tr><td><b>Tags</b></td><td><code>tag show</code> · <code>tag set</code> · <code>tag bulk</code></td></tr>
<tr><td><b>Distributed firewall</b></td><td><code>rule list</code> · <code>rule show</code> · <code>rule hygiene</code> · <code>rule search --ip</code> · <code>policy list</code> · <code>service list</code></td></tr>
<tr><td><b>Gateway firewall</b></td><td><code>gw-policy list</code> · <code>gw-rule list</code> · <code>gw-rule hygiene</code></td></tr>
<tr><td><b>Tracing</b></td><td><code>trace</code> — static evaluation + live NSX traceflow</td></tr>
<tr><td><b>Impact & analysis</b></td><td><code>impact</code> · <code>vm groups</code> · <code>parity</code> · <code>compliance</code></td></tr>
<tr><td><b>Declarative authoring</b></td><td><code>apply</code> · <code>audit list</code> · <code>audit undo</code></td></tr>
<tr><td><b>Snapshots</b></td><td><code>snapshot save</code> · <code>snapshot restore</code> · <code>drift</code></td></tr>
<tr><td><b>Recommendations</b></td><td><code>recommend</code> — rules from a flow export</td></tr>
<tr><td><b>Operational health</b></td><td><code>alarms</code> · <code>cert list</code> · <code>capacity</code></td></tr>
<tr><td><b>Network topology</b></td><td><code>segment list</code> · <code>edge list</code> · <code>bgp</code></td></tr>
<tr><td><b>Advanced security</b></td><td><code>context-profile list</code> · <code>idps events</code> · <code>idps profile list</code></td></tr>
<tr><td><b>Terraform</b></td><td><code>terraform export</code> — HCL per manager for the NSX provider</td></tr>
<tr><td><b>VCF</b></td><td><code>vcf import</code> — discover managers from SDDC Manager</td></tr>
</table>

---

## Install

**pip**
```sh
pip install nsxctl
```

**Single file — zero dependencies, works anywhere Python runs**
```sh
curl -LO https://github.com/sampath9966/nsx-vDefend/releases/latest/download/nsx-toolkit.py
python3 nsx-toolkit.py --help
```

**Source**
```sh
git clone https://github.com/sampath9966/nsx-vDefend.git
cd nsx-vDefend && pip install -e ".[dev]"
```

> **Requirements:** Python ≥ 3.9. No runtime dependencies. `requests` is used when present; stdlib `urllib` is the fallback.

---

## Quick start

```sh
# Create inventory.json and verify connectivity
nsxctl init
nsxctl status

# Explore
nsxctl group list
nsxctl rule list --policy web-tier
nsxctl alarms --severity high

# Trace a flow
nsxctl trace web-prod-01 db-prod-01 --port 5432

# Run a hygiene check (exits 1 when findings ≥ HIGH)
nsxctl rule hygiene --fail-on high --out-sarif hygiene.sarif

# Export the full estate as Terraform HCL
nsxctl terraform export --out ./tf-export

# In a VCF environment, auto-populate the inventory from SDDC Manager
nsxctl vcf import --vcf-host sddc-mgr.corp.example.com --enable-writes
```

---

## Commands

Full documentation: **[docs/commands.md](docs/commands.md)**

Shell completion:

```sh
nsxctl completion bash >> ~/.bash_completion   # bash
nsxctl completion zsh  >> ~/.zshrc             # zsh
nsxctl completion fish >> ~/.config/fish/completions/nsxctl.fish
```

---

## Configuration

`nsxctl` reads an inventory file (`./inventory.json` → `~/.nsx_toolkit/inventory.json`).

```jsonc
{
  "managers": [
    {
      "name": "gm",
      "role": "gm",                           // "gm" | "lm"
      "host": "gm.nsx.example.com",
      "verify_ssl": true,
      "auth": "session",
      "username_env": "NSX_GM_USER",
      "password_env": "NSX_GM_PASS"
    },
    {
      "name": "lm-london",
      "role": "lm",
      "host": "lm-lon.nsx.example.com",
      "ca_bundle": "/etc/pki/tls/certs/corp-ca.pem",
      "auth": "session",
      "username_env": "NSX_LM_LONDON_USER",
      "password_env": "NSX_LM_LONDON_PASS"
    }
  ]
}
```

See **[docs/configuration.md](docs/configuration.md)** for the full schema, credential backends (keyring, plaintext, env), multi-profile inventories, NSX Projects scoping, and tag taxonomy.

---

## Writing changes

Everything is read-only by default. Mutations require an explicit opt-in:

```sh
# Preview (safe — no API writes)
nsxctl apply policy.yaml

# Apply
nsxctl apply policy.yaml --enable-writes

# Review what changed
nsxctl audit list

# Roll back a specific change
nsxctl audit undo <change-id> --enable-writes
```

The declarative format supports groups, policies, and rules in YAML or JSON. Every write is logged with its before/after diff and an optional change ticket reference (`--change-ticket CHG0012345`).

See **[docs/authoring.md](docs/authoring.md)** for the format, ticket integration, and rollback.

---

---

## VCF integration

`nsxctl vcf import` discovers NSX Local Managers from a VCF SDDC Manager and populates the inventory automatically:

```sh
nsxctl vcf import \
  --vcf-host sddc-mgr.corp.example.com \
  --vcf-user administrator@vsphere.local \
  --out inventory.json \
  --enable-writes
```

Discovers every SDDC, extracts `nsxtManager.hostname`, merges new entries into the inventory (existing hosts are never duplicated), and prints a status table. Omit `--enable-writes` for a dry-run preview.

See **[docs/vcf.md](docs/vcf.md)** for TLS options and multi-SDDC fleet patterns.

---

## CI and pipelines

`nsxctl` is built for unattended runs. Key flags:

| Flag | Purpose |
|---|---|
| `--non-interactive` | Never prompt — fail fast instead |
| `--no-color` | Plain output for log aggregators |
| `--only-on-change` | Exit 0 silently when nothing changed |
| `--out-junit PATH` | JUnit XML for test reporters |
| `--out-sarif PATH` | SARIF for GitHub Code Scanning |
| `--out-metrics PATH` | Prometheus text format for push-gateway |
| `--notify URL` | POST a JSON summary to a webhook |

Full pipeline recipes (GitHub Actions, Jenkins, Prometheus, webhooks): **[docs/ci.md](docs/ci.md)**

**Example: nightly drift detection**

```yaml
- name: NSX drift check
  run: |
    nsxctl drift \
      --non-interactive \
      --no-color \
      --only-on-change \
      --out-sarif nsx-drift.sarif
  env:
    NSX_GM_USER: ${{ secrets.NSX_GM_USER }}
    NSX_GM_PASS: ${{ secrets.NSX_GM_PASS }}

- name: Upload drift to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nsx-drift.sarif
```

**Example: hygiene gate in a change pipeline**

```sh
nsxctl rule hygiene \
  --fail-on high \
  --non-interactive \
  --out-junit hygiene.xml \
  --notify "$TEAMS_WEBHOOK"
```

---

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full guide. The short version:

```sh
pip install -e ".[dev]"
pytest                                          # 540 tests, ~3 min
ruff check src/ tests/
python tools/build_single_file.py --check       # single-file sync
```

PRs must keep all five Python versions green and pass the single-file sync check. See the [PR template](.github/pull_request_template.md) for the full checklist.

---

## License

[Apache License 2.0](LICENSE)
