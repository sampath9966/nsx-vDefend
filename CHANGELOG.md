# Changelog

All notable changes to this project are documented here.

Versioning follows [Semantic Versioning](https://semver.org/). The `main` branch reflects the latest release. Development happens on feature branches.

---

## [1.2.0] — 2026-09-14

### Added

- **Gateway Firewall** — `gw-policy list`, `gw-rule list`, `gw-rule hygiene`. Read-only visibility into T0/T1 gateway policies and rules with the same hygiene checks available for DFW.
- **Context profiles** — `context-profile list`. Lists NSX L7 application ID and FQDN signatures with attribute detail.
- **IDS/IPS** — `idps events [--severity]` and `idps profile list`. Shows intrusion detection events and signature profiles from the NSX IDS/IPS engine.
- **VCF integration** — `vcf import`. Queries a VMware Cloud Foundation SDDC Manager (`/v1/sddcs`) and populates `inventory.json` with the NSX Local Manager for every discovered SDDC. Merge-safe: existing entries are skipped.
- **VM visibility** — `vm groups VM`. Lists every DFW group a VM belongs to with a rule-reference count.
- **Rule search** — `rule search --ip CIDR`. Finds every DFW rule whose source or destination group could apply to a given IP or CIDR.
- **Operational health** — `alarms`, `cert list`, `capacity`. Read commands for open NSX alarms, TLS certificate expiry, and per-resource utilisation.
- **Network topology** — `segment list`, `edge list`, `bgp`. Segment inventory, edge node status, and BGP neighbour state per T0 gateway.
- **Terraform export** — `terraform export`. Writes HCL files per manager (`groups.tf`, `dfw.tf`, `certs.tf`, `imports.tf`) for the `vmware/nsxt` provider.

### Changed

- Shell completion now covers all new command nouns.

### Fixed

- Single-file amalgam: resolved top-level name collision between `actions/idps.py` and `commands/setup.py` (`PROFILE_HEADERS` → `CTX_PROFILE_HEADERS`).

---

## [1.1.0] — 2026-09-08

### Added

- **Snapshot restore** — `snapshot restore FILE`. Restores configuration from a snapshot object by object through the authoring engine.
- **Flow recommendations** — `recommend FILE`. Proposes DFW rules from a flow export (NetFlow, IPFIX, CSV).
- **Continuous mode** — `--out-junit`, `--out-sarif`, `--out-metrics`, `--notify`, `--only-on-change`. Pipeline-friendly output for CI, Prometheus push-gateway and webhook notification.
- **Bulk tag operations** — `tag bulk FILE`. CSV-driven tag adds and removes across many VMs.
- **Doctor** — `nsxctl doctor`. Reports what each NSX manager actually serves (transport zones, T0/T1, segments, edges).
- **Shell completion** — `nsxctl completion bash|zsh|fish`.
- **Interactive menu** — `nsxctl menu`.
- **NSX Projects scoping** — `--project NAME` scopes all policy paths to a project.
- **Value completion** — tab-completion for group, policy, and service names.

### Changed

- `nsxctl setup-path` now works on Windows in addition to POSIX systems.
- The audit log format is backward-compatible with entries written by earlier versions.

---

## [1.0.0] — 2026-09-03

Initial release.

### Included

- `init`, `status`, `login`, `config`, `managers`, `profiles`
- `group list`, `group show`, `group members`
- `tag show`, `tag set`
- `rule list`, `rule show`, `rule hygiene`, `policy list`, `service list`
- `impact`, `parity`, `compliance`
- `trace` — static evaluation + live NSX traceflow
- `apply` — declarative group and rule authoring
- `snapshot save`, `drift`
- `audit list`, `audit undo`
- Multi-profile inventory, CA bundle support, keyring credential storage
- Zero-dependency `nsx-toolkit.py` amalgam
- CI across Python 3.9–3.13
