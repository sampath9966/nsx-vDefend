# Command reference

All commands support `--help` for inline documentation. This page organises them by area and documents the flags that matter most.

## Global flags

These flags apply to every command.

| Flag | Default | Description |
|---|---|---|
| `--inventory PATH` | `./inventory.json` | Inventory file |
| `--profile NAME` | first profile | Which estate in a multi-profile inventory |
| `--manager NAME` | all | Target one manager by name |
| `--all-lm` | — | Target every Local Manager |
| `--domain NAME` | `default` | NSX domain |
| `--project NAME` | — | Scope to an NSX Project |
| `--ca-bundle PATH` | — | CA bundle for TLS |
| `--enable-writes` | — | Permit mutations |
| `--yes` / `-y` | — | Skip confirmation prompts |
| `--no-color` | — | Plain output |
| `--non-interactive` | — | Never prompt; fail fast |
| `--out-csv PATH` | — | Write structured output to CSV |
| `--out-json PATH` | — | Write structured output to JSON |
| `--out-html PATH` | — | Write an HTML report |
| `--out-junit PATH` | — | Write JUnit XML |
| `--out-sarif PATH` | — | Write SARIF (Code Scanning) |
| `--out-metrics PATH` | — | Write Prometheus text metrics |
| `--notify URL` | — | POST a JSON summary to a webhook |
| `--only-on-change` | — | Exit 0 silently when nothing changed |

---

## Setup and diagnostics

### `nsxctl init`
Guided first-run setup. Creates `inventory.json` and tests connectivity.

### `nsxctl status`
Checks that every manager in the inventory is reachable and authenticated. Prints version, role, and auth method per manager.

### `nsxctl doctor`
Queries each manager to determine what it actually serves: transport zones, segments, deployed edge nodes, T0/T1 gateways. Useful to verify scope before running broader commands.

### `nsxctl login [MANAGER]`
Prompts for credentials and stores them using the configured backend (`--store keyring|plaintext`).

### `nsxctl config`
Prints the resolved configuration (inventory path, credential store, active profile) without revealing passwords.

### `nsxctl managers`
Lists all managers defined in the inventory with their role, host and authentication method.

### `nsxctl profiles`
Lists the named profiles (estates) defined in the inventory.

---

## Groups

### `nsxctl group list [--contains TEXT] [--scope SCOPE] [--tag TAG]`
Lists all security groups across every manager. `--contains` filters by display name substring.

### `nsxctl group show NAME`
Shows the full definition of a group including its membership criteria (conditions, IP expressions, path expressions, conjunctions).

### `nsxctl group members NAME`
Resolves and lists the current effective members (VMs, IPs) of a group.

---

## Tags

### `nsxctl tag show VM`
Shows all tags on a VM.

### `nsxctl tag set VM SCOPE VALUE [--remove]`
Adds or removes a single tag. Requires `--enable-writes`.

### `nsxctl tag bulk FILE [--dry-run]`
Applies tag operations from a CSV file. Columns: `vm_name`, `scope`, `tag`, `action` (`add`/`remove`). Requires `--enable-writes`.

```csv
vm_name,scope,tag,action
web-prod-01,env,prod,add
web-prod-01,tier,web,add
db-prod-01,criticality,critical,add
```

---

## Distributed Firewall

### `nsxctl rule list [--policy NAME] [--contains TEXT] [--action ACTION] [--disabled]`
Lists DFW rules. Filters: `--policy` (policy name), `--action` (ALLOW/DROP/REJECT), `--disabled` (show only disabled rules).

### `nsxctl rule show NAME`
Shows a single rule with its full source, destination, service, and scope.

### `nsxctl rule hygiene [--fail-on LEVEL]`
Runs 12 hygiene checks against the live rule set:
- Any-any-allow rules
- Shadowed rules
- Drop rules without logging
- Duplicate rules
- Disabled rules (stale)
- Overly broad service definitions
- ...and more

`--fail-on critical|high|medium` exits non-zero when findings at or above the threshold exist. Useful in pipelines.

### `nsxctl rule search --ip CIDR`
Finds every rule whose source or destination group could apply to the given IP or CIDR. Shows the match basis (exact, ANY, or "tag-based / possible").

### `nsxctl policy list [--contains TEXT]`
Lists security policies.

### `nsxctl service list [--contains TEXT]`
Lists service definitions.

---

## Gateway Firewall

### `nsxctl gw-policy list [--contains TEXT]`
Lists gateway firewall policies on T0/T1 gateways.

### `nsxctl gw-rule list [--policy NAME] [--action ACTION] [--disabled]`
Lists gateway firewall rules. Supports the same filters as `rule list`.

### `nsxctl gw-rule hygiene`
Runs hygiene checks against gateway firewall rules (any-any-allow, disabled, drop-not-logged, duplicates).

---

## Tracing

### `nsxctl trace SRC DST [--port PORT] [--proto tcp|udp|icmp]`
Evaluates whether SRC can reach DST and which DFW rule decides it. Performs static evaluation first; runs a live NSX traceflow when the result is inconclusive.

Output shows the matched rule, action, and whether the decision was static or live. Pass `--src-ip` / `--dst-ip` to use raw IPs instead of VM names.

---

## Impact analysis

### `nsxctl impact VM`
Shows the complete chain: VM → groups it belongs to → DFW rules referencing those groups. Answers "what breaks if I change this VM?"

### `nsxctl vm groups VM`
Lists every DFW group a VM is currently a member of, with a rule-reference count per group.

### `nsxctl parity GROUP --dynamic EXPRESSION`
Compares a static group against a proposed dynamic replacement to show which members differ.

### `nsxctl compliance [--fail-on LEVEL]`
Checks tagging posture across every Local Manager against the taxonomy. Reports VMs missing required tag scopes.

---

## Recommendations

### `nsxctl recommend FILE [--format netflow|ipfix|csv]`
Reads a flow export and proposes DFW rules that allow the observed flows with the smallest rule surface. Preview only; use `apply` to push the proposals.

---

## Snapshots and drift

### `nsxctl snapshot save [--name NAME]`
Captures the full policy configuration (groups, policies, rules) from every manager to a local JSON file.

### `nsxctl snapshot restore FILE [--dry-run]`
Restores configuration from a snapshot, object by object through the authoring engine. Requires `--enable-writes`.

### `nsxctl drift [--only-on-change]`
Compares the current live state against the last snapshot and reports additions, removals and modifications.

---

## Declarative apply

### `nsxctl apply FILE [--dry-run]`
Applies a declarative YAML or JSON file of groups and rules. Idempotent — existing objects are updated, not duplicated. Requires `--enable-writes`.

---

## Operational health

### `nsxctl alarms [--severity LEVEL] [--all]`
Lists open NSX alarms across all managers, deduplicated by alarm ID. `--severity` filters; `--all` includes resolved alarms. Sorted by severity (CRITICAL first).

### `nsxctl cert list [--warn-days N] [--expired]`
Lists TLS certificates with expiry status. Highlights certs expiring within `--warn-days` (default 90). `--expired` shows only expired or critically expiring certs.

### `nsxctl capacity`
Shows per-resource utilisation across all managers (groups, rules, policies, transport nodes). Colour-coded against NSX's built-in thresholds.

---

## Network topology

### `nsxctl segment list [--contains TEXT] [--type overlay|vlan]`
Lists overlay and VLAN-backed segments with subnet and connected-gateway information.

### `nsxctl edge list`
Lists edge transport nodes with deployment type, admin state and current status.

### `nsxctl bgp [--tier-0 NAME] [--down-only]`
Shows BGP neighbour state per T0 gateway. `--down-only` hides ESTABLISHED sessions.

---

## Advanced security

### `nsxctl context-profile list [--contains TEXT]`
Lists NSX context profiles (L7 application IDs, FQDNs, DNS signatures).

### `nsxctl idps events [--severity LEVEL]`
Shows IDS/IPS detection events, newest first. Filter by severity (CRITICAL, HIGH, MEDIUM, LOW).

### `nsxctl idps profile list`
Lists IDS/IPS signature profiles with override counts.

---

## Terraform export

### `nsxctl terraform export [--out DIR] [--types groups,dfw,certs] [--domain NAME]`
Exports NSX configuration as Terraform HCL for the `vmware/nsxt` provider. Creates one subdirectory per manager with `groups.tf`, `dfw.tf`, `certs.tf` and `imports.tf` (Terraform ≥ 1.5 import blocks). A shared `provider.tf` stub is written at the root.

---

## VCF integration

### `nsxctl vcf import --vcf-host HOST [--vcf-user USER] [--out PATH]`
Discovers NSX Local Managers from a VCF SDDC Manager and merges them into the inventory file. Skips hosts already present. Requires `--enable-writes` to write the file; omit for a dry-run preview.

See [`vcf.md`](vcf.md) for details.

---

## Audit

### `nsxctl audit list [--manager NAME] [--limit N]`
Lists audited write operations with author, timestamp, and a summary of what changed.

### `nsxctl audit undo CHANGE_ID`
Rolls back a specific audited change by replaying its before-state. Requires `--enable-writes`.

---

## Utilities

### `nsxctl completion bash|zsh|fish`
Prints a shell completion script. Source it in your shell profile.

### `nsxctl menu`
Opens an interactive full-screen menu for users who prefer a guided interface.

### `nsxctl version`
Prints the installed version and exits.
