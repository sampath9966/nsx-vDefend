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
nsxctl doctor                           what does THIS NSX actually serve?
nsxctl managers                         list configured managers
nsxctl profiles                         estates this inventory defines
nsxctl projects                         NSX Projects on each manager
nsxctl login [NAME]                     set or replace stored credentials
nsxctl config show | path | validate    what config is in effect, and from where

nsxctl group list [--contains X] [--members]
nsxctl group show NAME
nsxctl group create NAME --criteria 'tag:env=prod AND tag:tier=web'
nsxctl group edit NAME | group delete NAME

nsxctl tag list VM                      every tag on a VM, checked against your taxonomy
nsxctl tag find --scope S --tag T       every VM carrying a tag
nsxctl tag edit VM                      interactive add/remove
nsxctl tag apply FILE.csv               bulk change (dry run by default)
nsxctl tag ticket FILE.csv              change-plan document, validated against live NSX

nsxctl snapshot save [NAME]             capture the current configuration
nsxctl snapshot list | show NAME
nsxctl snapshot diff BEFORE AFTER       compare two snapshots
nsxctl snapshot restore NAME            put a snapshot's config back
nsxctl drift [NAME]                     what changed since the snapshot, and who

nsxctl rule list [--policy P] [--action DROP] [--disabled]
nsxctl rule show NAME
nsxctl policy list | service list | service show NAME

nsxctl rule create NAME --policy P --from G1 --to G2 --service S --action ALLOW
nsxctl rule edit NAME | rule move NAME --before OTHER | rule delete NAME
nsxctl apply FILE.yaml                  declarative batch (dry run by default)
nsxctl recommend FLOWS.csv              propose rules from observed traffic

nsxctl trace VM_A VM_B [--port N]       can A reach B, and what decided it
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

### Reading what is there

```bash
nsxctl rule list --policy app-tier      # in NSX evaluation order
nsxctl rule show allow-web-db
nsxctl policy list
nsxctl service list                     # and which ones trace can decide
```

`rule list` sorts by **category first** (Ethernet -> Emergency ->
Infrastructure -> Environment -> Application), then policy and rule sequence.
That is not the order the API returns them in, and it is the order that decides
traffic.

`service list`'s last column says whether each service is a plain L4 port set.
That is what makes an undecided `nsxctl trace` verdict explicable rather than
mystifying.

### Rule hygiene

```bash
nsxctl rule hygiene                          # the "is my policy sane" report
nsxctl rule hygiene --out-html hygiene.html  # a file you can email
nsxctl rule hygiene --fail-on critical       # for a pipeline or cron
```

Twelve checks across three categories:

| Finding | Severity | Basis |
|---|---|---|
| `any_any_allow` | critical | source and destination both ANY with ALLOW |
| `missing_group` | critical | references a group that does not exist |
| `any_any_other` | high | source and destination both ANY, non-ALLOW |
| `broad_applied_to` | high | applied-to is ANY — enforced everywhere |
| `shadowed_by_any_any` | high | unreachable: an any-any rule sits above it |
| `unused_since_baseline` | high | zero hits *between two baseline reads* |
| `no_criteria_group` | medium | referenced group has no criteria — rule is inert |
| `drop_not_logged` | medium | DROP/REJECT with logging off |
| `duplicate_rule` | medium | identical match criteria to an earlier rule |
| `unused_rule` | medium *(soft)* | counter reads zero |
| `disabled_rule` | low | dead configuration |
| `empty_group` | low *(soft)* | group resolves to 0 VM members |

**Findings marked soft are indications, not proof**, and the detail column
says why. Two things this report deliberately will not claim:

- **A zero hit count does not mean a rule is unused.** NSX counters are
  cumulative since the last reset — a reboot or a rule edit zeroes them. Use
  a baseline (below) for a claim you can defend.
- **Groups matched on VIF, IP-set, segment or segment-port criteria are never
  reported as empty.** The VM member API returns nothing for them, so a naive
  count would flag live groups as dead. They report as *not measurable*.

Shadow detection does no port or CIDR arithmetic, so it cannot produce a false
"unreachable". It only flags what is provable: an exact-duplicate match key,
or a rule sitting below one that matches everything.

### Config snapshots and drift

```bash
nsxctl snapshot save approved     # capture groups, policies and rules
# ... a week, and someone edits a rule in the UI ...
nsxctl drift                      # what changed, and who changed it
```

```
MODIFIED rule https [security]   by dave
    + destination_groups: ['ANY']
    - destination_groups: ['/infra/domains/default/groups/g-web']
MODIFIED policy Perimeter (edited) [cosmetic]   by dave
    display_name: Perimeter -> Perimeter (edited)
```

Changes are classified **security** (can alter what traffic is permitted) or
**cosmetic** (only a name, description or note), so a scheduled check stays
quiet about a rename and is loud about a new any-any rule:

```bash
nsxctl drift --fail-on-drift security     # exit 1 only on real changes
nsxctl snapshot diff approved current --out-html drift.html
```

`nsxctl snapshot diff` needs no live NSX — it compares two stored snapshots.

**The tree is config-as-code.** One JSON file per object, sorted keys, volatile
fields stripped, so ordinary tools work on it:

```
approved/
  manifest.json
  groups/lm-london/g-web.json
  policies/lm-london/p1/_policy.json
  policies/lm-london/p1/rules/https.json
```

```bash
git diff --no-index snapshots/approved snapshots/current
```

Two details that make this work rather than merely look like it works:

- **Volatile fields never reach the object files.** `_revision`,
  `_last_modified_time`, `realization_id` and friends change when nothing real
  changed; left in, every diff would be noise. They ride in the manifest
  instead, which is where `--out-html` and the console get *who changed it*.
- **`source_groups` compares as a set; `expression` compares in order.**
  Membership is what matters for the first, but group criteria are
  `Condition AND Condition` — reordering them changes which workloads match.
  Anything unrecognised is compared in order and treated as security-relevant,
  because a false "changed" costs a second look and a missed one costs an
  incident.

VM tags are excluded unless you pass `--with-tags`: retagging is routine churn
that would bury a real rule change.

### Proving a rule is unused

```bash
nsxctl rule baseline save --baseline-file monday.json
# ... a week of production traffic later ...
nsxctl rule baseline compare --baseline-file monday.json
```

A counter that did not move between the two reads genuinely saw no matching
traffic in that window — evidence you can attach to a deletion request.

If the second read is *lower* than the first, the counter was reset and the
window proves nothing. That reports as `counter_reset`, never as unused;
claiming no traffic when the evidence was wiped is how a live firewall rule
gets deleted.

### Can A reach B, and what stopped it

```bash
nsxctl trace web-prod-01 db-prod-01 --port 3306
nsxctl trace web-prod-01 --to 10.20.30.40 --port 443
nsxctl trace web-prod-01 db-prod-01 --port 3306 --static   # no packet
```

**Two engines answer that, and they answer different questions**, so the
report never blends them:

```
  WHAT THE POLICY SAYS   (evaluated here -- no packet sent)
  ----------------------------------------------------------------
    DROP  by rule 'block-legacy-db' in policy 'app-tier'  [seq 40, Application]

  WHAT THE DATA PLANE DID   (traceflow -- a synthetic packet was sent)
  ----------------------------------------------------------------
    DROPPED  at FIREWALL on esx-01
    by rule 'block-legacy-db' in policy 'app-tier'   acl_rule_id 4130

  Agreed: the policy and the data plane tell the same story.
```

When they disagree, that disagreement *is* the finding -- NAT, a partial
realization, or a rule not yet pushed to a host will each produce it -- and
the report lists the likely causes rather than picking a winner.

Four things the command handles rather than papers over:

- **Traceflow is a Manager API and the Global Manager does not serve it.** The
  command finds the Local Manager that actually hosts the source VM and targets
  that one. With no LM connected it says so and runs the static half.
- **It needs a logical port, not a VM.** VM → VIF → logical switch port is the
  real chain. A multi-NIC VM is ambiguous, so the NICs are listed and you pick
  with `--nic`; it will not choose for you. A powered-off VM or an unrealized
  port each get their own message.
- **It injects a real packet.** Synthetic and harmless, but real, so it sits
  behind the same confirmation as a write: `--yes` for scripts, `--static` to
  send nothing. The traceflow object is always deleted afterwards, including
  on timeout.
- **The verdict comes back as a number.** An observation says `acl_rule_id
  4130`. The policy rule's `rule_id` carries the same integer, so the
  deduplicated sweep turns it into a rule and policy name. An id no rule in the
  domain carries is reported as the raw number, never hidden.

Static evaluation walks rules in NSX's real order -- **category first**
(Ethernet → Emergency → Infrastructure → Environment → Application), then
policy and rule sequence -- because a per-policy ordering answers the wrong
question. Where it cannot decide a rule it says so instead of guessing:

```
    UNCERTAIN: 1 rule(s) ahead of this one could not be decided:
      app-tier / icmp-rule
        service Ping is not a plain L4 port set
```

Only `L4PortSetServiceEntry` reduces to a port comparison. ICMP, ALG and
IP-protocol services are left undecided, and without `--port` a rule limited
to any service is undecided too -- calling one a non-match is how a trace
names the wrong rule.

### Creating and changing rules

```bash
nsxctl group create g-web --criteria 'tag:env=prod AND tag:tier=web'
nsxctl rule create allow-web-db --policy app-tier \
    --from g-web --to g-db --service MySQL --action ALLOW
nsxctl rule move allow-web-db --before deny-all
nsxctl apply changes.yaml
```

**Dry run by default.** Nothing is written without `--enable-writes`, and the
plan is rendered by the same diff engine `nsxctl drift` uses, so a preview of a
change looks exactly like the drift report of that change:

```
  MODIFY rule allow-web-db   [lm-london]
      [security] action: ALLOW -> DROP
      [cosmetic] display_name: allow-web-db -> Allow web to db
```

**The proposed rule is run through `rule hygiene` before it is written:**

```
  PREFLIGHT: the proposed change would be reported by `nsxctl rule hygiene`:
    critical any_any_allow
      source and destination are both ANY with ALLOW -- permits all traffic
```

**Concurrent edits are refused by NSX itself.** Every write carries back the
`_revision` it read; NSX answers 412 if anything changed in between, so two
operators editing the same rule cannot silently clobber each other:

```
$ nsxctl rule edit allow-web-db --action DROP --enable-writes
  FAILED modify rule 'allow-web-db'
      modify rule 'allow-web-db' changed on NSX since the plan was built, so
      the write was refused rather than overwriting somebody else's change.
```

`--force` overrides it. A GM-authored object is never written through a Local
Manager -- NSX realizes those read-only, and the refusal names the reason.

#### Criteria syntax

```
tag:SCOPE=VALUE     tag equals          tag:env=prod
tag:SCOPE~VALUE     tag contains        tag:owner~platform
name=VALUE          VM name equals      name=web-prod-01
name~VALUE          VM name contains    name~web-
ip:A[,B...]         IP addresses/CIDRs  ip:10.0.0.0/8
```

Joined with `AND` or `OR`. **Mixing the two is refused rather than sent**: NSX
applies one conjunction operator per expression, so a mixed expression would
not select what it reads as -- which for a firewall group is the whole
ballgame.

#### Declarative batches

```yaml
groups:
  - id: g-web
    display_name: Web tier
    criteria: 'tag:env=prod AND tag:tier=web'
  - id: g-retired
    state: absent

rules:
  - id: allow-web-db
    policy: app-tier
    source: [g-web]
    destination: [g-db]
    services: [MySQL]
    action: ALLOW
```

`nsxctl apply changes.yaml` plans every entry, prints one combined diff, and
writes nothing that already matches NSX. JSON is always accepted; YAML needs
PyYAML.

#### Undo is asymmetric, and says so

`nsxctl audit undo` reverses one entry. Every write -- tags, groups and rules
alike -- is logged with both sides of it.

| Undoing a | Becomes | Reliable? |
|---|---|---|
| create | a delete | yes |
| modify | a write of the before-body | yes |
| delete | recreating the object | **no** |

Recreating a deleted object cannot be guaranteed: anything that referenced it
may have been cleaned up in the meantime. Snapshots are the real backstop
there, which is also why `snapshot restore` is deliberately *not* part of this
-- restoring a whole DFW is a different class of risk from undoing one rule.

Audit entries written before authoring existed still list and still undo. The
tag fields were kept and the general ones added alongside, with one reader
mapping both shapes.

### What does this NSX actually serve?

```bash
nsxctl doctor
```

The toolkit degrades rather than fails in a dozen places -- statistics may 404,
traceflow is Local-Manager-only, Projects may not exist, some group criteria
are not VM-resolvable. Every one of those is handled where it happens, which
means **a missing feature and a bug in the tool look identical** until you ask:

```
  lm-london  Local Manager  https://lm-lon.example.com:443
    Capability          Status   Detail                    Affects
    ------------------  -------  ------------------------  -----------------------
    groups              ok       412 item(s)
    rule statistics     missing  404 -- not served ...      rule hygiene unused
                                                            checks, rule baseline
    traceflow           ok       0 item(s)
```

Every probe is a bounded read. Nothing is written, and **traceflow is checked
by listing, never by injecting a packet** -- a capability check that put real
traffic on the data plane every time somebody asked what their NSX supports
would be its own kind of bug.

`nsxctl doctor --json` is the one output worth pasting into a bug report.
`--fail-on-missing` makes it a pipeline gate.

### Running it on a schedule

```bash
nsxctl rule hygiene --only-on-change --notify "$SLACK_WEBHOOK"
nsxctl drift --fail-on-drift security --out-junit drift.xml
nsxctl doctor --out-metrics /var/lib/node_exporter/nsxctl.prom
```

| Flag | What consumes it |
|---|---|
| `--out-junit PATH` | A pipeline, showing each check as a test |
| `--out-sarif PATH` | A code-scanning UI, annotating findings by severity |
| `--out-metrics PATH` | A node_exporter textfile collector |
| `--notify URL` | One POST with the summary, for chat or an incident tool |
| `--only-on-change` | Print nothing and notify nobody unless the findings differ |

**`--only-on-change` is what makes a nightly cron bearable.** Each run
fingerprints its own findings and compares that with the last. Unchanged, the
whole report is discarded *before it reaches stdout*, so cron sends no mail;
changed, it prints in full and the webhook fires. Without it a scheduled
hygiene report mails you the same 40 findings every morning until you pipe it
to `/dev/null` -- and then you never see number 41.

The fingerprint is built only from what a finding *is*, never from when it ran,
and the state is written **only when `--only-on-change` is given**: a plain
interactive run that quietly primed it would make your first scheduled run
silent with forty findings sitting there unreported.

Metrics emit a zero series when clean, because an alert rule needs a series
that exists and reads zero, not one that vanishes.

### Proposing rules from traffic you actually saw

```bash
nsxctl recommend flows.csv
nsxctl recommend flows.csv --policy app-tier --out-file proposed.json
nsxctl apply proposed.json          # review first; dry run by default
```

Reads a flow export you already have -- NSX Intelligence export, vRNI, a
firewall-log query -- rather than calling the Intelligence recommendation API,
which is licensed separately and absent on most estates. Column names are
matched loosely (`src`, `src_ip`, `source_ip` all work) because every exporter
names them differently and none of them are wrong.

```
    Source   Destination  Proto  Ports  Flows
    Web      DB           tcp    3306   913

  UNCLASSIFIED: 1 address(es) belong to no group:
    10.9.9.9           destination  5 flow(s)
    These are the most useful rows here: traffic exists and nobody has
    classified the workload. No rule is proposed for them.
```

Three things it will not do:

- **It never proposes a default-deny.** No traffic seen in one window is not
  evidence none exists -- the same reasoning that stops a zero hit count
  retiring a rule.
- **It never invents a group for an address nobody claims.** An unresolved
  endpoint is reported, because that is the finding.
- **A pair talking on more than `--max-ports` ports is flagged, not ruled.**
  That shape is usually a scanner or a monitoring host, and one rule with fifty
  ports would bury it.

Denied flows are ignored unless `--include-denied`: a blocked flow is usually
evidence the segmentation is working, not evidence a rule is missing.

### Putting a snapshot back

```bash
nsxctl snapshot restore approved                      # dry run
nsxctl snapshot restore approved --enable-writes
nsxctl snapshot restore approved --prune --enable-writes
```

Per-object, through the same plan-then-apply path as `nsxctl rule edit`: each
object gets a field-level diff you can read, a `_revision` check that refuses
to overwrite a concurrent edit, and its own audit entry. A restore is
reviewable and individually undoable, not a blind push of a whole tree.

**Deleting is opt-in.** An object that exists now but not in the snapshot is
left alone unless you pass `--prune`: a snapshot records what *was* there, it
does not assert that nothing else may exist, and a group created legitimately
since is not drift to be erased.

### More than one estate

```bash
nsxctl profiles
nsxctl --profile dr status
NSX_PROFILE=dr nsxctl compliance
```

```json
{"default_profile": "prod",
 "profiles": {
   "prod": {"managers": [...]},
   "dr":   {"managers": [...]}}}
```

The flat single-estate inventory `nsxctl init` writes still works exactly as
it always did. With several profiles and no `default_profile`, the tool
**refuses rather than picking one** -- guessing which estate to talk to is the
one wrong answer that matters.

### NSX Projects

```bash
nsxctl projects
nsxctl --project tenant-a rule list
```

A Project has its own infra tree, so `--project` swaps the policy base rather
than filtering results. Objects in the default infra are genuinely not visible
from inside a project, and vice versa.

### The three you'll actually use daily

```bash
# Is my tagging where I think it is?
nsxctl compliance

# What breaks if I retag this VM?
nsxctl impact web-prod-01

# Which VMs are tagged env=prod?
nsxctl tag find --scope env --tag prod --out-csv prod.csv

# What is wrong with my firewall policy?
nsxctl rule hygiene

# Why can't web01 reach db01?
nsxctl trace web-prod-01 db-prod-01 --port 3306
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
nsxctl completion cache          # so TAB can complete object names too
```

The script is generated from the live command tree, so it always matches the
commands your build actually has.

It also completes **names**, not just flags -- `--policy <TAB>`, `--from
<TAB>`, `nsxctl rule show <TAB>`. Those come from a cache file that ordinary
list commands refresh as a side effect. **Pressing TAB never makes a network
call**: a completion that reached out to eight managers would turn a keystroke
into a two-second stall, and into a hang on an unreachable one. A stale cache
completes a stale name and NSX says so, which is the right failure. The cache
is per profile and project, because completing production names into a DR
command is worse than completing nothing.

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

- **Read-only by default.** Changes need `--enable-writes`. That includes
  every authoring command: `group create`, `rule edit` and `apply` all print a
  plan and stop.
- **`nsxctl trace` injects a packet, and asks first.** It is the one read in
  the toolkit that touches the data plane. `--static` sends nothing.
- **Dry run always runs first.** `nsxctl tag apply` prints the full plan before
  anything is written.
- **Non-interactive writes need `--yes`.** Without a terminal and without
  `--yes`, it refuses rather than assuming consent.
- **Concurrent edits are detected.** Each VM is re-read immediately before it is
  written; if its tags changed since the plan was computed, that row fails
  instead of overwriting someone else's change. `--force` overrides. Group and
  rule writes get this from NSX itself: the `_revision` read at plan time rides
  back with the write, and NSX rejects a stale one with 412.
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
  policy.py snapshot.py diff.py             traversal, capture, comparison
  trace.py                                  traceflow + static path evaluation
  authoring.py                              criteria parsing, planned writes
  sinks.py                                  JUnit, SARIF, metrics, webhook, state
  flows.py                                  observed flows -> proposed rules
  namecache.py                              names for completion, never live
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
