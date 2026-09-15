# Authoring — writing changes to NSX

`nsxctl` treats NSX as an immutable system by default. Every command is read-only unless `--enable-writes` is explicitly passed. This document covers the write surface: the declarative apply format, the write gate, the audit log, and rollback.

---

## The write gate

Any command that would modify NSX requires two things:

1. `--enable-writes` — signals intent to mutate
2. Confirmation at the prompt (bypassed with `--yes`)

Without `--enable-writes`, every mutating code path executes in dry-run mode, printing what would change without making any API calls.

```sh
# Dry run — safe, prints proposed changes
nsxctl apply policy.yaml

# Actual write — requires explicit opt-in
nsxctl apply policy.yaml --enable-writes

# Unattended write (CI, automation)
nsxctl apply policy.yaml --enable-writes --yes
```

---

## Declarative apply format

`nsxctl apply` reads YAML or JSON files that declare groups and rules. The format mirrors the NSX policy API but strips away transport boilerplate.

### Groups

```yaml
groups:
  - id: g-web-tier
    display_name: Web Tier
    description: All production web VMs
    expression:
      - member_type: VirtualMachine
        key: Tag
        operator: EQUALS
        scope: tier
        value: web

  - id: g-db-tier
    display_name: DB Tier
    expression:
      - member_type: VirtualMachine
        key: Tag
        operator: EQUALS
        scope: tier
        value: db
```

### Rules

```yaml
policies:
  - id: app-segmentation
    display_name: App Segmentation
    category: Application
    rules:
      - id: allow-web-to-db
        display_name: Web to DB (MySQL)
        source_groups: [/infra/domains/default/groups/g-web-tier]
        destination_groups: [/infra/domains/default/groups/g-db-tier]
        services: [/infra/services/MySQL]
        action: ALLOW
        logged: true

      - id: default-deny
        display_name: Default deny
        source_groups: [ANY]
        destination_groups: [ANY]
        services: [ANY]
        action: DROP
        logged: true
```

Apply it:

```sh
nsxctl apply segmentation.yaml --enable-writes
```

---

## Change tickets

Every write operation can carry a change ticket reference. Set it with `--change-ticket`:

```sh
nsxctl apply policy.yaml \
  --enable-writes \
  --change-ticket CHG0012345
```

The ticket ID is stored in the audit log alongside the change.

---

## Audit log

Every successful write is logged to `~/.nsx_toolkit/audit.jsonl` (one JSON object per line). Each entry contains:

- Change ID (UUID)
- Timestamp (UTC)
- Manager name
- Object type, ID and path
- Before and after state
- Change ticket reference (if provided)

```sh
# List recent changes
nsxctl audit list

# Show the last 10 changes on lm-london
nsxctl audit list --manager lm-london --limit 10

# Export the full log to CSV
nsxctl audit list --out-csv audit.csv
```

---

## Rollback

`nsxctl audit undo` replays the before-state of a change through the same revision-checked write path:

```sh
nsxctl audit undo <change-id> --enable-writes
```

The undo operation itself is logged. It respects the current revision of the object — if the object has changed since the original write, the undo will fail with a conflict error rather than overwrite the newer state. Resolve the conflict manually, then retry.

---

## Bulk tag operations

Tag changes across many VMs are expressed as a CSV:

| Column | Values | Description |
|---|---|---|
| `vm_name` | VM display name | Target VM |
| `scope` | any valid scope | Tag scope |
| `tag` | any valid value | Tag value |
| `action` | `add` / `remove` | Operation |

```sh
nsxctl tag bulk changes.csv --dry-run
nsxctl tag bulk changes.csv --enable-writes
```

The taxonomy file (if configured) validates scope and value before any change is sent.

---

## Snapshot and restore

Snapshots capture the full policy state as a point-in-time JSON file. Restore replays each object through the authoring engine, making only the changes needed to reconcile live state with the snapshot.

```sh
# Save current state
nsxctl snapshot save --name before-change-window

# ... make changes ...

# Compare against the snapshot
nsxctl drift

# Roll back everything to the snapshot
nsxctl snapshot restore snapshots/before-change-window.json --enable-writes
```
