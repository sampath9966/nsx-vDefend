# Configuration

## Inventory file

`nsxctl` reads a JSON file that describes the NSX managers in your estate. The default search order is:

1. `./inventory.json` (current directory)
2. `~/.nsx_toolkit/inventory.json`

Override with `--inventory PATH` or create the file interactively with `nsxctl init`.

### Full schema

```jsonc
{
  // Optional: group managers into named profiles (estates).
  // Omit "profiles" to have a flat, single-profile inventory.
  "profiles": {
    "production": ["gm", "lm-london", "lm-frankfurt"],
    "staging":    ["lm-staging"]
  },

  "managers": [
    {
      // Required fields
      "name": "gm",           // Unique label used in --manager / --profile
      "role": "gm",           // "gm" | "lm"
      "host": "gm.nsx.example.com",

      // Optional — defaults shown
      "port":       443,
      "scheme":     "https",
      "verify_ssl": true,     // Set false only for lab; pass ca_bundle in prod
      "ca_bundle":  "/etc/pki/tls/certs/corp-ca.pem",
      "timeout":    30,

      // Auth
      "auth":         "session",      // "session" (cookie) | "basic"
      "username_env": "NSX_GM_USER",  // Read username from this env var
      "password_env": "NSX_GM_PASS"   // Read password from this env var
    }
  ]
}
```

### Roles

| Role | Description |
|---|---|
| `gm` | Global Manager — queried for federated objects (global groups, spans) |
| `lm` | Local Manager — queried for domain-local policy, groups, topology |

Commands that target a specific scope use these roles to fan out correctly. Passing `--all-lm` restricts the query to Local Managers only.

---

## Credential storage

Credentials are never stored in the inventory file itself. Three backends are supported, tried in order:

| Backend | When used |
|---|---|
| Environment variables | `username_env` / `password_env` fields are set in the inventory |
| OS keyring | `--store keyring` (requires `pip install nsxctl[keyring]`) |
| Plaintext cache | `--store plaintext` — stored in `~/.nsx_toolkit/credentials.json`, chmod 600 |

`nsxctl login` prompts for credentials and stores them in whichever backend is configured.

---

## Multi-profile inventories

A single inventory file can represent multiple estates (production, staging, DR). Define a `profiles` map at the top level:

```jsonc
{
  "profiles": {
    "prod":    ["gm-prod", "lm-lon", "lm-fra"],
    "staging": ["lm-staging"]
  },
  "managers": [ /* ... all managers ... */ ]
}
```

Select a profile at runtime:

```sh
nsxctl --profile prod group list
nsxctl --profile staging rule list

# Or via environment variable
export NSX_PROFILE=prod
nsxctl group list
```

---

## NSX Projects

To scope all policy paths to an NSX Project (multi-tenancy):

```sh
nsxctl --project finance-bu rule list
```

Objects in the default infra scope are not visible from inside a project context.

---

## CA bundles

For production environments with private CAs:

```sh
# Per-manager (in inventory.json)
{ "ca_bundle": "/etc/pki/tls/certs/corp-ca.pem" }

# Global override on the command line
nsxctl --ca-bundle /path/to/bundle.pem status
```

---

## Tag taxonomy

An optional taxonomy file defines which tag scopes and values are valid. Without it, any tag is accepted.

```jsonc
// taxonomy.json
{
  "format": "^[a-z0-9][a-z0-9\\-]*$",
  "allow_unknown_scopes": false,
  "scopes": {
    "tenant":      { "required": true },
    "app":         { "required": true },
    "env":         { "required": true, "values": ["prod", "uat", "dev", "staging"] },
    "tier":        { "required": true, "values": ["web", "app", "db", "mgmt", "dmz"] },
    "site":        { "required": true },
    "criticality": { "required": false, "values": ["critical", "high", "medium", "low"] }
  }
}
```

Load it with `--taxonomy taxonomy.json` or place it alongside `inventory.json` as `taxonomy.json`.
