# VCF integration

`nsxctl vcf import` queries a VMware Cloud Foundation SDDC Manager and automatically populates the nsxctl inventory with the NSX Local Manager for every SDDC it finds.

---

## How it works

1. Authenticates to the SDDC Manager REST API (`/v1/sddcs`) using HTTP Basic auth.
2. Extracts the `nsxtManager.hostname` from each SDDC record.
3. Loads the existing inventory file (if any) and skips hosts that are already present.
4. Prints a status table: each discovered SDDC, its NSX host, and whether it is `new` or `already present`.
5. Writes the updated inventory when `--enable-writes` is passed.

---

## Basic usage

```sh
nsxctl vcf import \
  --vcf-host sddc-mgr.corp.example.com \
  --vcf-user administrator@vsphere.local \
  --out inventory.json \
  --enable-writes
```

Omit `--enable-writes` to preview what would be added without touching the file.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `--vcf-host HOST` | required | SDDC Manager hostname or IP |
| `--vcf-user USER` | `administrator@vsphere.local` | SDDC Manager username |
| `--vcf-password PASS` | prompted | Password (prompted interactively if omitted) |
| `--out PATH` | `inventory.json` | Inventory file to create or update |
| `--ca-bundle PATH` | system CA | CA bundle for TLS verification of the SDDC Manager |

---

## TLS

The SDDC Manager API is always HTTPS. By default, the system CA bundle is used for verification.

For environments with a private CA:

```sh
nsxctl vcf import \
  --vcf-host sddc-mgr.corp.example.com \
  --ca-bundle /etc/pki/tls/certs/corp-ca.pem \
  --out inventory.json \
  --enable-writes
```

---

## Credentials for the discovered managers

`vcf import` populates the inventory with the NSX Manager hostnames. Credentials for each manager are configured separately (see [configuration.md](configuration.md)). The typical pattern for a VCF environment is to use environment variables per manager, keyed by SDDC name:

```jsonc
// inventory.json (after vcf import)
{
  "managers": [
    {
      "name": "sddc-london",
      "role": "lm",
      "host": "nsx-lon.corp.example.com",
      "verify_ssl": true,
      "auth": "session",
      "username_env": "NSX_SDDC_LONDON_USER",
      "password_env": "NSX_SDDC_LONDON_PASS"
    }
  ]
}
```

Set the corresponding environment variables in your shell or secret store, then run `nsxctl status` to verify connectivity across all discovered managers.

---

## Multi-SDDC fleet pattern

For a large fleet, run `vcf import` once per SDDC Manager (if you have multiple) into the same inventory file. The merge logic is idempotent — hosts already present are skipped:

```sh
for HOST in sddc-mgr-lon.corp.example.com sddc-mgr-fra.corp.example.com; do
  nsxctl vcf import \
    --vcf-host "$HOST" \
    --out inventory.json \
    --enable-writes
done
```

Then verify the full fleet in one shot:

```sh
nsxctl --all-lm status
```

---

## Automation

In a CI/CD pipeline, supply credentials via environment variables and use `--yes` to suppress prompts:

```sh
nsxctl vcf import \
  --vcf-host "$VCF_HOST" \
  --vcf-user "$VCF_USER" \
  --vcf-password "$VCF_PASSWORD" \
  --out inventory.json \
  --enable-writes \
  --yes
```
