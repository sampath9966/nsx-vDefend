# Security

## Reporting a vulnerability

If you find a security vulnerability in nsxctl, **do not open a public GitHub issue.**

Report it privately via GitHub's security advisory feature:
**[Report a vulnerability](https://github.com/sampath9966/nsx-vDefend/security/advisories/new)**

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal reproduction case if possible)
- Any suggested fix or workaround you have in mind

You should receive an acknowledgement within 72 hours. We aim to publish a fix and advisory within 14 days of a confirmed report.

---

## Security design notes

### Credential handling

- Credentials are **never stored in `inventory.json`**. The file holds only the names of environment variables from which credentials are read at runtime.
- The optional keyring backend (`--store keyring`) delegates to the OS credential store (macOS Keychain, GNOME Keyring, Windows Credential Manager).
- The plaintext cache (`--store plaintext`) writes to `~/.nsx_toolkit/credentials.json` with mode `0600`. No credentials are written to disk unless this backend is explicitly selected.
- Passwords accepted at interactive prompts use `getpass.getpass()` and are never echoed.

### Write gate

- Every command is read-only unless `--enable-writes` is explicitly passed.
- Mutating commands issue a confirmation prompt unless `--yes` is also given.
- The audit log records every write with its author, timestamp, and full before/after diff so changes can be reviewed and rolled back.

### TLS

- TLS verification is enabled by default (`verify_ssl: true`).
- A per-manager `ca_bundle` path or a global `--ca-bundle` flag loads a private CA bundle. This is the recommended approach for environments with a private PKI.
- Setting `verify_ssl: false` in the inventory suppresses certificate verification. This is provided for lab environments only and should never be used in production.

### Network

- `nsxctl` makes outbound HTTPS connections to the NSX managers listed in the inventory. It does not open any listening sockets.
- The VCF integration (`vcf import`) additionally connects to the SDDC Manager host specified on the command line.
- No telemetry or analytics data is sent anywhere.

### Dependencies

- The tool has **no required runtime dependencies**. The standard library `urllib` transport is always available as a fallback.
- `requests` is used when present (pip install `nsxctl[http]`). Pinned to `>=2.20` to ensure modern TLS handling.
- `keyring` is optional (`nsxctl[keyring]`).
- `pyyaml` is optional (`nsxctl[yaml]`) — used only when YAML-format taxonomy or apply files are loaded.
