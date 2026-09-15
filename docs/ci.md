# CI and pipeline integration

`nsxctl` is designed to run unattended in CI pipelines, cron jobs, and change-management automation. Every command supports structured output formats and a set of flags that make it easy to integrate with existing tooling.

---

## Key flags

| Flag | Purpose |
|---|---|
| `--non-interactive` | Never prompt. Fail rather than ask. Required for unattended runs. |
| `--no-color` | Disable ANSI colour codes. |
| `--only-on-change` | Exit 0 and produce no output or notification unless results differ from the last run. |
| `--out-csv PATH` | Write structured results to a CSV file. |
| `--out-json PATH` | Write structured results to JSON. |
| `--out-html PATH` | Write a shareable HTML report. |
| `--out-junit PATH` | Write JUnit XML (test reporters, Jenkins, GitLab). |
| `--out-sarif PATH` | Write SARIF 2.1 (GitHub Code Scanning, Azure DevOps). |
| `--out-metrics PATH` | Write Prometheus textfile metrics for a `node_exporter` collector directory. |
| `--notify URL` | POST a JSON summary to a webhook (Slack, Teams, PagerDuty) when the run finishes. |
| `--fail-on LEVEL` | Exit 1 when hygiene or health findings at or above `LEVEL` exist (`critical` / `high` / `medium` / `low`). |

---

## GitHub Actions

### Nightly drift detection

```yaml
name: NSX drift

on:
  schedule:
    - cron: "0 6 * * 1-5"   # weekdays at 06:00 UTC
  workflow_dispatch:

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install nsxctl
        run: pip install nsxctl

      - name: Run drift check
        run: |
          nsxctl drift \
            --non-interactive \
            --no-color \
            --only-on-change \
            --out-sarif nsx-drift.sarif \
            --notify "${{ secrets.TEAMS_WEBHOOK }}"
        env:
          NSX_GM_USER: ${{ secrets.NSX_GM_USER }}
          NSX_GM_PASS: ${{ secrets.NSX_GM_PASS }}

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: nsx-drift.sarif
```

### Hygiene gate in a change pipeline

```yaml
      - name: DFW hygiene check
        run: |
          nsxctl rule hygiene \
            --fail-on high \
            --non-interactive \
            --out-junit hygiene.xml
        env:
          NSX_LM_USER: ${{ secrets.NSX_LM_USER }}
          NSX_LM_PASS: ${{ secrets.NSX_LM_PASS }}

      - name: Publish hygiene results
        uses: actions/junit-reporter@v1
        if: always()
        with:
          report_paths: hygiene.xml
```

---

## Jenkins

```groovy
pipeline {
    agent any
    environment {
        NSX_GM_USER = credentials('nsx-gm-user')
        NSX_GM_PASS = credentials('nsx-gm-pass')
    }
    stages {
        stage('NSX hygiene') {
            steps {
                sh '''
                    nsxctl rule hygiene \
                        --fail-on high \
                        --non-interactive \
                        --no-color \
                        --out-junit hygiene.xml
                '''
            }
            post {
                always {
                    junit 'hygiene.xml'
                }
            }
        }
    }
}
```

---

## Prometheus / Grafana

`--out-metrics` writes Prometheus text format. Drop it into a `node_exporter` textfile collector directory:

```sh
# /etc/cron.d/nsx-capacity
*/15 * * * * nsxadmin nsxctl capacity \
    --non-interactive \
    --no-color \
    --out-metrics /var/lib/node_exporter/nsx_capacity.prom
```

Metrics are prefixed `nsx_` with labels for `manager` and `resource_type`.

---

## Webhook notification

`--notify URL` POSTs a JSON body to the given URL after every run. The body includes:

```json
{
  "tool": "nsxctl",
  "version": "1.2.0",
  "command": "rule hygiene",
  "managers": ["gm", "lm-london"],
  "exit_code": 1,
  "summary": "3 findings at HIGH or above",
  "timestamp": "2026-09-15T06:00:00Z"
}
```

Compatible with Slack incoming webhooks, Microsoft Teams connectors, and any service that accepts a JSON POST.

---

## Jumpbox / air-gapped environments

On an air-gapped jumpbox with no package access:

```sh
# Copy the zero-dependency single file
scp nsx-toolkit.py jumpbox:/usr/local/bin/nsxctl
chmod +x /usr/local/bin/nsxctl

# It runs on any Python 3.9+ with no pip install
nsxctl status
```

The single file is published as a release asset with each version tag.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or `--only-on-change` with no changes) |
| `1` | Findings at or above `--fail-on` threshold; or a runtime error |
| `2` | Configuration error (inventory not found, manager unreachable, etc.) |
