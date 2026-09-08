"""Machine-readable outputs, and the state that makes a scheduled run quiet.

A report you have to remember to run is a report nobody runs. These are the
formats something else consumes on your behalf:

  * **JUnit XML** -- a pipeline shows each check as a test, so a new any-any
    ALLOW appears in the same place as a failing unit test.
  * **SARIF** -- a code-scanning UI annotates findings, with severities that
    map to the ones the checks already produce.
  * **Prometheus textfile** -- a node_exporter collector turns "3 critical
    findings" into a graph and an alert rule.
  * **A webhook** -- one POST with the summary, for chat or an incident tool.

And the piece that makes a nightly cron bearable: **quiet unless changed**.
Every run fingerprints its own findings and compares that against the last
run's. Unchanged, the whole report is discarded before it reaches stdout, so
cron sends no mail; changed, it prints in full and the webhook fires. Without
this, a scheduled hygiene report mails you the same 40 findings every morning
until you filter it to /dev/null, and then you never see number 41.
"""

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.sax.saxutils as saxutils

from .errors import NsxError
from .output import debug
from .paths import DATA_DIR, utc_now_iso
from .version import TOOL_NAME, VERSION

STATE_DIR = os.path.join(DATA_DIR, "state")

# Every severity vocabulary in the toolkit, mapped onto the two that machine
# formats understand. Anything unrecognised is a warning: under-reporting a
# finding is worse than over-reporting one.
SARIF_LEVELS = {
    "critical": "error", "high": "error", "security": "error",
    "missing": "error", "medium": "warning", "degraded": "warning",
    "low": "note", "cosmetic": "note", "ok": "none", "n/a": "none",
}
FAILING_SEVERITIES = frozenset({"critical", "high", "security", "missing",
                                "medium", "degraded"})

WEBHOOK_TIMEOUT = 10.0


def sarif_level(severity):
    return SARIF_LEVELS.get(str(severity).lower(), "warning")


def is_failing(severity):
    return str(severity).lower() in FAILING_SEVERITIES


# === FINDINGS ===
def make_finding(check, severity, message, where="", passed=False, detail=""):
    """One machine-readable finding. A plain dict on purpose: it is written to
    four formats and posted to a fifth, and none of them want an object."""
    return {"check": str(check), "severity": str(severity),
            "message": str(message), "where": str(where),
            "passed": bool(passed), "detail": str(detail)}


def summarise_findings(findings):
    counts = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return counts


# === JUNIT ===
def _xml_attr(value):
    return saxutils.quoteattr(str(value))


def _xml_text(value):
    return saxutils.escape(str(value))


def render_junit(suites):
    """suites: {suite name: [finding, ...]}.

    A passing check still emits a testcase. A suite with no testcases at all
    reads in most CI UIs as "did not run", which is exactly the wrong thing to
    show for a clean estate.
    """
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>"]
    for name in sorted(suites):
        items = suites[name]
        failures = sum(1 for f in items if not f["passed"])
        parts.append(
            '  <testsuite name={} tests="{}" failures="{}" timestamp={}>'
            .format(_xml_attr(name), len(items) or 1, failures,
                    _xml_attr(utc_now_iso())))
        if not items:
            parts.append(
                '    <testcase classname={} name="no findings"/>'.format(
                    _xml_attr(name)))
        for item in items:
            case = '    <testcase classname={} name={}'.format(
                _xml_attr(name),
                _xml_attr("{}: {}".format(item["check"], item["where"])
                          if item["where"] else item["check"]))
            if item["passed"]:
                parts.append(case + "/>")
                continue
            parts.append(case + ">")
            parts.append(
                '      <failure type={} message={}>{}</failure>'.format(
                    _xml_attr(item["severity"]), _xml_attr(item["message"]),
                    _xml_text(item["detail"] or item["message"])))
            parts.append("    </testcase>")
        parts.append("  </testsuite>")
    parts.append("</testsuites>")
    return "\n".join(parts) + "\n"


# === SARIF ===
def render_sarif(findings, tool_name=TOOL_NAME, version=VERSION):
    """SARIF 2.1.0. Rules are deduplicated by check name so a UI groups them."""
    rules, seen = [], {}
    for item in findings:
        if item["check"] in seen:
            continue
        seen[item["check"]] = len(rules)
        rules.append({
            "id": item["check"],
            "shortDescription": {"text": item["check"].replace("_", " ")},
            "defaultConfiguration": {"level": sarif_level(item["severity"])},
        })
    results = []
    for item in findings:
        if item["passed"]:
            continue
        results.append({
            "ruleId": item["check"],
            "ruleIndex": seen[item["check"]],
            "level": sarif_level(item["severity"]),
            "message": {"text": item["detail"] or item["message"]},
            "properties": {"severity": item["severity"],
                           "object": item["where"]},
            # NSX objects are not files, so the "location" is the object path.
            # Emitting a fake file location would make a UI offer to open it.
            "locations": [{"logicalLocations": [
                {"fullyQualifiedName": item["where"] or item["check"],
                 "kind": "resource"}]}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": version,
                                "rules": rules}},
            "results": results,
        }],
    }, indent=2) + "\n"


# === PROMETHEUS ===
def _metric_name(text):
    cleaned = "".join(c if c.isalnum() else "_" for c in str(text).lower())
    return cleaned.strip("_") or "unknown"


def render_metrics(command, findings, extra=None, prefix="nsxctl"):
    """Prometheus textfile format, for a node_exporter collector directory.

    One gauge per severity plus a run timestamp, which is what an alert rule
    needs: "critical findings above zero" and "this check has not run today"
    are both real alerts, and the second one is the one people forget.
    """
    counts = summarise_findings([f for f in findings if not f["passed"]])
    lines = [
        "# HELP {}_findings Findings by severity from the last run.".format(
            prefix),
        "# TYPE {}_findings gauge".format(prefix),
    ]
    for severity in sorted(counts):
        lines.append('{}_findings{{command="{}",severity="{}"}} {}'.format(
            prefix, _metric_name(command), _metric_name(severity),
            counts[severity]))
    if not counts:
        lines.append('{}_findings{{command="{}",severity="none"}} 0'.format(
            prefix, _metric_name(command)))
    lines.extend([
        "# HELP {}_last_run_timestamp_seconds When this command last "
        "completed.".format(prefix),
        "# TYPE {}_last_run_timestamp_seconds gauge".format(prefix),
        '{}_last_run_timestamp_seconds{{command="{}"}} {}'.format(
            prefix, _metric_name(command), int(time.time())),
    ])
    for key, value in sorted((extra or {}).items()):
        lines.extend([
            "# TYPE {}_{} gauge".format(prefix, _metric_name(key)),
            '{}_{}{{command="{}"}} {}'.format(
                prefix, _metric_name(key), _metric_name(command), value),
        ])
    return "\n".join(lines) + "\n"


# === WRITING ===
def write_text(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Written whole then moved, so a collector never reads half a file.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    return path


# === WEBHOOK ===
def post_webhook(url, payload, timeout=WEBHOOK_TIMEOUT):
    """POST a JSON summary. Returns the status code.

    Deliberately stdlib-only and deliberately not retried: a notification that
    silently retries into a chat channel is how one failing check becomes
    forty messages. One attempt, and the failure is reported.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise NsxError(
            "Webhook URL must be http or https (got {!r}).".format(url))
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "{}/{}".format(TOOL_NAME.replace(" ", "-"),
                                              VERSION)})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as e:
        raise NsxError("Webhook returned HTTP {}.".format(e.code)) from e
    except (urllib.error.URLError, OSError) as e:
        raise NsxError("Webhook could not be reached: {}".format(e)) from e


def webhook_payload(command, findings, changed, profile=None, project=None):
    counts = summarise_findings([f for f in findings if not f["passed"]])
    worst = ""
    for severity in ("critical", "security", "missing", "high", "medium",
                     "degraded", "low", "cosmetic"):
        if counts.get(severity):
            worst = severity
            break
    return {
        "tool": TOOL_NAME, "version": VERSION, "command": command,
        "timestamp": utc_now_iso(), "profile": profile or "",
        "project": project or "", "changed_since_last_run": bool(changed),
        "total": sum(counts.values()), "worst_severity": worst,
        "counts": counts,
        "findings": [f for f in findings if not f["passed"]][:50],
    }


# === RUN STATE ===
def fingerprint(findings):
    """A stable hash of what the run found.

    Sorted and built only from what a finding *is*, never from when it ran or
    how long it took -- otherwise every run differs from the last and
    "quiet unless changed" is never quiet.
    """
    material = sorted(
        "{}|{}|{}|{}".format(f["check"], f["severity"], f["where"],
                             f["message"])
        for f in findings if not f["passed"])
    digest = hashlib.sha256("\n".join(material).encode("utf-8")).hexdigest()
    return digest


def state_path(command, profile=None, project=None, root=None):
    safe = "".join(c if c.isalnum() else "_"
                   for c in "{}_{}_{}".format(command, profile or "default",
                                              project or "infra"))
    return os.path.join(root or STATE_DIR, safe[:100] + ".json")


def load_state(command, profile=None, project=None, root=None):
    try:
        with open(state_path(command, profile, project, root),
                  encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(command, digest, counts, profile=None, project=None, root=None):
    path = state_path(command, profile, project, root)
    try:
        write_text(path, json.dumps({
            "command": command, "fingerprint": digest, "counts": counts,
            "last_run": utc_now_iso()}, indent=2, sort_keys=True) + "\n")
    except OSError as e:
        debug("could not write run state {}: {}".format(path, e))
        return None
    return path


def changed_since_last(command, findings, profile=None, project=None,
                       root=None):
    """(changed, previous_state). A first run always counts as changed."""
    digest = fingerprint(findings)
    previous = load_state(command, profile, project, root)
    if not previous:
        return True, {}
    return previous.get("fingerprint") != digest, previous
