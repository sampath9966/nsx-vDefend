"""Operational health: alarms, certificates, capacity."""
import datetime

from ..api import (
    F_CAPACITY_USAGE_DATA,
    F_CURRENT_USAGE_COUNT,
    F_DISPLAY_NAME,
    F_EVENT_COUNT,
    F_FEATURE_DISPLAY_NAME,
    F_FIRST_REPORTED_TIME,
    F_ID,
    F_LAST_REPORTED_TIME,
    F_LINK_HREF,
    F_MAX_SUPPORTED_COUNT,
    F_MAX_THRESHOLD_PERCENT,
    F_MIN_THRESHOLD_PERCENT,
    F_NOT_AFTER,
    F_SEVERITY,
    F_USAGE_TYPE,
    F_USED_BY_LINKS,
)
from ..output import cBG, cBR, cBY, cD, parallel_run, say, section, table

ALARM_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ALARM_HEADERS = [
    "manager", "severity", "summary", "node", "count", "first_seen", "last_seen",
]
CERT_HEADERS = ["manager", "name", "expires", "days_left", "used_by", "status"]
CAP_HEADERS  = ["manager", "resource", "used", "limit", "pct", "status"]


def _ts_ms_to_date(ms):
    try:
        return datetime.datetime.fromtimestamp(
            int(ms) / 1000, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d")
    except Exception:
        return ""


def _days_until_ms(ms):
    try:
        exp = datetime.datetime.fromtimestamp(int(ms) / 1000, tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        return (exp - now).days
    except Exception:
        return None


def _color_alarm(row):
    sev = row[1]
    if sev == "CRITICAL":
        return [cBR(c) for c in row]
    if sev == "HIGH":
        return [cBY(c) for c in row]
    return row


def act_alarms(sessions, exporter, severity=None, show_all=False):
    """Collect alarms from every manager, dedup by id, sort by severity."""
    status = None if show_all else "OPEN"
    fetched = parallel_run(
        sessions,
        lambda s: s.get_alarms(status=status, severity=severity),
        label="Fetching alarms",
    )
    seen, rows = set(), []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for alarm in (result or []):
            aid = alarm.get(F_ID, "")
            if aid and aid in seen:
                continue
            seen.add(aid)
            rows.append([
                s.name,
                alarm.get(F_SEVERITY, ""),
                alarm.get(F_FEATURE_DISPLAY_NAME,
                          alarm.get("summary", alarm.get("alarm_source", ""))),
                alarm.get("node_resource_display_name",
                          alarm.get("node_id", "")),
                str(alarm.get(F_EVENT_COUNT, 1)),
                _ts_ms_to_date(alarm.get(F_FIRST_REPORTED_TIME, 0)),
                _ts_ms_to_date(alarm.get(F_LAST_REPORTED_TIME, 0)),
            ])
    rows.sort(key=lambda r: ALARM_ORDER.get(r[1], 99))
    section("Alarms ({})".format(len(rows)))
    if rows:
        table(ALARM_HEADERS, [_color_alarm(r) for r in rows])
    else:
        say("  No alarms found.")
    exporter.stage("alarms", ALARM_HEADERS, rows)


def act_cert_list(sessions, exporter, warn_days=90, expired_only=False):
    """List TLS certificates across all managers with expiry status."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_certificates(),
        label="Fetching certificates",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for cert in (result or []):
            days = _days_until_ms(cert.get(F_NOT_AFTER, 0))
            if days is None:
                status, display = "UNKNOWN", cD("UNKNOWN")
            elif days <= 0:
                status, display = "EXPIRED", cBR("EXPIRED")
            elif days <= 30:
                status, display = "CRITICAL", cBR("CRITICAL")
            elif days <= warn_days:
                status, display = "WARNING", cBY("WARNING")
            else:
                status, display = "OK", cBG("OK")
            if expired_only and status not in ("EXPIRED", "CRITICAL"):
                continue
            used = ", ".join(
                lnk.get(F_LINK_HREF, "").rsplit("/", 1)[-1]
                for lnk in (cert.get(F_USED_BY_LINKS) or [])
            ) or "-"
            rows.append([
                s.name,
                cert.get(F_DISPLAY_NAME, cert.get(F_ID, "")),
                _ts_ms_to_date(cert.get(F_NOT_AFTER, 0)),
                str(days if days is not None else "?"),
                used,
                display,
            ])
    section("Certificates ({})".format(len(rows)))
    if rows:
        table(CERT_HEADERS, rows)
    else:
        say("  No certificates found.")
    # Store plain status strings (not colored) for structured export
    plain_rows = [r[:-1] + [r[-1].strip("\x1b[0m").strip()] for r in rows]
    exporter.stage("certificates", CERT_HEADERS, plain_rows)


def act_capacity(sessions, exporter):
    """Show per-resource utilisation across all managers."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_capacity(),
        label="Fetching capacity",
    )
    all_rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        data = (result or {}).get(F_CAPACITY_USAGE_DATA, [])
        rows = []
        for entry in data:
            used  = entry.get(F_CURRENT_USAGE_COUNT, 0)
            limit = entry.get(F_MAX_SUPPORTED_COUNT, 0)
            pct   = int(used * 100 / limit) if limit else 0
            max_thr = entry.get(F_MAX_THRESHOLD_PERCENT, 90)
            min_thr = entry.get(F_MIN_THRESHOLD_PERCENT, 75)
            if pct >= max_thr:
                display = cBR("HIGH")
            elif pct >= min_thr:
                display = cBY("WARN")
            else:
                display = cBG("OK")
            rows.append([
                s.name,
                entry.get(F_USAGE_TYPE, ""),
                str(used),
                str(limit),
                "{}%".format(pct),
                display,
            ])
            all_rows.append(rows[-1])
        section("{} capacity".format(s.name))
        if rows:
            table(CAP_HEADERS, rows)
        else:
            say("  No capacity data.")
    exporter.stage("capacity", CAP_HEADERS, all_rows)
