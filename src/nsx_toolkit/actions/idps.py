"""Advanced security: context profiles and IDS/IPS events."""
from ..api import (
    F_DISPLAY_NAME,
    F_ID,
)
from ..output import cBR, cBY, cD, parallel_run, say, section, table

CTX_PROFILE_HEADERS = ["manager", "id", "name", "type", "attributes"]
IDS_EVENT_HEADERS   = ["manager", "time", "severity", "signature",
                       "src_ip", "dst_ip", "count"]
IDS_PROFILE_HEADERS = ["manager", "id", "name", "overridden_signatures"]


def _sev_color(sev):
    s = str(sev).upper()
    if s in ("CRITICAL", "HIGH"):
        return cBR(s)
    if s == "MEDIUM":
        return cBY(s)
    return cD(s)


def act_context_profile_list(sessions, exporter, contains=None):
    """List NSX context profiles (L7 app / FQDN signatures)."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_context_profiles(),
        label="Fetching context profiles",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for cp in (result or []):
            name = cp.get(F_DISPLAY_NAME, cp.get(F_ID, ""))
            if contains and contains.lower() not in name.lower():
                continue
            attrs = cp.get("attributes") or []
            attr_str = ", ".join(
                "{}={}".format(a.get("key", ""), a.get("value", ""))
                for a in attrs[:3]
            ) or "-"
            cp_type = cp.get("profile_type", cp.get("resource_type", ""))
            rows.append([s.name, cp.get(F_ID, ""), name, cp_type, attr_str])
    section("Context profiles ({})".format(len(rows)))
    if rows:
        table(CTX_PROFILE_HEADERS, rows)
    else:
        say("  No context profiles found.")
    exporter.stage("context_profiles", CTX_PROFILE_HEADERS, rows)


def act_ids_events(sessions, exporter, severity=None):
    """Show IDS/IPS detection events, newest first."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_ids_events(severity=severity),
        label="Fetching IDS events",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for ev in (result or []):
            rows.append([
                s.name,
                str(ev.get("event_time", "")),
                ev.get("severity", ""),
                ev.get("intrusion_service_signature_id",
                       ev.get("signature_id", "")),
                ev.get("src_ip", ""),
                ev.get("dst_ip", ""),
                str(ev.get("count", 1)),
            ])
    rows.sort(key=lambda r: r[1], reverse=True)
    section("IDS events ({})".format(len(rows)))
    if rows:
        colored = [r[:2] + [_sev_color(r[2])] + r[3:] for r in rows]
        table(IDS_EVENT_HEADERS, colored)
    else:
        say("  No IDS events found.")
    exporter.stage("ids_events", IDS_EVENT_HEADERS, rows)


def act_ids_profiles(sessions, exporter):
    """List IDS/IPS signature profiles."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_ids_profiles(),
        label="Fetching IDS profiles",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for prof in (result or []):
            overrides = prof.get("overridden_signatures") or []
            rows.append([
                s.name,
                prof.get(F_ID, ""),
                prof.get(F_DISPLAY_NAME, prof.get(F_ID, "")),
                str(len(overrides)),
            ])
    section("IDS profiles ({})".format(len(rows)))
    if rows:
        table(IDS_PROFILE_HEADERS, rows)
    else:
        say("  No IDS profiles found.")
    exporter.stage("ids_profiles", IDS_PROFILE_HEADERS, rows)
