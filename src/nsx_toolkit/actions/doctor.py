"""What does THIS NSX actually serve.

The toolkit degrades rather than fails in a dozen places: statistics may 404,
traceflow is Local-Manager-only, VM member counts are unmeasurable for some
group criteria, the Global Manager answers on one of two bases, Projects may
not exist. Every one of those is handled where it happens -- and until now
nothing told you *which* of them applied to your manager, so a missing feature
looked identical to a bug in the tool.

This probes each surface once and says, per manager, what works. It is the
first thing to run when a command behaves differently than the README says,
and the one output worth pasting into a bug report.

Every probe is a bounded read: a single GET with page_size 1 where possible,
and a HEAD-shaped existence check otherwise. Nothing here writes, and nothing
here injects a packet -- traceflow is probed by listing, never by running one.
"""

from ..api import (
    DEFAULT_DOMAIN,
    F_RESULT_COUNT,
    F_RESULTS,
    PARAM_PAGE_SIZE,
    PATH_FABRIC_VIFS,
    PATH_FABRIC_VMS,
    PATH_LOGICAL_PORTS,
    PATH_NODE_VERSION,
    PATH_TRACEFLOW,
    ROLE_GM,
    ROLE_LABEL,
    ROLE_LM,
    p_groups,
    p_policy_stats,
    p_projects,
    p_sec_policies,
    p_services,
    p_vm_group_assoc,
)
from ..errors import NsxError
from ..output import (
    cB,
    cBG,
    cBR,
    cBY,
    cC,
    cD,
    hr,
    say,
    section,
    table,
)
from ..sinks import make_finding

DOCTOR_HEADERS = ["manager", "role", "capability", "status", "detail"]

OK, MISSING, DEGRADED, NA = "ok", "missing", "degraded", "n/a"

# What each capability is FOR, so a missing one names the command it breaks
# rather than an endpoint nobody has heard of.
CAPABILITY_USES = {
    "policy base": "everything",
    "groups": "group list, impact, hygiene",
    "security policies": "rule list, hygiene, drift, trace",
    "services": "rule create --service, trace port matching",
    "rule statistics": "rule hygiene unused checks, rule baseline",
    "vm inventory": "tag commands, compliance, trace",
    "group associations": "impact, trace static evaluation",
    "vifs": "trace (source NIC resolution)",
    "logical ports": "trace (packet injection point)",
    "traceflow": "trace (the live half)",
    "projects": "--project scoping",
}


class Probe:
    """One capability check against one manager."""

    __slots__ = ("manager", "role", "capability", "status", "detail")

    def __init__(self, manager, role, capability, status, detail=""):
        self.manager = manager
        self.role = role
        self.capability = capability
        self.status = status
        self.detail = detail

    def row(self):
        return [self.manager, self.role, self.capability, self.status,
                self.detail]


def _count_of(payload):
    if not isinstance(payload, dict):
        return None
    if F_RESULT_COUNT in payload:
        return payload.get(F_RESULT_COUNT)
    results = payload.get(F_RESULTS)
    return len(results) if isinstance(results, list) else None


def _probe_get(nsx, path, params=None):
    """(status, detail) for one bounded GET."""
    try:
        payload = nsx.get(path, params=params or {PARAM_PAGE_SIZE: 1})
    except NsxError as e:
        text = str(e)
        if "HTTP 404" in text:
            return MISSING, "404 -- not served by this version"
        if "HTTP 403" in text:
            return DEGRADED, "403 -- the account cannot read it"
        return MISSING, text[-110:]
    count = _count_of(payload)
    return OK, "" if count is None else "{} item(s)".format(count)


def probe_manager(nsx, domain=DEFAULT_DOMAIN):
    """Every capability the toolkit depends on, checked once."""
    probes = []
    role = ROLE_LABEL.get(nsx.role, "?")

    def add(capability, status, detail=""):
        probes.append(Probe(nsx.name, role, capability, status, detail))

    version = None
    try:
        payload = nsx.get(PATH_NODE_VERSION)
        version = payload.get("node_version") or payload.get("product_version")
        add("version", OK, str(version or "unknown"))
    except NsxError as e:
        add("version", MISSING, str(e)[-110:])

    try:
        base = nsx.base(domain)
        add("policy base", OK, base)
    except NsxError as e:
        add("policy base", MISSING, str(e)[-110:])
        return probes, version

    add("groups", *_probe_get(nsx, p_groups(base, domain)))
    add("security policies", *_probe_get(nsx, p_sec_policies(base, domain)))
    add("services", *_probe_get(nsx, p_services(base)))
    add("group associations", *_probe_get(nsx, p_vm_group_assoc(base),
                                          params={"vm_external_id": "probe"}))

    # Statistics hang off a real policy, so probe one rather than guessing an
    # id -- a 404 for "no such policy" would look like "not supported".
    stats_status, stats_detail = _probe_statistics(nsx, base, domain)
    add("rule statistics", stats_status, stats_detail)

    if nsx.role == ROLE_LM:
        add("vm inventory", *_probe_get(nsx, PATH_FABRIC_VMS))
        add("vifs", *_probe_get(nsx, PATH_FABRIC_VIFS))
        add("logical ports", *_probe_get(nsx, PATH_LOGICAL_PORTS))
        add("traceflow", *_probe_get(nsx, PATH_TRACEFLOW))
    else:
        for capability in ("vm inventory", "vifs", "logical ports",
                           "traceflow"):
            add(capability, NA, "Local Manager only")

    add("projects", *_probe_get(nsx, p_projects(nsx.org)))
    return probes, version


def _probe_statistics(nsx, base, domain):
    """Statistics need a policy to hang off, so find one first."""
    try:
        policies = nsx.get(p_sec_policies(base, domain),
                           params={PARAM_PAGE_SIZE: 1}).get(F_RESULTS) or []
    except NsxError as e:
        return MISSING, "could not list policies: {}".format(str(e)[-80:])
    if not policies:
        return NA, "no policy to measure against"
    pid = policies[0].get("id", "?")
    status, detail = _probe_get(nsx, p_policy_stats(base, domain, pid),
                                params={})
    if status == MISSING:
        return status, (detail + " -- hit-count checks will be skipped")
    return status, detail


def _probe_colour(status):
    return {OK: cBG, MISSING: cBR, DEGRADED: cBY, NA: cD}.get(status, cD)


def act_doctor(sessions, domain, exporter):
    """Returns (probes, healthy). Prints a per-manager capability report."""
    section("NSX CAPABILITY REPORT")
    say("  {}".format(cD(
        "What this NSX actually serves. Every probe is a bounded read -- "
        "nothing is written,")))
    say("  {}".format(cD(
        "and traceflow is checked by listing, never by injecting a packet.")))

    all_probes = []
    for nsx in sessions:
        hr()
        say("  {}  {}  {}".format(cB(nsx.name),
                                  cD(ROLE_LABEL.get(nsx.role, "?")),
                                  cD(nsx.base_url)))
        if nsx.project:
            say("  {}".format(cD("scoped to project {}".format(nsx.project))))
        probes, _version = probe_manager(nsx, domain)
        all_probes.extend(probes)
        rows = []
        for probe in probes:
            use = CAPABILITY_USES.get(probe.capability, "")
            rows.append([
                probe.capability,
                _probe_colour(probe.status)(probe.status),
                probe.detail[:52],
                cD(use) if probe.status in (MISSING, DEGRADED) else ""])
        table(["Capability", "Status", "Detail", "Affects"], rows, indent=4)

    hr()
    missing = [p for p in all_probes if p.status == MISSING]
    degraded = [p for p in all_probes if p.status == DEGRADED]
    exporter.stage("doctor", DOCTOR_HEADERS, [p.row() for p in all_probes])
    exporter.stage_findings("nsx_capabilities", [
        make_finding(probe.capability, probe.status,
                     "{} on {}".format(probe.capability, probe.manager),
                     where=probe.manager,
                     passed=probe.status in (OK, NA),
                     detail="{}  affects: {}".format(
                         probe.detail,
                         CAPABILITY_USES.get(probe.capability, "")))
        for probe in all_probes])

    if not missing and not degraded:
        say("  {} every surface the toolkit uses is available.".format(
            cBG("Healthy:")))
        return all_probes, True

    if missing:
        say("  {} {} capability(ies) are not served here:".format(
            cBR("Missing:"), len(missing)))
        for probe in missing:
            say("    {} / {}   {}".format(
                cC(probe.manager), cB(probe.capability),
                cD(CAPABILITY_USES.get(probe.capability, ""))))
    if degraded:
        say("  {} {} capability(ies) exist but this account cannot read "
            "them:".format(cBY("Degraded:"), len(degraded)))
        for probe in degraded:
            say("    {} / {}".format(cC(probe.manager), cB(probe.capability)))
    say("\n  {}".format(cD(
        "A missing capability is not a bug in the toolkit -- the commands "
        "that use it")))
    say("  {}".format(cD(
        "degrade and say so. This report is the thing to paste into a "
        "question about it.")))
    return all_probes, False


def unhealthy_count(probes):
    return sum(1 for p in probes if p.status in (MISSING, DEGRADED))


def gm_only_estate(sessions):
    """True when nothing that needs a Local Manager can possibly work."""
    return bool(sessions) and all(s.role == ROLE_GM for s in sessions)
