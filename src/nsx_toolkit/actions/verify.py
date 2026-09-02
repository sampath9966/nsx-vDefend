"""Connectivity, authentication and API-base verification."""

from ..api import (
    DEFAULT_DOMAIN,
    F_RESULT_COUNT,
    F_RESULTS,
    PARAM_PAGE_SIZE,
    PATH_FABRIC_VMS,
    ROLE_GM,
    ROLE_LABEL,
    ROLE_LM,
    p_groups,
    p_sec_policies,
)
from ..errors import NsxError
from ..output import cBG, cBR, cD, err, hr, say, section


def act_verify(sessions, domain=DEFAULT_DOMAIN):
    all_ok = True
    for nsx in sessions:
        section("{}  [{}]  {}".format(
            nsx.name, ROLE_LABEL.get(nsx.role, "?"), nsx.base_url))
        say("  {} transport={} auth={} verify_ssl={}".format(
            cD("config:"), nsx.t.name, nsx.auth_mode, nsx.verify))
        if nsx.role == ROLE_GM:
            try:
                base = nsx.base(domain, verbose=True)
            except NsxError as e:
                err(str(e))
                all_ok = False
                continue
            checks = [("groups", p_groups(base, domain)),
                      ("security-policies", p_sec_policies(base, domain))]
        elif nsx.role == ROLE_LM:
            base = nsx.base(domain)
            checks = [("groups", p_groups(base, domain)),
                      ("security-policies", p_sec_policies(base, domain)),
                      ("VM inventory", PATH_FABRIC_VMS)]
        else:
            say("  {}".format(cBR("no role")))
            all_ok = False
            continue
        ver = nsx.version()
        if ver:
            say("  {} NSX {}.{}".format(cD("version:"), ver[0], ver[1]))
        for label, path in checks:
            try:
                d = nsx.get(path, params={PARAM_PAGE_SIZE: 1})
                n = d.get(F_RESULT_COUNT, len(d.get(F_RESULTS, [])))
                say("  {}    {:22s}  {} item(s)".format(cBG("OK"), label, n))
            except NsxError as e:
                say("  {}  {:22s}  {}".format(cBR("FAIL"), label, str(e)[:120]))
                all_ok = False
    hr()
    say("  {}.".format("All " + cBG("OK") if all_ok else cBR("Failures detected")))
    return all_ok
