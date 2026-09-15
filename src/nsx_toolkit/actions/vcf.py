"""VCF SDDC Manager integration: discover NSX Local Managers across all SDDCs."""
import base64
import json
import os
import ssl
import urllib.request

from ..output import say, section, table

VCF_HEADERS = ["sddc", "nsx_host", "status"]


def _vcf_get(host, path, user, password, ca_bundle=None):
    url = "https://{}{}".format(host, path)
    creds = base64.b64encode("{}:{}".format(user, password).encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": "Basic {}".format(creds),
        "Accept": "application/json",
    })
    ctx = ssl.create_default_context()
    if ca_bundle:
        ctx.load_verify_locations(ca_bundle)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())


def act_vcf_import(vcf_host, vcf_user, vcf_password, out_path,
                   ca_bundle=None, enable_writes=False, exporter=None):
    """Discover NSX Local Managers from VCF SDDC Manager and merge into inventory."""
    say("Connecting to VCF SDDC Manager: {}".format(vcf_host))
    try:
        data = _vcf_get(vcf_host, "/v1/sddcs", vcf_user, vcf_password, ca_bundle)
    except Exception as exc:
        say("  Error reaching VCF SDDC Manager: {}".format(exc))
        return

    sddcs = data.get("elements", [])
    say("  Found {} SDDC(s).".format(len(sddcs)))

    existing = {}
    if os.path.exists(out_path):
        try:
            with open(out_path) as f:
                inv = json.load(f)
            for mgr in inv.get("managers", []):
                existing[mgr.get("host", "").lower()] = mgr
        except Exception as exc:
            say("  Warning: could not read {}: {}".format(out_path, exc))
            inv = {"managers": []}
    else:
        inv = {"managers": []}

    rows = []
    new_entries = []
    for sddc in sddcs:
        sddc_name = sddc.get("name", sddc.get("id", ""))
        nsx_mgr = sddc.get("nsxtManager") or {}
        nsx_host = nsx_mgr.get("hostname", "")
        if not nsx_host:
            say("  SDDC '{}' has no nsxtManager.hostname — skipped.".format(sddc_name))
            continue
        host_key = nsx_host.lower()
        if host_key in existing:
            rows.append([sddc_name, nsx_host, "already present"])
        else:
            entry = {
                "name": sddc_name,
                "role": "lm",
                "host": nsx_host,
                "port": 443,
                "scheme": "https",
                "verify_ssl": True,
            }
            new_entries.append(entry)
            rows.append([sddc_name, nsx_host, "new"])

    section("VCF NSX managers ({} discovered)".format(len(rows)))
    if rows:
        table(VCF_HEADERS, rows)
    else:
        say("  No NSX managers discovered.")

    if new_entries:
        if enable_writes:
            inv["managers"].extend(new_entries)
            with open(out_path, "w") as f:
                json.dump(inv, f, indent=2)
            say("  Written to {}.".format(out_path))
        else:
            say("  Dry run — {} new manager(s) would be added to {}. "
                "Pass --enable-writes to commit.".format(len(new_entries), out_path))
    else:
        say("  Inventory up to date — nothing to add.")

    if exporter is not None:
        exporter.stage("vcf_import", VCF_HEADERS, rows)
