"""Network topology: segments, edge transport nodes, BGP neighbours."""
from ..api import (
    F_ADMIN_STATE,
    F_CONNECTION_STATE,
    F_CONNECTIVITY_PATH,
    F_CONTROL_STATUS,
    F_DISPLAY_NAME,
    F_GATEWAY_ADDRESS,
    F_ID,
    F_NEIGHBOR_ADDRESS,
    F_NODE_DEPLOYMENT_STATUS,
    F_PREFIXES_RECEIVED,
    F_REMOTE_AS_NUM,
    F_SUBNETS,
    F_TIME_SINCE_ESTAB,
    F_VLAN_IDS,
)
from ..output import cBG, cBR, parallel_run, say, section, table

SEG_HEADERS  = ["manager", "name", "type", "vlan", "subnet", "connected_to"]
EDGE_HEADERS = ["manager", "name", "admin_state", "status"]
BGP_HEADERS  = ["manager", "tier0", "neighbor", "remote_as",
                "state", "uptime_s", "prefixes_rx"]


def _seg_type(seg):
    vlan = seg.get(F_VLAN_IDS, [])
    if vlan:
        return "vlan"
    return "overlay"


def _connected_to(seg):
    path = seg.get(F_CONNECTIVITY_PATH) or ""
    if not path:
        return "standalone"
    return path.rsplit("/", 1)[-1]


def _first_subnet(seg):
    for sub in (seg.get(F_SUBNETS) or []):
        addr = sub.get(F_GATEWAY_ADDRESS, "")
        if addr:
            return addr
    return ""


def act_segment_list(sessions, domain, exporter, contains=None, seg_type=None):
    """List overlay and VLAN-backed segments across all managers."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_segments(domain),
        label="Fetching segments",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for seg in (result or []):
            name = seg.get(F_DISPLAY_NAME, seg.get(F_ID, ""))
            if contains and contains.lower() not in name.lower():
                continue
            stype = _seg_type(seg)
            if seg_type and stype != seg_type:
                continue
            vlan = ", ".join(str(v) for v in (seg.get(F_VLAN_IDS) or []))
            rows.append([
                s.name,
                name,
                stype,
                vlan or "-",
                _first_subnet(seg) or "-",
                _connected_to(seg),
            ])
    section("Segments ({})".format(len(rows)))
    if rows:
        table(SEG_HEADERS, rows)
    else:
        say("  No segments found.")
    exporter.stage("segments", SEG_HEADERS, rows)


def act_edge_list(sessions, exporter):
    """List edge transport nodes and their deployment status."""
    fetched = parallel_run(
        sessions,
        lambda s: s.get_transport_nodes(node_type="EdgeNode"),
        label="Fetching edge nodes",
    )
    rows = []
    for s in sessions:
        result = fetched.get(s.name)
        if isinstance(result, Exception):
            say("  {} skipped: {}".format(s.name, result))
            continue
        for node in (result or []):
            nid = node.get(F_ID, "")
            name = node.get(F_DISPLAY_NAME, nid)
            admin = node.get(F_ADMIN_STATE, "")
            status_obj = s.get_transport_node_status(nid)
            deploy_status = status_obj.get(F_NODE_DEPLOYMENT_STATUS, "")
            ctrl = (status_obj.get(F_CONTROL_STATUS) or {}).get("status", "")
            status_str = deploy_status or ctrl or "UNKNOWN"
            admin_display = cBG(admin) if admin == "UP" else cBR(admin)
            rows.append([s.name, name, admin_display, status_str])
    section("Edge nodes ({})".format(len(rows)))
    if rows:
        table(EDGE_HEADERS, rows)
    else:
        say("  No edge nodes found.")
    plain_rows = [[r[0], r[1], r[2].strip("\x1b[0m").strip(), r[3]] for r in rows]
    exporter.stage("edges", EDGE_HEADERS, plain_rows)


def act_bgp(sessions, domain, exporter, tier0=None, down_only=False):
    """Show BGP neighbour state for all T0 gateways."""
    all_rows = []
    for s in sessions:
        t0s = s.get_tier0s(domain)
        for t0 in t0s:
            t0id = t0.get(F_ID, "")
            t0name = t0.get(F_DISPLAY_NAME, t0id)
            if tier0 and tier0.lower() not in t0name.lower():
                continue
            locale_services = s.get_locale_services(t0id, domain)
            if not locale_services:
                continue
            neighbors = []
            ls_fetched = parallel_run(
                locale_services,
                lambda ls, _s=s, _t=t0id: _s.get_bgp_neighbors(
                    _t, ls.get(F_ID, ""), domain),
                label="BGP on {}".format(t0name),
                key=lambda ls: ls.get(F_ID, ""),
            )
            for ls in locale_services:
                lsid = ls.get(F_ID, "")
                nbrs = ls_fetched.get(lsid)
                if isinstance(nbrs, Exception) or not nbrs:
                    continue
                neighbors.extend(nbrs)
            rows = []
            for nb in neighbors:
                state = nb.get(F_CONNECTION_STATE, "")
                if down_only and state == "ESTABLISHED":
                    continue
                state_display = cBG(state) if state == "ESTABLISHED" else cBR(state)
                rows.append([
                    s.name,
                    t0name,
                    nb.get(F_NEIGHBOR_ADDRESS, ""),
                    nb.get(F_REMOTE_AS_NUM, ""),
                    state_display,
                    str(nb.get(F_TIME_SINCE_ESTAB, 0)),
                    str(nb.get(F_PREFIXES_RECEIVED, 0)),
                ])
                all_rows.append(rows[-1])
            if rows:
                section("{} — BGP on {}".format(s.name, t0name))
                table(BGP_HEADERS, rows)
    if not all_rows:
        say("  No BGP neighbours found.")
    plain_rows = [r[:4] + [r[4].strip("\x1b[0m").strip()] + r[5:] for r in all_rows]
    exporter.stage("bgp", BGP_HEADERS, plain_rows)
