"""An in-process fake NSX manager.

Deliberately a real HTTP server rather than a monkeypatched client: the tests
then exercise the actual transport, cursor pagination, retry loop and session
authentication instead of a stub that agrees with whatever the code does.

Two personalities:
  * Local Manager  -- serves /policy/api/v1/infra, holds VM inventory and tags
  * Global Manager -- serves /global-manager/api/v1/global-infra, no VMs

Rules authored on the GM are realized read-only onto every LM beneath it, and
keep their '/global-infra/...' path when read back from an LM. The fake
reproduces that, because it is the exact behaviour the reverse-lookup dedup
depends on.

Two behaviours exist here because the toolkit's safety properties depend on
them and a stub that just says yes would prove nothing:

  * Traceflow is a Manager API served only by a Local Manager, it is
    asynchronous, and the object it creates has to be deleted afterwards. The
    fake serves it on the LM personality only, hands out a configurable
    sequence of operation states so the poll loop is really exercised, and
    records deletes so cleanup can be asserted.
  * Policy writes enforce optimistic concurrency: a PUT carrying a `_revision`
    that does not match the stored one is answered 412, exactly as NSX does.
    That check is the whole safety mechanism behind authoring.
"""

import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LM_BASE = "/policy/api/v1/infra"
GM_BASE = "/global-manager/api/v1/global-infra"


class FakeState:
    """Mutable content for one fake manager."""

    def __init__(self, role="lm", name="fake", version="4.1.2.0"):
        self.role = role
        self.name = name
        self.version = version
        self.base = GM_BASE if role == "gm" else LM_BASE
        self.vms = []
        self.groups = []
        self.group_members = {}      # group id -> [vm dicts]
        self.policies = []
        self.rules = {}              # policy id -> [rule dicts]
        self.associations = {}       # vm external_id -> [association dicts]
        self.stats = {}              # policy id -> {rule id: stats dict}
        self.stats_unsupported = False   # 404 the statistics route
        self.services = []           # policy service definitions
        self.projects = []           # NSX Projects (multi-tenancy)
        self.projects_unsupported = False
        self.vifs = {}               # owner vm external_id -> [vif dicts]
        self.logical_ports = {}      # attachment id -> logical port dict
        self.traceflows = {}         # traceflow id -> request body
        self.traceflow_deleted = []  # ids the toolkit cleaned up
        self.traceflow_observations = []
        self.traceflow_states = ["FINISHED"]   # one per poll; last repeats
        self.traceflow_unsupported = False     # 404 the traceflow route
        self.traceflow_polls = 0
        self.request_log = []
        self.fail_times = {}         # path substring -> remaining 503s
        self.require_auth = True
        self.lock = threading.Lock()
        self.alarms = []
        self.certs = []
        self.capacity_data = []
        self.segments = []
        self.tier0s = []
        self.locale_services = {}    # {t0id: [ls, ...]}
        self.bgp_neighbors = {}      # {(t0id, lsid): [neighbor, ...]}
        self.transport_nodes = []
        self.tn_status = {}          # {tnid: status_dict}
        self.gw_policies = []
        self.gw_rules = {}           # policy id -> [rule dicts]
        self.context_profiles = []
        self.ids_profiles = []
        self.ids_events = []

    # --- content helpers ---------------------------------------------------
    def add_vm(self, name, external_id=None, tags=None, power="VM_RUNNING"):
        vm = {"display_name": name,
              "external_id": external_id or "ext-{}".format(name),
              "power_state": power,
              "tags": [{"scope": s, "tag": t} for s, t in (tags or [])]}
        self.vms.append(vm)
        return vm

    def add_group(self, gid, display_name=None, origin="LM", expression=None,
                  members=()):
        prefix = "/global-infra" if origin == "GM" else "/infra"
        path = "{}/domains/default/groups/{}".format(prefix, gid)
        group = {"id": gid,
                 "display_name": display_name or gid,
                 "path": path,
                 "expression": expression or []}
        group.update(_meta(path))
        self.groups.append(group)
        self.group_members[gid] = list(members)
        return group

    def add_vif(self, vm, mac="00:50:56:aa:bb:cc", ips=("10.1.1.10",),
                device_name="Network adapter 1", attachment_id=None,
                lport_id=None):
        """A VM's virtual NIC, plus the logical port it is attached to.

        Traceflow needs a logical port, never a VM, so VM -> VIF -> logical
        port is the resolution chain the toolkit has to walk. A VM with two of
        these is genuinely ambiguous, which is why the fake lets a test add
        more than one.
        """
        ext = vm["external_id"]
        index = len(self.vifs.get(ext, []))
        attachment_id = attachment_id or "att-{}-{}".format(ext, index)
        vif = {"owner_vm_id": ext,
               "device_key": "4000{}".format(index),
               "device_name": device_name,
               "mac_address": mac,
               "lport_attachment_id": attachment_id,
               "ip_address_info": [{"ip_addresses": list(ips)}]}
        self.vifs.setdefault(ext, []).append(vif)
        if lport_id is not False:
            self.logical_ports[attachment_id] = {
                "id": lport_id or "lp-{}-{}".format(ext, index),
                "display_name": "{}-nic{}".format(vm["display_name"], index),
                "attachment": {"id": attachment_id}}
        return vif

    def add_project(self, pid, display_name=None):
        """An NSX Project. Its infra tree is served as an alternate base, so a
        --project run really does see a different object set."""
        project = {"id": pid, "display_name": display_name or pid,
                   "path": "/orgs/default/projects/{}".format(pid)}
        self.projects.append(project)
        return project

    def add_service(self, sid, protocol="TCP", ports=("443",),
                    display_name=None, entries=None):
        """A service definition. `entries` overrides the L4 shape, so a test
        can serve an ICMP or ALG service the port matcher cannot decide."""
        path = "/infra/services/{}".format(sid)
        service = {"id": sid,
                   "display_name": display_name or sid,
                   "path": path,
                   "service_entries": entries if entries is not None else [
                       {"resource_type": "L4PortSetServiceEntry",
                        "l4_protocol": protocol,
                        "destination_ports": list(ports)}]}
        service.update(_meta(path))
        self.services.append(service)
        return service

    def set_traceflow_result(self, observations, states=("FINISHED",)):
        """What the next traceflow reports, and how many polls it takes."""
        self.traceflow_observations = list(observations)
        self.traceflow_states = list(states)

    def associate(self, vm, group):
        self.associations.setdefault(vm["external_id"], []).append({
            "target_id": group["id"],
            "target_display_name": group["display_name"],
            "target_type": "Group",
            "path": group["path"],
            "is_valid": True})

    def add_policy(self, pid, display_name=None, origin="LM"):
        prefix = "/global-infra" if origin == "GM" else "/infra"
        path = "{}/domains/default/security-policies/{}".format(prefix, pid)
        pol = {"id": pid,
               "display_name": display_name or pid,
               "path": path}
        pol.update(_meta(path))
        self.policies.append(pol)
        self.rules.setdefault(pid, [])
        return pol

    def add_rule(self, pid, rid, source_groups=(), destination_groups=(),
                 scope=(), action="ALLOW", origin="LM", display_name=None,
                 services=("ANY",), disabled=False, logged=True,
                 sequence_number=None, direction="IN_OUT", rule_id=None):
        prefix = "/global-infra" if origin == "GM" else "/infra"
        existing = self.rules.setdefault(pid, [])
        rule = {"id": rid,
                "display_name": display_name or rid,
                "path": "{}/domains/default/security-policies/{}/rules/{}".format(
                    prefix, pid, rid),
                "source_groups": list(source_groups) or ["ANY"],
                "destination_groups": list(destination_groups) or ["ANY"],
                "scope": list(scope) or ["ANY"],
                "services": list(services),
                "action": action,
                "disabled": bool(disabled),
                "logged": bool(logged),
                "direction": direction,
                "sequence_number": (sequence_number if sequence_number
                                    is not None else (len(existing) + 1) * 10),
                # The realized numeric DFW id. A traceflow observation names
                # the rule that dropped the packet by this and nothing else.
                "rule_id": (rule_id if rule_id is not None
                            else _next_rule_id())}
        rule.update(_meta(rule["path"]))
        existing.append(rule)
        return rule

    def touch(self, kind, oid, user="someone-else", pid=None, **changes):
        """Mutate an object the way a person editing in the NSX UI would.

        Applies the changes, bumps _revision and updates the modified
        timestamp and user -- so drift has something real to detect, and the
        report has someone real to attribute it to.
        """
        target = None
        if kind == "group":
            target = next((g for g in self.groups if g["id"] == oid), None)
        elif kind == "policy":
            target = next((p for p in self.policies if p["id"] == oid), None)
        elif kind == "rule":
            for policy_id, rules in self.rules.items():
                if pid and policy_id != pid:
                    continue
                target = next((r for r in rules if r["id"] == oid), None)
                if target:
                    break
        if target is None:
            raise KeyError("no such {}: {}".format(kind, oid))
        target.update(changes)
        target["_revision"] = target.get("_revision", 0) + 1
        target["_last_modified_time"] = target.get(
            "_last_modified_time", 1700000000000) + 60000
        target["_last_modified_user"] = user
        return target

    def add_alarm(self, aid, severity="HIGH", summary="test alarm",
                  status="OPEN", node_id="mgr-01", event_count=1,
                  first_reported=1700000000000, last_reported=1700000000000):
        alarm = {
            "id": aid, "severity": severity,
            "feature_display_name": summary, "status": status,
            "node_resource_display_name": node_id,
            "event_count": event_count,
            "first_reported_time": first_reported,
            "last_reported_time": last_reported,
        }
        self.alarms.append(alarm)
        return alarm

    def add_cert(self, cid, display_name=None, not_after_days=365, used_by=None):
        import time as _time
        not_after_ms = int((_time.time() + not_after_days * 86400) * 1000)
        cert = {
            "id": cid,
            "display_name": display_name or cid,
            "not_after": not_after_ms,
            "used_by": [{"href": "/api/v1/node/services/{}".format(h)}
                        for h in (used_by or [])],
        }
        self.certs.append(cert)
        return cert

    def set_capacity(self, usage_list):
        self.capacity_data = list(usage_list)

    def add_segment(self, sid, display_name=None, seg_type="ROUTED",
                    gateway="10.0.0.1/24", connectivity_path=None, vlan_ids=None):
        seg = {"id": sid,
               "display_name": display_name or sid,
               "type": seg_type,
               "subnets": [{"gateway_address": gateway}],
               "connectivity_path": connectivity_path,
               "vlan_ids": vlan_ids or []}
        self.segments.append(seg)
        return seg

    def add_tier0(self, t0id, display_name=None):
        t0 = {"id": t0id, "display_name": display_name or t0id}
        self.tier0s.append(t0)
        self.locale_services.setdefault(t0id, [])
        return t0

    def add_locale_service(self, t0id, lsid, display_name=None):
        ls = {"id": lsid, "display_name": display_name or lsid}
        self.locale_services.setdefault(t0id, []).append(ls)
        return ls

    def add_bgp_neighbor(self, t0id, lsid, addr, remote_as="65001",
                         state="ESTABLISHED", uptime=0, prefixes=0):
        n = {"neighbor_address": addr,
             "remote_as_num": remote_as,
             "connection_state": state,
             "time_since_established": uptime,
             "prefixes_received": prefixes}
        self.bgp_neighbors.setdefault((t0id, lsid), []).append(n)
        return n

    def add_edge_node(self, eid, display_name=None, admin_state="UP",
                      status="NODE_READY"):
        node = {"id": eid,
                "display_name": display_name or eid,
                "node_type": "EdgeNode",
                "admin_state": admin_state}
        self.transport_nodes.append(node)
        self.tn_status[eid] = {
            "host_node_deployment_status": status,
            "control_connection_status": {"status": "UP"}}
        return node

    def add_gw_policy(self, pid, display_name=None, category="LocalGatewayRules",
                      seq=10, scope=None):
        pol = {"id": pid, "display_name": display_name or pid,
               "category": category, "sequence_number": seq,
               "scope": scope or ["ANY"],
               "path": "/infra/gateway-policies/{}".format(pid)}
        pol.update(_meta(pol["path"]))
        self.gw_policies.append(pol)
        self.gw_rules.setdefault(pid, [])
        return pol

    def add_gw_rule(self, pid, rid, display_name=None, action="ALLOW",
                    src=None, dst=None, services=None, disabled=False, logged=True):
        rule = {"id": rid, "display_name": display_name or rid,
                "action": action,
                "sequence_number": len(self.gw_rules.get(pid, [])) * 10 + 10,
                "source_groups": src or ["ANY"],
                "destination_groups": dst or ["ANY"],
                "services": services or ["ANY"],
                "disabled": disabled, "logged": logged}
        self.gw_rules.setdefault(pid, []).append(rule)
        return rule

    def add_context_profile(self, cpid, display_name=None, profile_type="AppID",
                            attrs=None):
        cp = {"id": cpid, "display_name": display_name or cpid,
              "profile_type": profile_type,
              "attributes": attrs or [{"key": "APP_ID", "value": "SSL"}]}
        self.context_profiles.append(cp)
        return cp

    def add_ids_profile(self, iid, display_name=None, overrides=None):
        prof = {"id": iid, "display_name": display_name or iid,
                "overridden_signatures": overrides or []}
        self.ids_profiles.append(prof)
        return prof

    def add_ids_event(self, severity="HIGH", sig_id="1001", src="10.0.0.1",
                      dst="10.0.0.2", count=1, event_time="2026-09-01T00:00:00Z"):
        ev = {"severity": severity.upper(),
              "intrusion_service_signature_id": sig_id,
              "src_ip": src, "dst_ip": dst,
              "count": count, "event_time": event_time}
        self.ids_events.append(ev)
        return ev

    def set_hit_count(self, pid, rid, hits, last_update=1700000000000):
        """Drive the hit-count and baseline checks."""
        self.stats.setdefault(pid, {})[rid] = {
            "hit_count": hits, "byte_count": hits * 100,
            "packet_count": hits * 2, "last_update_timestamp": last_update}

    def fail_next(self, path_fragment, times=1):
        """Return HTTP 503 for the next `times` requests matching a path."""
        self.fail_times[path_fragment] = times

    def count(self, fragment):
        return sum(1 for entry in self.request_log if fragment in entry)


_META_COUNTER = [0]
_RULE_ID_COUNTER = [4000]


def _next_rule_id():
    _RULE_ID_COUNTER[0] += 1
    return _RULE_ID_COUNTER[0]


def obs_forwarded(node="esx-01", component="LR", sequence=0):
    return {"resource_type": "TraceflowObservationForwarded",
            "component_type": component, "component_name": component + "-1",
            "transport_node_name": node, "sequence_no": sequence}


def obs_dropped(acl_rule_id=None, node="esx-01", component="FIREWALL",
                reason="FIREWALL_RULE", sequence=1):
    obs = {"resource_type": "TraceflowObservationDropped",
           "component_type": component, "component_name": component,
           "transport_node_name": node, "reason": reason,
           "sequence_no": sequence}
    if acl_rule_id is not None:
        obs["acl_rule_id"] = acl_rule_id
    return obs


def obs_delivered(node="esx-02", sequence=2):
    return {"resource_type": "TraceflowObservationDelivered",
            "component_type": "VNIC", "component_name": "vnic",
            "transport_node_name": node, "sequence_no": sequence}


def _meta(path, user="admin", revision=0, created=1700000000000,
          modified=1700000000000):
    """Realization and audit fields NSX attaches to every policy object.

    These change on every write -- and some on every read -- so the snapshot
    normaliser must strip them. They exist in the fake precisely so that
    stripping is tested rather than assumed.
    """
    _META_COUNTER[0] += 1
    unique = "{:08x}-0000-0000-0000-{:012x}".format(
        _META_COUNTER[0], _META_COUNTER[0])
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    return {
        "_revision": revision,
        "_create_time": created,
        "_create_user": user,
        "_last_modified_time": modified,
        "_last_modified_user": user,
        "_system_owned": False,
        "_protection": "NOT_PROTECTED",
        "realization_id": unique,
        "unique_id": unique,
        "parent_path": parent,
        "relative_path": path.rsplit("/", 1)[-1],
        "marked_for_delete": False,
        "overridden": False,
    }


def _page(items, query):
    """NSX-style opaque cursor pagination."""
    try:
        size = int(query.get("page_size", ["1000"])[0])
    except (TypeError, ValueError):
        size = 1000
    try:
        start = int(query.get("cursor", ["0"])[0])
    except (TypeError, ValueError):
        start = 0
    chunk = items[start:start + size]
    body = {"results": chunk, "result_count": len(items)}
    if start + size < len(items):
        body["cursor"] = str(start + size)
    return body


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self):
        return self.server.state

    def log_message(self, *_args):
        pass  # keep the test output readable

    # --- plumbing ----------------------------------------------------------
    def _send(self, code, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authed(self):
        if not self.state.require_auth:
            return True
        if self.headers.get("Authorization", "").startswith("Basic "):
            return True
        cookie = self.headers.get("Cookie") or ""
        return "JSESSIONID=" in cookie

    def _maybe_fail(self, path):
        with self.state.lock:
            for fragment, remaining in list(self.state.fail_times.items()):
                if fragment in path and remaining > 0:
                    self.state.fail_times[fragment] = remaining - 1
                    return True
        return False

    def _find(self, kind, oid, pid=None):
        """One stored object by kind and id, or None."""
        st = self.state
        if kind == "group":
            return next((g for g in st.groups if g["id"] == oid), None)
        if kind == "policy":
            return next((p for p in st.policies if p["id"] == oid), None)
        if kind == "rule":
            for policy_id, rules in st.rules.items():
                if pid and policy_id != pid:
                    continue
                hit = next((r for r in rules if r["id"] == oid), None)
                if hit:
                    return hit
        return None

    def _policy_target(self, rel):
        """(kind, id, policy id) for a writable policy object path."""
        parts = [p for p in rel.split("/") if p]
        if len(parts) == 4 and parts[0] == "domains" and parts[2] == "groups":
            return "group", parts[3], None
        if len(parts) >= 4 and parts[0] == "domains" and \
                parts[2] == "security-policies":
            if len(parts) == 4:
                return "policy", parts[3], None
            if len(parts) == 6 and parts[4] == "rules":
                return "rule", parts[5], parts[3]
        return None, None, None

    # --- routing -----------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        st = self.state
        with st.lock:
            st.request_log.append("POST " + path)

        if path == "/api/session/create":
            return self._send(200, {}, {
                "Set-Cookie": "JSESSIONID=fake-session-id; Path=/; HttpOnly",
                "X-XSRF-TOKEN": "fake-xsrf-token"})

        if not self._authed():
            return self._send(403, {"error_message": "not authenticated"})
        if self._maybe_fail(path):
            return self._send(503, {"error_message": "busy"})

        if path == "/api/v1/traceflow":
            if st.role == "gm" or st.traceflow_unsupported:
                # The Global Manager serves no traceflow API at all. That is
                # the behaviour `nsxctl trace` has to detect and explain
                # rather than surface as an obscure 404.
                return self._send(404, {"error_message": "no traceflow here"})
            body = json.loads(raw.decode("utf-8")) if raw else {}
            with st.lock:
                tid = "tf-{}".format(len(st.traceflows) + 1)
                st.traceflows[tid] = body
                st.traceflow_polls = 0
                # Create reports the first configured state; each poll advances
                # one. A trace that is already FINISHED on create is real NSX
                # behaviour for a fast path, and a test that wants the poll
                # loop exercised configures IN_PROGRESS ahead of it.
                state = st.traceflow_states[0]
            return self._send(201, {"id": tid, "operation_state": state})

        if path == "/api/v1/fabric/virtual-machines" and \
                query.get("action") == ["update_tags"]:
            body = json.loads(raw.decode("utf-8")) if raw else {}
            ext = body.get("external_id")
            with self.state.lock:
                for vm in self.state.vms:
                    if vm["external_id"] == ext:
                        vm["tags"] = list(body.get("tags") or [])
                        return self._send(200, {})
            return self._send(404, {"error_message": "no such VM"})

        return self._send(404, {"error_message": "unhandled POST " + path})

    def do_PUT(self):
        """Create or replace a policy object, enforcing optimistic concurrency.

        NSX answers 412 when the `_revision` in the body does not match the
        stored one. That is what stops two operators silently clobbering each
        other, so the fake enforces it rather than accepting any write.
        """
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        st = self.state
        with st.lock:
            st.request_log.append("PUT " + path)
        if not self._authed():
            return self._send(403, {"error_message": "not authenticated"})
        if self._maybe_fail(path):
            return self._send(503, {"error_message": "busy"})
        if not path.startswith(st.base):
            return self._send(404, {"error_message": "unknown base"})

        kind, oid, pid = self._policy_target(path[len(st.base):])
        if not kind:
            return self._send(404, {"error_message": "unhandled PUT " + path})
        body = json.loads(raw.decode("utf-8")) if raw else {}
        with st.lock:
            existing = self._find(kind, oid, pid=pid)
            if existing is not None:
                sent = body.get("_revision")
                if sent is not None and sent != existing.get("_revision", 0):
                    return self._send(412, {
                        "error_message": "stale revision",
                        "error_code": 500127})
                existing.update(body)
                existing["_revision"] = existing.get("_revision", 0) + 1
                existing["_last_modified_user"] = "toolkit"
                return self._send(200, existing)

            created = dict(body)
            created["id"] = oid
            created["path"] = "{}/domains/default/{}".format(
                "/infra",
                "groups/{}".format(oid) if kind == "group"
                else ("security-policies/{}".format(oid) if kind == "policy"
                      else "security-policies/{}/rules/{}".format(pid, oid)))
            created.update(_meta(created["path"]))
            if kind == "group":
                st.groups.append(created)
                st.group_members.setdefault(oid, [])
            elif kind == "policy":
                st.policies.append(created)
                st.rules.setdefault(oid, [])
            else:
                created.setdefault("rule_id", _next_rule_id())
                st.rules.setdefault(pid, []).append(created)
            return self._send(200, created)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        st = self.state
        with st.lock:
            st.request_log.append("DELETE " + path)
        if not self._authed():
            return self._send(403, {"error_message": "not authenticated"})
        if self._maybe_fail(path):
            return self._send(503, {"error_message": "busy"})

        if path.startswith("/api/v1/traceflow/"):
            tid = path[len("/api/v1/traceflow/"):]
            with st.lock:
                st.traceflows.pop(tid, None)
                st.traceflow_deleted.append(tid)
            return self._send(200, {})

        if not path.startswith(st.base):
            return self._send(404, {"error_message": "unknown base"})
        kind, oid, pid = self._policy_target(path[len(st.base):])
        with st.lock:
            target = self._find(kind, oid, pid=pid) if kind else None
            if target is None:
                return self._send(404, {"error_message": "no such object"})
            if kind == "group":
                st.groups.remove(target)
                st.group_members.pop(oid, None)
            elif kind == "policy":
                st.policies.remove(target)
                st.rules.pop(oid, None)
            else:
                st.rules[pid].remove(target)
        return self._send(200, {})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        with self.state.lock:
            self.state.request_log.append("GET " + path)

        if not self._authed():
            return self._send(403, {"error_message": "not authenticated"})
        if self._maybe_fail(path):
            return self._send(503, {"error_message": "busy"})

        st = self.state

        if path == "/api/v1/node/version":
            return self._send(200, {"node_version": st.version})

        if path == "/api/v1/fabric/vifs":
            if st.role == "gm":
                return self._send(404, {"error_message": "GM holds no VIFs"})
            owner = (query.get("owner_vm_id") or [""])[0]
            vifs = (st.vifs.get(owner, []) if owner
                    else [v for group in st.vifs.values() for v in group])
            return self._send(200, _page(vifs, query))

        if path == "/api/v1/logical-ports":
            if st.role == "gm":
                return self._send(404, {"error_message": "GM holds no ports"})
            attachment = (query.get("attachment_id") or [""])[0]
            ports = ([st.logical_ports[attachment]]
                     if attachment in st.logical_ports
                     else ([] if attachment
                           else list(st.logical_ports.values())))
            return self._send(200, _page(ports, query))

        if path == "/api/v1/traceflow":
            # Listing, not running. `nsxctl doctor` probes the surface this
            # way precisely so a capability check never injects a packet.
            if st.role == "gm" or st.traceflow_unsupported:
                return self._send(404, {"error_message": "no traceflow here"})
            return self._send(200, _page(
                [{"id": tid} for tid in sorted(st.traceflows)], query))

        if path.startswith("/api/v1/traceflow/"):
            if st.role == "gm" or st.traceflow_unsupported:
                return self._send(404, {"error_message": "no traceflow here"})
            rest = path[len("/api/v1/traceflow/"):]
            tid, _, tail = rest.partition("/")
            if tid not in st.traceflows:
                return self._send(404, {"error_message": "no such traceflow"})
            if tail == "observations":
                return self._send(200, _page(st.traceflow_observations, query))
            if tail:
                return self._send(404, {"error_message": "unhandled " + path})
            with st.lock:
                st.traceflow_polls += 1
                index = min(st.traceflow_polls,
                            len(st.traceflow_states) - 1)
                state = st.traceflow_states[index]
            return self._send(200, {"id": tid, "operation_state": state})

        if path.startswith("/policy/api/v1/orgs/") and \
                path.endswith("/projects"):
            # Projects hang off the org, not off any infra base, which is why
            # this is matched before the base check below.
            if st.projects_unsupported:
                return self._send(404, {"error_message": "no project API"})
            return self._send(200, _page(st.projects, query))

        if path == "/api/v1/fabric/virtual-machines":
            if st.role == "gm":
                return self._send(404, {"error_message": "GM holds no VMs"})
            vms = st.vms
            wanted = query.get("display_name")
            if wanted:
                vms = [v for v in vms if v["display_name"] == wanted[0]]
            return self._send(200, _page(vms, query))

        if path == "/api/v1/alarms":
            status_f = (query.get("status") or [None])[0]
            sev_f    = (query.get("severity") or [None])[0]
            alarms = st.alarms
            if status_f:
                alarms = [a for a in alarms if a.get("status") == status_f]
            if sev_f:
                alarms = [a for a in alarms if a.get("severity") == sev_f.upper()]
            return self._send(200, _page(alarms, query))

        if path == "/api/v1/trust-management/certificates":
            return self._send(200, _page(st.certs, query))

        if path == "/api/v1/capacity/usage":
            return self._send(200, {"capacity_usage_data": st.capacity_data})

        if path == "/api/v1/transport-nodes":
            node_type = (query.get("node_type") or [None])[0]
            nodes = st.transport_nodes
            if node_type:
                nodes = [n for n in nodes if n.get("node_type") == node_type]
            return self._send(200, _page(nodes, query))

        m = re.match(r"^/api/v1/transport-nodes/([^/]+)/status$", path)
        if m:
            return self._send(200, st.tn_status.get(m.group(1), {}))

        # Anything below is base-relative; a wrong base must 404 so the GM
        # base probe in Nsx.base() is genuinely exercised.
        if not path.startswith(st.base):
            return self._send(404, {"error_message": "unknown base"})
        rel = path[len(st.base):]

        if rel == "/virtual-machine-group-associations":
            ext = (query.get("vm_external_id") or [""])[0]
            return self._send(200, _page(st.associations.get(ext, []), query))

        if rel == "/domains":
            return self._send(200, _page([{"id": "default"}], query))

        if rel == "/services":
            return self._send(200, _page(st.services, query))

        if rel == "/segments":
            return self._send(200, _page(st.segments, query))

        if rel == "/tier-0s":
            return self._send(200, _page(st.tier0s, query))

        m = re.match(r"^/tier-0s/([^/]+)/locale-services$", rel)
        if m:
            t0id = m.group(1)
            return self._send(200, _page(st.locale_services.get(t0id, []), query))

        m = re.match(
            r"^/tier-0s/([^/]+)/locale-services/([^/]+)/bgp/neighbors/status$", rel)
        if m:
            t0id, lsid = m.group(1), m.group(2)
            neighbors = st.bgp_neighbors.get((t0id, lsid), [])
            return self._send(200, {"results": neighbors})

        # gateway-policies
        m = re.match(r"^/domains/([^/]+)/gateway-policies$", rel)
        if m:
            return self._send(200, _page(st.gw_policies, query))

        m = re.match(r"^/domains/([^/]+)/gateway-policies/([^/]+)/rules$", rel)
        if m:
            pid = m.group(2)
            return self._send(200, _page(st.gw_rules.get(pid, []), query))

        # context-profiles
        if rel == "/context-profiles":
            return self._send(200, _page(st.context_profiles, query))

        # IDS/IPS
        if rel == "/intrusion-services/profiles":
            return self._send(200, _page(st.ids_profiles, query))

        if rel == "/intrusion-services/ids-events":
            sev = (query.get("severity") or [None])[0]
            evs = st.ids_events
            if sev:
                evs = [e for e in evs if e.get("severity") == sev.upper()]
            return self._send(200, _page(evs, query))

        parts = [p for p in rel.split("/") if p]
        # domains/{domain}/groups[/{gid}[/members/virtual-machines]]
        if len(parts) >= 3 and parts[0] == "domains" and parts[2] == "groups":
            if len(parts) == 3:
                return self._send(200, _page(st.groups, query))
            if len(parts) == 4:
                found = self._find("group", parts[3])
                if found is None:
                    return self._send(404, {"error_message": "no such group"})
                return self._send(200, found)
            if len(parts) == 6 and parts[4] == "members" and \
                    parts[5] == "virtual-machines":
                return self._send(
                    200, _page(st.group_members.get(parts[3], []), query))

        # domains/{domain}/security-policies[/{pid}/rules|statistics]
        if len(parts) >= 3 and parts[0] == "domains" and \
                parts[2] == "security-policies":
            if len(parts) == 3:
                return self._send(200, _page(st.policies, query))
            if len(parts) == 4:
                found = self._find("policy", parts[3])
                if found is None:
                    return self._send(404, {"error_message": "no such policy"})
                return self._send(200, found)
            if len(parts) == 5 and parts[4] == "rules":
                return self._send(200, _page(st.rules.get(parts[3], []), query))
            if len(parts) == 6 and parts[4] == "rules":
                found = self._find("rule", parts[5], pid=parts[3])
                if found is None:
                    return self._send(404, {"error_message": "no such rule"})
                return self._send(200, found)
            if len(parts) == 5 and parts[4] == "statistics":
                if st.stats_unsupported:
                    return self._send(
                        404, {"error_message": "statistics not supported"})
                pid = parts[3]
                entries = []
                for rule in st.rules.get(pid, []):
                    counters = st.stats.get(pid, {}).get(rule["id"])
                    if counters is None:
                        continue
                    entry = dict(counters)
                    entry["rule_path"] = rule["path"]
                    entries.append(entry)
                return self._send(200, {"results": [
                    {"statistics": entries,
                     "enforcement_point_path": "/infra/sites/default"}]})
            if len(parts) == 7 and parts[4] == "rules" and \
                    parts[6] == "statistics":
                if st.stats_unsupported:
                    return self._send(
                        404, {"error_message": "statistics not supported"})
                pid, rid = parts[3], parts[5]
                counters = st.stats.get(pid, {}).get(rid)
                if counters is None:
                    return self._send(200, {"results": []})
                rule = next((r for r in st.rules.get(pid, [])
                             if r["id"] == rid), None)
                entry = dict(counters)
                entry["rule_path"] = rule["path"] if rule else ""
                return self._send(200, {"results": [{"statistics": [entry]}]})

        return self._send(404, {"error_message": "unhandled GET " + path})


class FakeNsx:
    """Context manager wrapping a running fake manager."""

    def __init__(self, role="lm", name="fake", version="4.1.2.0"):
        self.state = FakeState(role=role, name=name, version=version)
        self.server = None
        self.thread = None

    def start(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.state = self.state
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        return self

    @property
    def port(self):
        return self.server.server_address[1]

    def entry(self, **overrides):
        """An inventory entry pointing at this fake."""
        e = {"name": self.state.name,
             "role": self.state.role,
             "host": "127.0.0.1",
             "port": self.port,
             "scheme": "http",
             "verify_ssl": False,
             "auth": "session",
             "username_env": "FAKE_USER",
             "password_env": "FAKE_PASS"}
        e.update(overrides)
        return e

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
