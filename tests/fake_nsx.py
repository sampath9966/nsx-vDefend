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
"""

import json
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
        self.request_log = []
        self.fail_times = {}         # path substring -> remaining 503s
        self.require_auth = True
        self.lock = threading.Lock()

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
        group = {"id": gid,
                 "display_name": display_name or gid,
                 "path": "{}/domains/default/groups/{}".format(prefix, gid),
                 "expression": expression or []}
        self.groups.append(group)
        self.group_members[gid] = list(members)
        return group

    def associate(self, vm, group):
        self.associations.setdefault(vm["external_id"], []).append({
            "target_id": group["id"],
            "target_display_name": group["display_name"],
            "target_type": "Group",
            "path": group["path"],
            "is_valid": True})

    def add_policy(self, pid, display_name=None, origin="LM"):
        prefix = "/global-infra" if origin == "GM" else "/infra"
        pol = {"id": pid,
               "display_name": display_name or pid,
               "path": "{}/domains/default/security-policies/{}".format(prefix, pid)}
        self.policies.append(pol)
        self.rules.setdefault(pid, [])
        return pol

    def add_rule(self, pid, rid, source_groups=(), destination_groups=(),
                 scope=(), action="ALLOW", origin="LM", display_name=None):
        prefix = "/global-infra" if origin == "GM" else "/infra"
        rule = {"id": rid,
                "display_name": display_name or rid,
                "path": "{}/domains/default/security-policies/{}/rules/{}".format(
                    prefix, pid, rid),
                "source_groups": list(source_groups),
                "destination_groups": list(destination_groups),
                "scope": list(scope),
                "action": action}
        self.rules.setdefault(pid, []).append(rule)
        return rule

    def fail_next(self, path_fragment, times=1):
        """Return HTTP 503 for the next `times` requests matching a path."""
        self.fail_times[path_fragment] = times

    def count(self, fragment):
        return sum(1 for entry in self.request_log if fragment in entry)


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

    # --- routing -----------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        with self.state.lock:
            self.state.request_log.append("POST " + path)

        if path == "/api/session/create":
            return self._send(200, {}, {
                "Set-Cookie": "JSESSIONID=fake-session-id; Path=/; HttpOnly",
                "X-XSRF-TOKEN": "fake-xsrf-token"})

        if not self._authed():
            return self._send(403, {"error_message": "not authenticated"})
        if self._maybe_fail(path):
            return self._send(503, {"error_message": "busy"})

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

        if path == "/api/v1/fabric/virtual-machines":
            if st.role == "gm":
                return self._send(404, {"error_message": "GM holds no VMs"})
            vms = st.vms
            wanted = query.get("display_name")
            if wanted:
                vms = [v for v in vms if v["display_name"] == wanted[0]]
            return self._send(200, _page(vms, query))

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

        parts = [p for p in rel.split("/") if p]
        # domains/{domain}/groups[/{gid}/members/virtual-machines]
        if len(parts) >= 3 and parts[0] == "domains" and parts[2] == "groups":
            if len(parts) == 3:
                return self._send(200, _page(st.groups, query))
            if len(parts) == 6 and parts[4] == "members" and \
                    parts[5] == "virtual-machines":
                return self._send(
                    200, _page(st.group_members.get(parts[3], []), query))

        # domains/{domain}/security-policies[/{pid}/rules]
        if len(parts) >= 3 and parts[0] == "domains" and \
                parts[2] == "security-policies":
            if len(parts) == 3:
                return self._send(200, _page(st.policies, query))
            if len(parts) == 5 and parts[4] == "rules":
                return self._send(200, _page(st.rules.get(parts[3], []), query))

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
