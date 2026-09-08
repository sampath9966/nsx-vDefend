"""NSX transport and session.

Two transports sit behind one interface: 'requests' when it is installed, and
a pure-stdlib urllib fallback when it is not. The toolkit therefore runs on a
locked-down jumpbox with nothing installed at all.

On top of that: retry with backoff (a single 503 no longer aborts a sweep of
eight managers), session-token authentication (Basic on every call would
re-authenticate against AD/LDAP each request and risk account lockout), TLS
verification scoped per manager, and a lazily-built VM index so repeated VM
lookups cost one inventory fetch instead of one per lookup.
"""

import base64
import json
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .api import (
    ACTION_UPDATE_TAGS,
    API_BASE_GM_CANDIDATES,
    API_BASE_LM,
    DEFAULT_DOMAIN,
    DEFAULT_ORG,
    F_CURSOR,
    F_DISPLAY_NAME,
    F_EXTERNAL_ID,
    F_NODE_VERSION,
    F_PRODUCT_VERSION,
    F_RESULTS,
    F_TAG_SCOPE,
    F_TAG_VALUE,
    F_TAGS,
    PAGE_SIZE,
    PARAM_ACTION,
    PARAM_CURSOR,
    PARAM_DISPLAY_NAME,
    PARAM_PAGE_SIZE,
    PATH_FABRIC_VMS,
    PATH_NODE_VERSION,
    PATH_SESSION_CREATE,
    ROLE_GM,
    p_groups,
    parse_version,
    project_base,
)
from .errors import NsxError, NsxHttpError
from .output import cG, debug, say

RETRY_STATUS = (429, 500, 502, 503, 504)
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.0
MAX_BACKOFF = 20.0

_tls_warnings_suppressed = False
_suppress_lock = threading.Lock()


def _suppress_tls_warnings():
    """Silence 'unverified HTTPS' noise -- only ever called when a manager is
    actually configured with verify_ssl false, never globally at import."""
    global _tls_warnings_suppressed
    with _suppress_lock:
        if _tls_warnings_suppressed:
            return
        _tls_warnings_suppressed = True
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass


def have_requests():
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False


class TransportError(Exception):
    """Connection-level failure (DNS, refused, reset, timeout)."""


class Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise NsxError("Response was not valid JSON: {}".format(e)) from e

    def text(self, limit=400):
        try:
            return self.body.decode("utf-8", "replace")[:limit]
        except Exception:
            return ""


class RequestsTransport:
    name = "requests"

    def __init__(self, pool_size=16):
        import requests
        from requests.adapters import HTTPAdapter
        self._requests = requests
        self.s = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size,
                              pool_maxsize=pool_size, max_retries=0)
        self.s.mount("https://", adapter)
        self.s.mount("http://", adapter)

    def request(self, method, url, headers, body, timeout, verify, cert):
        try:
            r = self.s.request(method, url, headers=headers, data=body,
                               timeout=timeout, verify=verify, cert=cert,
                               allow_redirects=False)
        except self._requests.exceptions.RequestException as e:
            raise TransportError(str(e)) from e
        return Response(r.status_code, dict(r.headers), r.content)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


class UrllibTransport:
    """Stdlib fallback. Same interface, no third-party dependency."""

    name = "urllib"

    def __init__(self, pool_size=16):
        self._cookies = {}
        self._lock = threading.Lock()

    def _context(self, verify):
        if verify is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if isinstance(verify, str):
            return ssl.create_default_context(cafile=verify)
        return ssl.create_default_context()

    def request(self, method, url, headers, body, timeout, verify, cert):
        if cert:
            raise NsxError(
                "Client-certificate auth needs the 'requests' library "
                "(pip install requests).")
        hdrs = dict(headers or {})
        with self._lock:
            if self._cookies:
                hdrs["Cookie"] = "; ".join(
                    "{}={}".format(k, v) for k, v in self._cookies.items())
        if isinstance(body, str):
            body = body.encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(
                    req, timeout=timeout, context=self._context(verify)) as r:
                resp = Response(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            resp = Response(e.code, dict(e.headers or {}), e.read() or b"")
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            raise TransportError(str(e)) from e
        self._absorb_cookies(resp.headers)
        return resp

    def _absorb_cookies(self, headers):
        raw = headers.get("Set-Cookie") or headers.get("set-cookie")
        if not raw:
            return
        with self._lock:
            for chunk in str(raw).split(","):
                pair = chunk.split(";", 1)[0].strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    if k.strip():
                        self._cookies[k.strip()] = v.strip()

    def close(self):
        pass


def make_transport(pool_size=16):
    return (RequestsTransport(pool_size) if have_requests()
            else UrllibTransport(pool_size))


class Nsx:
    """One authenticated NSX manager."""

    def __init__(self, entry, user, pwd, transport=None, retries=DEFAULT_RETRIES):
        self.entry = entry
        self.name = entry.get("name", "?")
        self.role = (entry.get("role") or "").lower() or None
        host = entry.get("host")
        if not host:
            raise NsxError("'{}' has no 'host'.".format(self.name))
        self.host = host
        # 'scheme' exists for test harnesses and plaintext lab appliances.
        # Production NSX is always https, which is why that is the default.
        scheme = (entry.get("scheme") or "https").lower()
        self.base_url = "{}://{}:{}".format(scheme, host, entry.get("port", 443))
        self.timeout = entry.get("timeout", 30)
        self.retries = retries
        self.auth_mode = (entry.get("auth") or "session").lower()
        self._user, self._pwd = user, pwd
        self._base = entry.get("policy_base")
        # NSX Project scoping. Set, every policy path hangs off the project's
        # own infra tree instead of the default one.
        self.project = entry.get("project")
        self.org = entry.get("org") or DEFAULT_ORG
        self._version = None
        self._vm_index = None
        self._vm_lock = threading.Lock()
        self._base_lock = threading.Lock()
        self._auth_lock = threading.Lock()
        self._session_headers = {}
        self._authenticated = False

        verify = entry.get("verify_ssl", True)
        ca = entry.get("ca_bundle")
        if verify and ca:
            self.verify = ca
        else:
            self.verify = bool(verify)
        if self.verify is False:
            _suppress_tls_warnings()
        self.cert = entry.get("client_cert")
        self.t = transport or make_transport()

    # --- auth --------------------------------------------------------------
    def _basic_header(self):
        raw = "{}:{}".format(self._user, self._pwd).encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

    def _ensure_auth(self):
        """Establish session-token auth once. Falls back to Basic if the
        manager does not offer session create."""
        if self._authenticated:
            return
        with self._auth_lock:
            if self._authenticated:
                return
            if self.auth_mode == "basic":
                self._session_headers = self._basic_header()
            elif self.auth_mode == "token":
                token = self.entry.get("token") or self._pwd
                header = self.entry.get("token_header") or "X-NSX-Auth-Token"
                self._session_headers = {header: token}
            elif self.auth_mode == "cert":
                self._session_headers = {}
            else:
                self._session_headers = self._session_login()
            self._authenticated = True

    def _session_login(self):
        body = urllib.parse.urlencode(
            {"j_username": self._user, "j_password": self._pwd}).encode("utf-8")
        url = self.base_url + PATH_SESSION_CREATE
        try:
            r = self._send("POST", url, {
                "Content-Type": "application/x-www-form-urlencoded"}, body)
        except (TransportError, NsxError) as e:
            debug("{}: session create failed ({}), falling back to Basic".format(
                self.name, e))
            return self._basic_header()
        if r.status >= 400:
            debug("{}: session create HTTP {}, falling back to Basic".format(
                self.name, r.status))
            return self._basic_header()
        headers = {}
        xsrf = r.headers.get("x-xsrf-token") or r.headers.get("X-XSRF-TOKEN")
        if xsrf:
            headers["X-XSRF-TOKEN"] = xsrf
        cookie = r.headers.get("Set-Cookie") or r.headers.get("set-cookie")
        if cookie:
            jar = [c.split(";", 1)[0].strip() for c in str(cookie).split(",")
                   if "=" in c.split(";", 1)[0]]
            if jar:
                headers["Cookie"] = "; ".join(jar)
        if not headers:
            debug("{}: session create returned no token, using Basic".format(self.name))
            return self._basic_header()
        debug("{}: authenticated via session token".format(self.name))
        return headers

    # --- request plumbing --------------------------------------------------
    def _send(self, method, url, headers, body):
        return self.t.request(method, url, headers, body, self.timeout,
                              self.verify, self.cert)

    def _sleep_for(self, attempt, response):
        if response is not None:
            ra = (response.headers or {}).get("Retry-After")
            if ra:
                try:
                    return min(float(ra), MAX_BACKOFF)
                except ValueError:
                    pass
        return min(DEFAULT_BACKOFF * (2 ** attempt), MAX_BACKOFF) * (
            0.5 + random.random() / 2.0)

    def _req(self, method, path, body=None, params=None):
        self._ensure_auth()
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        headers = dict(self._session_headers)
        headers.setdefault("Accept", "application/json")
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")

        last_exc = None
        for attempt in range(self.retries + 1):
            started = time.time()
            try:
                r = self._send(method, url, headers, payload)
            except TransportError as e:
                last_exc = NsxError("[{}] {} {} -> {}".format(
                    self.name, method, url, e))
                debug("{} {} -> transport error: {} (attempt {}/{})".format(
                    method, url, e, attempt + 1, self.retries + 1))
                if attempt < self.retries:
                    time.sleep(self._sleep_for(attempt, None))
                    continue
                raise last_exc from e
            elapsed = (time.time() - started) * 1000
            debug("{} {} -> {} ({:.0f}ms)".format(method, url, r.status, elapsed))
            if r.status in RETRY_STATUS and attempt < self.retries:
                wait = self._sleep_for(attempt, r)
                debug("  retrying after {:.1f}s (HTTP {})".format(wait, r.status))
                time.sleep(wait)
                continue
            if r.status >= 400:
                raise NsxHttpError("[{}] {} {} -> HTTP {}: {}".format(
                    self.name, method, url, r.status, r.text()), r.status)
            return r.json()
        raise last_exc or NsxError("[{}] {} {} -> exhausted retries".format(
            self.name, method, url))

    def get(self, path, params=None):
        return self._req("GET", path, params=params)

    def post(self, path, body=None, params=None):
        return self._req("POST", path, body=body, params=params)

    def patch(self, path, body=None, params=None):
        return self._req("PATCH", path, body=body, params=params)

    def put(self, path, body=None, params=None):
        """Full-object write. PUT rather than PATCH for anything carrying a
        `_revision`: NSX only enforces the optimistic-concurrency check when
        the whole object is sent, and that check is the entire safety
        mechanism behind authoring."""
        return self._req("PUT", path, body=body, params=params)

    def delete(self, path, params=None):
        return self._req("DELETE", path, params=params)

    def get_all(self, path, params=None):
        """Follow NSX's opaque cursor pagination to completion."""
        out, cursor = [], None
        while True:
            p = dict(params or {})
            p.setdefault(PARAM_PAGE_SIZE, PAGE_SIZE)
            if cursor:
                p[PARAM_CURSOR] = cursor
            data = self.get(path, params=p)
            out.extend(data.get(F_RESULTS, []))
            cursor = data.get(F_CURSOR)
            if not cursor:
                break
        return out

    # --- capability detection ---------------------------------------------
    def base(self, domain=DEFAULT_DOMAIN, verbose=False):
        """Policy API base. GM answers on one of two paths depending on
        version, so probe rather than guess."""
        if self._base:
            return self._base
        with self._base_lock:
            if self._base:
                return self._base
            if self.project:
                # A project's tree is the same on either role, so no probe.
                self._base = project_base(self.project, self.org)
                if verbose:
                    say("    project scope: {}".format(cG(self._base)))
                return self._base
            if self.role != ROLE_GM:
                self._base = API_BASE_LM
                return self._base
            notes = []
            for cand in API_BASE_GM_CANDIDATES:
                try:
                    self.get(p_groups(cand, domain), params={PARAM_PAGE_SIZE: 1})
                    self._base = cand
                    if verbose:
                        say("    GM answers on: {}".format(cG(cand)))
                    return self._base
                except NsxError as e:
                    notes.append(str(e)[:160])
            raise NsxError("GM did not answer on any known base.\n" +
                           "\n".join("      {}".format(n) for n in notes))

    def version(self):
        """(major, minor) of the manager, or None if it cannot be read."""
        if self._version is not None:
            return self._version or None
        try:
            d = self.get(PATH_NODE_VERSION)
            raw = d.get(F_NODE_VERSION) or d.get(F_PRODUCT_VERSION)
            self._version = parse_version(raw) or ()
        except NsxError:
            self._version = ()
        return self._version or None

    # --- VM inventory ------------------------------------------------------
    def all_vms(self, refresh=False):
        """Full VM inventory, fetched at most once per session.

        This is the fix for bulk tagging: resolving 500 CSV rows previously
        triggered up to 500 full inventory sweeps per manager.
        """
        with self._vm_lock:
            if self._vm_index is None or refresh:
                self._vm_index = self.get_all(PATH_FABRIC_VMS)
            return self._vm_index

    def invalidate_vms(self):
        with self._vm_lock:
            self._vm_index = None

    def find_vms(self, needle, exact=False):
        """VMs whose display name matches. Tries the server-side exact filter
        first (cheap), then falls back to the cached index for substrings."""
        if not needle:
            return []
        try:
            hits = self.get(PATH_FABRIC_VMS,
                            params={PARAM_DISPLAY_NAME: needle}).get(F_RESULTS, [])
            if hits:
                return hits
        except NsxError:
            pass
        n = str(needle).lower()
        vms = self.all_vms()
        if exact:
            return [v for v in vms if str(v.get(F_DISPLAY_NAME, "")).lower() == n]
        return [v for v in vms if n in str(v.get(F_DISPLAY_NAME, "")).lower()]

    def get_vm_by_external_id(self, ext_id):
        for v in self.all_vms():
            if v.get(F_EXTERNAL_ID) == ext_id:
                return v
        return None

    def refresh_vm(self, vm):
        """Re-read one VM straight from NSX, bypassing the cache. Used
        immediately before a write so a stale plan cannot clobber someone
        else's concurrent change."""
        ext = vm.get(F_EXTERNAL_ID)
        name = vm.get(F_DISPLAY_NAME, "")
        try:
            hits = self.get(PATH_FABRIC_VMS,
                            params={PARAM_DISPLAY_NAME: name}).get(F_RESULTS, [])
            for h in hits:
                if h.get(F_EXTERNAL_ID) == ext:
                    return h
        except NsxError:
            pass
        for v in self.all_vms(refresh=True):
            if v.get(F_EXTERNAL_ID) == ext:
                return v
        return None

    def update_vm_tags(self, vm, pairs):
        ext = vm.get(F_EXTERNAL_ID)
        if not ext:
            raise NsxError("VM has no external_id.")
        self.post(PATH_FABRIC_VMS,
                  body={F_EXTERNAL_ID: ext,
                        F_TAGS: [{F_TAG_SCOPE: s, F_TAG_VALUE: t} for s, t in pairs]},
                  params={PARAM_ACTION: ACTION_UPDATE_TAGS})
        self.invalidate_vms()

    def close(self):
        try:
            self.t.close()
        except Exception:
            pass
