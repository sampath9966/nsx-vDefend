"""Tests for nsxctl vcf import."""
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nsx_toolkit.actions.vcf import act_vcf_import
from nsx_toolkit.export import Exporter


def _rows(exp, label):
    for rs in exp.sets:
        if rs.label == label:
            return rs.rows
    return []


def _make_sddc(name, nsx_host):
    return {"name": name, "id": name,
            "nsxtManager": {"hostname": nsx_host}}


class FakeVcf:
    """Minimal in-process SDDC Manager that serves GET /v1/sddcs."""

    def __init__(self, sddcs):
        self._sddcs = sddcs
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def host(self):
        return "127.0.0.1"

    @property
    def port(self):
        return self._server.server_address[1]

    def close(self):
        self._server.shutdown()

    def _handler(self):
        sddcs = self._sddcs

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/v1/sddcs":
                    body = json.dumps({"elements": sddcs}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

        return H


@pytest.fixture
def vcf_server(monkeypatch):
    """Patch ssl context so plain HTTP fake works as https target."""
    sddcs = []
    server = FakeVcf(sddcs)

    # Patch _vcf_get to use http:// internally so we can test without TLS
    import nsx_toolkit.actions.vcf as vcf_mod
    original_get = vcf_mod._vcf_get

    def _plain_get(host, path, user, password, ca_bundle=None):
        import urllib.request
        url = "http://{}:{}{}".format(server.host, server.port, path)
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    monkeypatch.setattr(vcf_mod, "_vcf_get", _plain_get)
    yield server, sddcs
    server.close()


def test_vcf_import_discovers_managers(vcf_server, tmp_path):
    server, sddcs = vcf_server
    sddcs += [
        _make_sddc("sddc-a", "nsx-a.example.com"),
        _make_sddc("sddc-b", "nsx-b.example.com"),
    ]
    out = tmp_path / "inventory.json"
    exp = Exporter()
    act_vcf_import("unused", "user", "pass", str(out),
                   enable_writes=True, exporter=exp)
    rows = _rows(exp, "vcf_import")
    assert len(rows) == 2
    hosts = {r[1] for r in rows}
    assert "nsx-a.example.com" in hosts
    assert "nsx-b.example.com" in hosts
    inv = json.loads(out.read_text())
    assert len(inv["managers"]) == 2


def test_vcf_import_dry_run(vcf_server, tmp_path):
    server, sddcs = vcf_server
    sddcs += [_make_sddc("sddc-a", "nsx-a.example.com")]
    out = tmp_path / "inventory.json"
    exp = Exporter()
    act_vcf_import("unused", "user", "pass", str(out),
                   enable_writes=False, exporter=exp)
    assert not out.exists()


def test_vcf_import_merges_existing(vcf_server, tmp_path):
    server, sddcs = vcf_server
    sddcs += [
        _make_sddc("sddc-a", "nsx-a.example.com"),
        _make_sddc("sddc-b", "nsx-b.example.com"),
    ]
    out = tmp_path / "inventory.json"
    existing = {"managers": [{"name": "sddc-a", "host": "nsx-a.example.com"}]}
    out.write_text(json.dumps(existing))
    exp = Exporter()
    act_vcf_import("unused", "user", "pass", str(out),
                   enable_writes=True, exporter=exp)
    inv = json.loads(out.read_text())
    hosts = {m["host"] for m in inv["managers"]}
    assert hosts == {"nsx-a.example.com", "nsx-b.example.com"}
    rows = _rows(exp, "vcf_import")
    statuses = {r[2] for r in rows}
    assert "already present" in statuses
    assert "new" in statuses


def test_vcf_import_empty_sddcs(vcf_server, tmp_path):
    server, sddcs = vcf_server   # sddcs list is empty
    out = tmp_path / "inventory.json"
    exp = Exporter()
    act_vcf_import("unused", "user", "pass", str(out),
                   enable_writes=True, exporter=exp)
    rows = _rows(exp, "vcf_import")
    assert rows == []
    assert not out.exists()
