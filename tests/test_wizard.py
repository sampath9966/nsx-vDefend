"""First-run setup -- the path that decides whether anyone keeps the tool."""

import builtins
import json
import os

import pytest

from nsx_toolkit import creds, output, wizard


@pytest.fixture
def answers(monkeypatch):
    """Feed scripted keystrokes to the wizard."""
    def _set(seq):
        pending = list(seq)

        def fake_input(_prompt=""):
            if not pending:
                raise EOFError("wizard asked more questions than expected")
            return pending.pop(0)

        monkeypatch.setattr(builtins, "input", fake_input)
        return lambda: pending
    output.set_interactive(True)
    yield _set
    output.set_interactive(False)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NSX_TOOLKIT_CREDENTIALS_FILE", str(tmp_path / "creds.env"))
    creds.set_store_policy("none")
    creds.reset_cache()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_non_interactive_first_run_prints_copyable_guidance(capsys, tmp_path):
    output.set_interactive(False)
    assert wizard.run_wizard(None) is None
    combined = capsys.readouterr()
    text = combined.out + combined.err
    assert "managers" in text          # a JSON example to copy
    assert "--inventory" in text       # and the flag that points at it
    assert "role" in text


def test_builds_an_inventory_from_answers(isolated, answers, monkeypatch, lm):
    """One Local Manager, answered end to end, written and reloadable."""
    monkeypatch.setenv("NSX_LM1_USER", "svc")
    monkeypatch.setenv("NSX_LM1_PASS", "secret")
    creds.reset_cache()
    answers([
        "127.0.0.1",   # hostname
        "lm1",         # short name
        "1",           # role: Local Manager
        str(lm.port),  # port
        "n",           # verify TLS?
        "n",           # add another manager?
        "1",           # store in the data dir
    ])
    path = wizard.run_wizard(None)
    assert path is not None
    data = json.loads(open(path, encoding="utf-8").read())
    entry = data["managers"][0]
    assert entry["name"] == "lm1"
    assert entry["role"] == "lm"
    assert entry["host"] == "127.0.0.1"
    assert entry["port"] == lm.port
    assert entry["verify_ssl"] is False
    assert entry["username_env"] == "NSX_LM1_USER"

    from nsx_toolkit.config import load_inventory
    assert load_inventory(path)[0]["name"] == "lm1"


def test_configures_a_global_manager_and_several_locals(isolated, answers,
                                                        monkeypatch):
    monkeypatch.setattr(wizard, "_test", lambda entry: True)
    answers([
        "gm.example.com", "gm", "2", "443", "n",   # a Global Manager
        "y",                                        # add another
        "lon.example.com", "lon", "1", "443", "n",  # a Local Manager
        "y",                                        # add another
        "fra.example.com", "fra", "1", "443", "n",  # another Local Manager
        "n",                                        # done
        "1",                                        # data dir
    ])
    path = wizard.run_wizard(None)
    managers = json.loads(open(path, encoding="utf-8").read())["managers"]
    assert [(m["name"], m["role"]) for m in managers] == [
        ("gm", "gm"), ("lon", "lm"), ("fra", "lm")]


def test_tls_verification_collects_a_ca_bundle(isolated, answers, monkeypatch):
    monkeypatch.setattr(wizard, "_test", lambda entry: True)
    answers([
        "lm.example.com", "lm1", "1", "443",
        "y",                        # verify TLS
        "/etc/pki/corp-ca.pem",     # CA bundle
        "n", "1",
    ])
    path = wizard.run_wizard(None)
    entry = json.loads(open(path, encoding="utf-8").read())["managers"][0]
    assert entry["verify_ssl"] is True
    assert entry["ca_bundle"] == "/etc/pki/corp-ca.pem"


def test_duplicate_names_are_rejected_before_writing(isolated, answers,
                                                     monkeypatch):
    monkeypatch.setattr(wizard, "_test", lambda entry: True)
    answers([
        "a.example.com", "dup", "1", "443", "n",
        "y",
        "b.example.com", "dup",     # rejected
        "dup2",                     # accepted
        "1", "443", "n",
        "n", "1",
    ])
    path = wizard.run_wizard(None)
    names = [m["name"] for m in
             json.loads(open(path, encoding="utf-8").read())["managers"]]
    assert names == ["dup", "dup2"]


def test_inventory_is_kept_even_when_a_manager_fails_its_check(
        isolated, answers, monkeypatch, capsys):
    """A typo'd host must not throw away everything else you just typed."""
    monkeypatch.setattr(wizard, "_test", lambda entry: False)
    answers(["broken.example.com", "lm1", "1", "443", "n", "n", "1"])
    path = wizard.run_wizard(None)
    assert path is not None and os.path.isfile(path)
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "--verify" in out          # tells you how to retest


def test_declining_to_overwrite_leaves_the_existing_file(isolated, answers,
                                                         monkeypatch):
    existing = isolated / "inventory.json"
    existing.write_text(json.dumps({"managers": [{"name": "keep"}]}),
                        encoding="utf-8")
    monkeypatch.setattr(wizard, "_test", lambda entry: True)
    answers([
        "new.example.com", "new", "1", "443", "n",
        "n",
        "2",      # the current directory, where the file already exists
        "n",      # do not overwrite
    ])
    assert wizard.run_wizard(None) is None
    kept = json.loads(existing.read_text(encoding="utf-8"))
    assert kept["managers"][0]["name"] == "keep"


def test_bootstrap_reports_where_it_looked(capsys, tmp_path):
    output.set_interactive(False)
    wizard.maybe_bootstrap(None, [str(tmp_path)])
    text = capsys.readouterr().out
    assert str(tmp_path) in text
    assert "inventory.json" in text
