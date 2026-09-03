"""End-to-end CLI behaviour against fake managers."""

import json

import pytest
from fake_nsx import FakeNsx

from nsx_toolkit import cli


@pytest.fixture
def env(tmp_path, monkeypatch):
    """An inventory plus credentials, wired to real fake managers."""
    monkeypatch.setenv("NSX_TOOLKIT_CREDENTIALS_FILE",
                       str(tmp_path / "credentials.env"))
    monkeypatch.setenv("FAKE_USER", "user")
    monkeypatch.setenv("FAKE_PASS", "pass")
    monkeypatch.setattr(cli, "DATA_DIR", str(tmp_path))
    from nsx_toolkit import creds
    creds.reset_cache()

    fakes = []

    def build(*roles):
        entries = []
        for role, name in roles:
            f = FakeNsx(role=role, name=name).start()
            fakes.append(f)
            entries.append(f.entry())
        inv = tmp_path / "inventory.json"
        inv.write_text(json.dumps({"managers": entries}), encoding="utf-8")
        return str(inv), fakes

    yield build
    for f in fakes:
        f.stop()


def run(argv):
    return cli.main(argv)


def test_json_output_is_a_parseable_envelope(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "prod")])
    rc = run(["--inventory", inv, "--dashboard", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["exit_code"] == 0
    labels = [r["label"] for r in payload["results"]]
    assert "dashboard" in labels


def test_json_mode_never_writes_banner_noise_to_stdout(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1")
    run(["--inventory", inv, "--dashboard", "--json"])
    out = capsys.readouterr().out
    json.loads(out)  # the whole of stdout must be the envelope


def test_two_actions_export_two_csv_files(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "prod")])
    fakes[0].state.add_group("g1", "Group One")
    target = tmp_path / "out.csv"
    rc = run(["--inventory", inv, "--groups", "--dashboard",
              "--out-csv", str(target), "--non-interactive"])
    assert rc == 0
    produced = sorted(p.name for p in tmp_path.glob("out_*.csv"))
    assert produced == ["out_dashboard.csv", "out_groups.csv"]


def test_bulk_write_is_refused_without_yes(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    rc = run(["--inventory", inv, "--bulk-tag", str(csv_path),
              "--enable-writes", "--non-interactive"])
    combined = capsys.readouterr()
    assert "Refusing to" in combined.err
    assert rc == 0
    assert fakes[0].state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]


def test_bulk_write_proceeds_with_yes(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    rc = run(["--inventory", inv, "--bulk-tag", str(csv_path),
              "--enable-writes", "--yes", "--non-interactive"])
    assert rc == 0
    assert {t["tag"] for t in fakes[0].state.vms[0]["tags"]} == {"dev", "prod"}


def test_dry_run_never_writes_even_with_yes(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    run(["--inventory", inv, "--bulk-tag", str(csv_path), "--dry-run",
         "--enable-writes", "--yes", "--non-interactive"])
    assert fakes[0].state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]


def test_unknown_manager_name_lists_the_known_ones(env, capsys):
    inv, _ = env(("lm", "lm1"))
    rc = run(["--inventory", inv, "--manager", "typo", "--verify"])
    assert rc == 2
    assert "lm1" in capsys.readouterr().err


def test_verify_reports_failure_via_exit_code(env):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.fail_next("/domains/default/groups", times=99)
    rc = run(["--inventory", inv, "--verify", "--non-interactive"])
    assert rc == 1


def test_verify_succeeds_against_a_healthy_manager(env):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_group("g1")
    fakes[0].state.add_policy("p1")
    fakes[0].state.add_vm("web1")
    assert run(["--inventory", inv, "--verify", "--non-interactive"]) == 0


def test_reverse_lookup_across_gm_and_lm_from_the_cli(env, capsys):
    inv, fakes = env(("gm", "gm1"), ("lm", "lm1"))
    gm, lm = fakes
    gpath = "/global-infra/domains/default/groups/gg1"
    for f in (gm, lm):
        f.state.add_group("gg1", "Global Web", origin="GM")
        f.state.add_policy("gpol", origin="GM")
        f.state.add_rule("gpol", "grule", source_groups=[gpath], origin="GM")
    vm = lm.state.add_vm("web1")
    lm.state.associate(vm, lm.state.groups[0])

    rc = run(["--inventory", inv, "--reverse-lookup", "web1", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    rows = next(r for r in payload["results"] if r["label"] == "reverse_lookup")
    assert rows["count"] == 1
    assert rows["records"][0]["rule_origin"] == "GM"


def test_change_ticket_validates_against_live_nsx(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text(
        "vm_name,scope,tag,action\nweb1,env,prod,add\nghost,env,prod,add\n",
        encoding="utf-8")
    rc = run(["--inventory", inv, "--change-ticket", str(csv_path),
              "--non-interactive"])
    out = capsys.readouterr().out
    assert rc == 0
    # The plan states the VM's real current tags and flags the unknown one.
    assert "current : env=dev" in out
    assert "NOT FOUND ON ANY MANAGER" in out
    assert "ghost" in out


def test_taxonomy_file_changes_what_counts_as_compliant(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("zone", "red")])
    tax = tmp_path / "custom.json"
    tax.write_text(json.dumps(
        {"scopes": {"zone": {"required": True, "values": ["red", "green"]}}}),
        encoding="utf-8")
    rc = run(["--inventory", inv, "--dashboard", "--taxonomy", str(tax),
              "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    record = next(r for r in payload["results"]
                  if r["label"] == "dashboard")["records"][0]
    assert record["status"] == "complete"
    assert record["missing"] == "none"
