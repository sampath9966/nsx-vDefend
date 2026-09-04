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


# === MACHINE-READABLE SINKS ===
def _hygiene_estate(fakes):
    """An estate with one finding worth reporting: an any-any ALLOW."""
    state = fakes[0].state
    state.add_policy("p1", "Policy One")
    state.add_rule("p1", "wide-open", action="ALLOW")


def test_junit_and_sarif_and_metrics_are_written(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    _hygiene_estate(fakes)
    junit = tmp_path / "j.xml"
    sarif = tmp_path / "s.sarif"
    metrics = tmp_path / "m.prom"
    rc = run(["--inventory", inv, "rule", "hygiene", "--non-interactive",
              "--out-junit", str(junit), "--out-sarif", str(sarif),
              "--out-metrics", str(metrics)])
    assert rc == 0
    assert "any_any_allow" in junit.read_text(encoding="utf-8")
    assert "any_any_allow" in sarif.read_text(encoding="utf-8")
    text = metrics.read_text(encoding="utf-8")
    assert 'severity="critical"' in text
    assert "nsxctl_last_run_timestamp_seconds" in text
    import xml.etree.ElementTree as ET
    ET.fromstring(junit.read_text(encoding="utf-8"))
    json.loads(sarif.read_text(encoding="utf-8"))


def test_only_on_change_is_silent_the_second_time(env, tmp_path, capsys):
    """The point of a nightly cron: a quiet night sends no mail."""
    inv, fakes = env(("lm", "lm1"))
    _hygiene_estate(fakes)
    args = ["--inventory", inv, "rule", "hygiene", "--non-interactive",
            "--only-on-change"]

    assert run(args) == 0
    first = capsys.readouterr().out
    assert "any_any_allow" in first

    assert run(args) == 0
    second = capsys.readouterr().out
    assert second.strip() == ""


def test_only_on_change_speaks_up_when_something_changes(env, tmp_path,
                                                         capsys):
    inv, fakes = env(("lm", "lm1"))
    _hygiene_estate(fakes)
    args = ["--inventory", inv, "rule", "hygiene", "--non-interactive",
            "--only-on-change"]
    run(args)
    capsys.readouterr()
    run(args)
    assert capsys.readouterr().out.strip() == ""

    # A new finding appears, so the report comes back.
    fakes[0].state.add_rule("p1", "another-wide-one", action="ALLOW")
    assert run(args) == 0
    assert "any_any_allow" in capsys.readouterr().out


def test_doctor_reports_capabilities_and_can_fail_a_pipeline(env):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_group("g1")
    fakes[0].state.add_policy("p1")
    assert run(["--inventory", inv, "doctor", "--non-interactive"]) == 0

    fakes[0].state.traceflow_unsupported = True
    assert run(["--inventory", inv, "doctor", "--non-interactive",
                "--fail-on-missing"]) == 1


def test_rule_and_policy_and_service_listings_run(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    state = fakes[0].state
    state.add_group("g-web", "Web")
    state.add_service("MySQL", ports=["3306"])
    state.add_policy("app-tier", "App Tier")
    state.add_rule("app-tier", "allow-web", action="ALLOW")
    for command in (["rule", "list"], ["policy", "list"], ["service", "list"]):
        assert run(["--inventory", inv] + command + ["--non-interactive"]) == 0
    out = capsys.readouterr().out
    assert "allow-web" in out and "app-tier" in out and "MySQL" in out


def test_profiles_command_reports_the_estate_in_effect(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    # Rewrite the inventory into the multi-profile shape.
    entries = json.loads(open(inv, encoding="utf-8").read())["managers"]
    open(inv, "w", encoding="utf-8").write(json.dumps({
        "default_profile": "prod",
        "profiles": {"prod": {"managers": entries},
                     "dr": {"managers": entries}}}))
    assert run(["--inventory", inv, "profiles", "--non-interactive"]) == 0
    out = capsys.readouterr().out
    assert "prod" in out and "dr" in out


def test_an_ambiguous_profile_choice_is_refused(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    entries = json.loads(open(inv, encoding="utf-8").read())["managers"]
    open(inv, "w", encoding="utf-8").write(json.dumps({
        "profiles": {"prod": {"managers": entries},
                     "dr": {"managers": entries}}}))
    assert run(["--inventory", inv, "status", "--non-interactive"]) == 2


def test_completion_cache_and_internal_complete(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_group("g-web", "Web")
    fakes[0].state.add_policy("app-tier", "App Tier")
    assert run(["--inventory", inv, "completion", "cache",
                "--non-interactive"]) == 0
    capsys.readouterr()
    # The internal hook reads the cache and needs no inventory at all.
    assert run(["__complete", "groups"]) == 0
    assert "g-web" in capsys.readouterr().out


def test_completion_reads_the_cache_of_the_profile_in_effect(env, tmp_path,
                                                             capsys):
    """The hook does not load the inventory the normal way -- doing so would
    trigger the first-run wizard from a TAB press -- so it has to work the
    profile out for itself or it reads the wrong cache."""
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_group("g-web", "Web")
    entries = json.loads(open(inv, encoding="utf-8").read())["managers"]
    open(inv, "w", encoding="utf-8").write(json.dumps({
        "default_profile": "prod", "profiles": {"prod": {"managers": entries}}}))

    assert run(["--inventory", inv, "completion", "cache",
                "--non-interactive"]) == 0
    capsys.readouterr()
    assert run(["--inventory", inv, "__complete", "groups"]) == 0
    assert "g-web" in capsys.readouterr().out


def test_internal_complete_never_fails_without_a_cache(tmp_path, monkeypatch):
    """It runs inside a shell hook, where a traceback lands on the prompt."""
    from nsx_toolkit import namecache
    monkeypatch.setattr(namecache, "CACHE_DIR", str(tmp_path / "absent"))
    assert run(["__complete", "groups"]) == 0
