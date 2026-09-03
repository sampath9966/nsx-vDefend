"""The pre-4.0 flag interface must keep working, and mean the same thing.

A deprecation shim nobody tests is just a second code path that quietly drifts
away from the real one. Each test here asserts the old flag and its documented
replacement produce the *same* result, not merely that the old flag runs.
"""

import json

import pytest
from fake_nsx import FakeNsx

from nsx_toolkit import cli
from nsx_toolkit.legacy import REPLACEMENT, translate_legacy_argv, uses_legacy


@pytest.fixture
def env(tmp_path, monkeypatch):
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


# --- translation ---------------------------------------------------------
def test_detects_legacy_flags():
    assert uses_legacy(["--dashboard"]) is True
    assert uses_legacy(["compliance"]) is False
    assert uses_legacy(["--json", "compliance"]) is False


def test_every_documented_replacement_translates():
    """Nothing in the deprecation table may be a promise the shim can't keep."""
    samples = {
        "--init": ["--init"],
        "--verify": ["--verify"],
        "--list-managers": ["--list-managers"],
        "--set-credentials": ["--set-credentials"],
        "--groups": ["--groups"],
        "--vm-tags": ["--vm-tags", "web1"],
        "--vms-by-tag": ["--vms-by-tag", "--scope", "env"],
        "--bulk-tag": ["--bulk-tag", "c.csv"],
        "--change-ticket": ["--change-ticket", "c.csv"],
        "--reverse-lookup": ["--reverse-lookup", "web1"],
        "--parity": ["--parity", "a", "b"],
        "--dashboard": ["--dashboard"],
        "--audit-log": ["--audit-log"],
    }
    assert set(samples) == set(REPLACEMENT), "a documented flag has no sample"
    for flag, argv in samples.items():
        commands, warnings = translate_legacy_argv(argv)
        assert commands, "{} translated to nothing".format(flag)
        assert any(flag in w for w in warnings), flag
        assert any(REPLACEMENT[flag].split()[1] in c for c in commands), flag


def test_translation_carries_command_options_across():
    commands, _ = translate_legacy_argv(
        ["--groups", "--contains", "web", "--members"])
    assert commands == [["group", "list", "--contains", "web", "--members"]]

    commands, _ = translate_legacy_argv(
        ["--vms-by-tag", "--scope", "env", "--tag", "prod"])
    assert commands == [["tag", "find", "--scope", "env", "--tag", "prod"]]

    commands, _ = translate_legacy_argv(["--bulk-tag", "c.csv", "--dry-run"])
    assert commands == [["tag", "apply", "c.csv", "--dry-run"]]


def test_global_flags_pass_through_untouched():
    commands, _ = translate_legacy_argv(
        ["--dashboard", "--json", "--manager", "lm1"])
    assert commands == [["compliance", "--json", "--manager", "lm1"]]


def test_multiple_actions_become_a_sequence():
    """The old CLI ran several actions in one invocation. Losing that would
    silently change what an existing cron job produces."""
    commands, warnings = translate_legacy_argv(["--groups", "--dashboard"])
    assert commands == [["group", "list"], ["compliance"]]
    assert len(warnings) == 2


# --- equivalence, end to end --------------------------------------------
def run(argv):
    return cli.main(argv)


def test_dashboard_flag_equals_compliance_command(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "prod")])

    assert run(["--inventory", inv, "--dashboard", "--json"]) == 0
    legacy_out = capsys.readouterr()
    assert run(["--inventory", inv, "compliance", "--json"]) == 0
    modern_out = capsys.readouterr()

    legacy_payload = json.loads(legacy_out.out)
    modern_payload = json.loads(modern_out.out)
    assert legacy_payload["results"] == modern_payload["results"]
    # ... and the old form said so, on stderr, exactly once.
    assert "use: nsxctl compliance" in legacy_out.err
    assert modern_out.err == ""


def test_vm_tags_flag_equals_tag_list_command(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "prod"), ("tier", "web")])

    run(["--inventory", inv, "--vm-tags", "web1", "--json"])
    legacy_payload = json.loads(capsys.readouterr().out)
    run(["--inventory", inv, "tag", "list", "web1", "--json"])
    modern_payload = json.loads(capsys.readouterr().out)
    assert legacy_payload["results"] == modern_payload["results"]


def test_reverse_lookup_flag_equals_impact_command(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    vm = fakes[0].state.add_vm("web1")
    group = fakes[0].state.add_group("g1", "Web Group")
    fakes[0].state.associate(vm, group)
    fakes[0].state.add_policy("p1")
    fakes[0].state.add_rule("p1", "r1", source_groups=[group["path"]])

    run(["--inventory", inv, "--reverse-lookup", "web1", "--json"])
    legacy_payload = json.loads(capsys.readouterr().out)
    run(["--inventory", inv, "impact", "web1", "--json"])
    modern_payload = json.loads(capsys.readouterr().out)
    assert legacy_payload["results"] == modern_payload["results"]
    assert legacy_payload["results"][0]["count"] == 1


def test_warning_goes_to_stderr_so_json_stays_parseable(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1")
    run(["--inventory", inv, "--dashboard", "--json"])
    captured = capsys.readouterr()
    json.loads(captured.out)          # the whole of stdout is the envelope
    assert "deprecated" in captured.err


def test_multi_action_run_still_exports_both_sets(env, tmp_path):
    """`--groups --dashboard --out-csv` wrote two files before 4.0; it still
    must, or someone's report silently loses half its content."""
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "prod")])
    fakes[0].state.add_group("g1", "Group One")
    target = tmp_path / "report.csv"
    assert run(["--inventory", inv, "--groups", "--dashboard",
                "--out-csv", str(target), "--non-interactive"]) == 0
    produced = sorted(p.name for p in tmp_path.glob("report_*.csv"))
    assert produced == ["report_dashboard.csv", "report_groups.csv"]


def test_legacy_bulk_tag_still_gated_on_yes(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    run(["--inventory", inv, "--bulk-tag", str(csv_path), "--enable-writes",
         "--non-interactive"])
    assert "Refusing to" in capsys.readouterr().err
    assert fakes[0].state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]
