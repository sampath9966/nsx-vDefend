"""The nsxctl command surface."""

import json

import pytest
from fake_nsx import FakeNsx

from nsx_toolkit import cli
from nsx_toolkit.commands import apply_global_defaults, build_parser
from nsx_toolkit.commands.shell import command_tree, completion_script


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


# --- parser shape --------------------------------------------------------
def test_global_flags_work_before_and_after_the_subcommand():
    """`nsxctl --json compliance` and `nsxctl compliance --json` are the same
    command. argparse does not give you this for free."""
    parser = build_parser()
    before = apply_global_defaults(parser.parse_args(["--json", "compliance"]))
    after = apply_global_defaults(parser.parse_args(["compliance", "--json"]))
    assert before.json is True
    assert after.json is True
    assert before.command == after.command == "compliance"


def test_a_global_flag_given_early_is_not_reset_by_the_subcommand():
    """The classic argparse trap: the subparser's default clobbering the
    top-level value. SUPPRESS defaults are what prevent it."""
    parser = build_parser()
    args = apply_global_defaults(
        parser.parse_args(["--manager", "lm1", "--debug", "compliance"]))
    assert args.manager == "lm1"
    assert args.debug is True


def test_defaults_are_applied_when_neither_side_supplies_them():
    parser = build_parser()
    args = apply_global_defaults(parser.parse_args(["compliance"]))
    assert args.domain == "default"
    assert args.json is False
    assert args.enable_writes is False


def test_every_command_has_a_handler():
    parser = build_parser()
    tree = command_tree(parser)
    for name in tree:
        argv = [name]
        # Commands with required positionals get a placeholder.
        for placeholder in (["x"], ["x", "y"], []):
            try:
                args = parser.parse_args(argv + placeholder)
            except SystemExit:
                continue
            assert hasattr(args, "func"), name
            break


# --- config --------------------------------------------------------------
def test_config_path_reports_where_everything_lives(env, capsys):
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "config", "path"]) == 0
    out = capsys.readouterr().out
    assert inv in out
    for label in ("credentials", "audit log", "exports", "snapshots"):
        assert label in out


def test_config_show_lists_managers_and_taxonomy(env, capsys):
    inv, _ = env(("gm", "gm1"), ("lm", "lm1"))
    assert cli.main(["--inventory", inv, "config", "show"]) == 0
    out = capsys.readouterr().out
    assert "gm1" in out and "lm1" in out
    assert "tenant" in out          # a taxonomy scope
    assert "prod" in out            # an allowed value


def test_config_validate_passes_on_a_good_inventory(env, capsys):
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "config", "validate"]) == 0
    assert "valid" in capsys.readouterr().out


def test_config_validate_fails_on_a_broken_inventory(tmp_path, capsys):
    """Exit 1 means 'validated, and it is wrong'. Exit 2 is reserved for
    'could not even start' -- a distinction a CI job can act on."""
    bad = tmp_path / "inventory.json"
    bad.write_text(json.dumps({"managers": [{"role": "nope"}]}),
                   encoding="utf-8")
    assert cli.main(["--inventory", str(bad), "config", "validate"]) == 1
    assert "role" in capsys.readouterr().err


def test_config_validate_exit_2_when_there_is_no_inventory(tmp_path, monkeypatch,
                                                           capsys):
    monkeypatch.setattr(cli, "DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["config", "validate"]) == 2
    assert "nsxctl init" in capsys.readouterr().err


def test_config_needs_no_managers_to_be_reachable(tmp_path, capsys):
    """Introspection must work when nothing is up -- that is when you need it."""
    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps({"managers": [
        {"name": "down", "role": "lm", "host": "192.0.2.1",
         "username_env": "U", "password_env": "P"}]}), encoding="utf-8")
    assert cli.main(["--inventory", str(inv), "config", "show"]) == 0
    assert "down" in capsys.readouterr().out


# --- completion ----------------------------------------------------------
@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_script_mentions_every_command(shell):
    script = completion_script(shell)
    for command in ("compliance", "impact", "group", "tag", "rule", "status"):
        assert command in script


def test_completion_is_generated_from_the_live_parser():
    """Adding a command must make it completable without touching the emitter."""
    tree = command_tree(build_parser())
    assert set(tree["tag"]["subcommands"]) == {
        "list", "find", "edit", "apply", "ticket"}
    assert set(tree["group"]["subcommands"]) == {"list", "show"}
    assert "--contains" in tree["group"]["subcommands"]["list"]


def test_completion_needs_no_inventory(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["completion", "bash"]) == 0
    assert "complete -F _nsxctl nsxctl" in capsys.readouterr().out


# --- commands ------------------------------------------------------------
def test_status_reports_transport_and_auth(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_group("g1")
    fakes[0].state.add_policy("p1")
    assert cli.main(["--inventory", inv, "status", "--non-interactive"]) == 0
    out = capsys.readouterr().out
    assert "auth=session" in out
    assert "transport=" in out


def test_managers_lists_configured_managers(env, capsys):
    inv, _ = env(("gm", "gm1"), ("lm", "lm1"))
    assert cli.main(["--inventory", inv, "managers"]) == 0
    out = capsys.readouterr().out
    assert "gm1" in out and "lm1" in out


def test_impact_is_the_reverse_lookup(env, capsys):
    inv, fakes = env(("lm", "lm1"))
    vm = fakes[0].state.add_vm("web1")
    group = fakes[0].state.add_group("g1", "Web Group")
    fakes[0].state.associate(vm, group)
    fakes[0].state.add_policy("p1")
    fakes[0].state.add_rule("p1", "r1", source_groups=[group["path"]])
    assert cli.main(["--inventory", inv, "impact", "web1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    result = next(r for r in payload["results"] if r["label"] == "reverse_lookup")
    assert result["count"] == 1


def test_tag_find_needs_a_scope_or_a_tag(env, capsys):
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "tag", "find"]) == 2
    assert "--scope" in capsys.readouterr().err


def test_bare_noun_explains_what_to_do_next(env, capsys):
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "group"]) == 2
    assert "nsxctl group list" in capsys.readouterr().err


def test_rule_commands_are_registered_but_not_yet_implemented(env, capsys):
    """The surface is stable from day one, so it cannot shift under people
    when hygiene lands."""
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "rule", "hygiene"]) == 3
    combined = capsys.readouterr()
    assert "not implemented yet" in (combined.out + combined.err).lower()


def test_tag_apply_previews_without_writing(env, tmp_path, capsys):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    assert cli.main(["--inventory", inv, "tag", "apply", str(csv_path)]) == 0
    assert "DRY RUN" in capsys.readouterr().out
    assert fakes[0].state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]


def test_tag_apply_writes_with_enable_writes_and_yes(env, tmp_path):
    inv, fakes = env(("lm", "lm1"))
    fakes[0].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = tmp_path / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    assert cli.main(["--inventory", inv, "tag", "apply", str(csv_path),
                     "--enable-writes", "--yes", "--non-interactive"]) == 0
    assert {t["tag"] for t in fakes[0].state.vms[0]["tags"]} == {"dev", "prod"}


def test_audit_undo_refuses_without_enable_writes(env, capsys):
    inv, _ = env(("lm", "lm1"))
    assert cli.main(["--inventory", inv, "audit", "undo"]) == 2
    assert "--enable-writes" in capsys.readouterr().err


def test_no_arguments_without_a_terminal_prints_help(tmp_path, monkeypatch,
                                                     capsys):
    monkeypatch.setattr(cli, "DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    from nsx_toolkit import output
    output.set_interactive(False)
    assert cli.main([]) == 2
    assert "usage: nsxctl" in capsys.readouterr().out
