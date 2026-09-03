"""End-to-end: the actual downloadable file, as a subprocess, against a
running fake NSX. Nothing here imports the package -- this is what a user
gets."""

import json
import os
import subprocess
import sys

import pytest
from fake_nsx import FakeNsx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINGLE = os.path.join(ROOT, "nsx-toolkit.py")


@pytest.fixture
def deployment(tmp_path):
    """A GM plus two LMs, an inventory, and an environment with credentials."""
    gm = FakeNsx(role="gm", name="gm").start()
    lm1 = FakeNsx(role="lm", name="lm-london").start()
    lm2 = FakeNsx(role="lm", name="lm-frankfurt").start()
    fakes = [gm, lm1, lm2]

    inv = tmp_path / "inventory.json"
    inv.write_text(json.dumps({"managers": [f.entry() for f in fakes]}),
                   encoding="utf-8")

    env = dict(os.environ)
    env.update({
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
        "FAKE_USER": "svc-nsx",
        "FAKE_PASS": "secret",
        "NSX_TOOLKIT_CREDENTIALS_FILE": str(tmp_path / "creds.env"),
        "NO_COLOR": "1",
    })
    try:
        yield {"inv": str(inv), "env": env, "gm": gm, "lm1": lm1, "lm2": lm2,
               "tmp": tmp_path}
    finally:
        for f in fakes:
            f.stop()


def run(deployment, *args, expect=0):
    result = subprocess.run(
        [sys.executable, SINGLE, "--inventory", deployment["inv"],
         "--non-interactive", *args],
        capture_output=True, text=True, cwd=str(deployment["tmp"]),
        env=deployment["env"])
    assert result.returncode == expect, (
        "exit {}\nSTDOUT:\n{}\nSTDERR:\n{}".format(
            result.returncode, result.stdout, result.stderr))
    return result


def test_verify_reaches_gm_and_both_lms(deployment):
    deployment["gm"].state.add_group("gg1")
    deployment["gm"].state.add_policy("gpol")
    for key in ("lm1", "lm2"):
        deployment[key].state.add_group("lg1")
        deployment[key].state.add_policy("lpol")
        deployment[key].state.add_vm("web1")
    out = run(deployment, "status").stdout
    for name in ("gm", "lm-london", "lm-frankfurt"):
        assert name in out
    assert "Failures detected" not in out


def test_dashboard_json_aggregates_across_both_lms(deployment):
    deployment["lm1"].state.add_vm("lon-web1", tags=[("env", "prod")])
    deployment["lm2"].state.add_vm("fra-web1", tags=[("env", "prod")])
    payload = json.loads(run(deployment, "compliance", "--json").stdout)
    records = next(r for r in payload["results"]
                   if r["label"] == "dashboard")["records"]
    assert {r["vm_name"] for r in records} == {"lon-web1", "fra-web1"}
    assert {r["manager"] for r in records} == {"lm-london", "lm-frankfurt"}


def test_full_bulk_workflow_dry_run_then_apply(deployment):
    lm = deployment["lm1"]
    lm.state.add_vm("web-prod-01", tags=[("env", "dev")])
    lm.state.add_vm("db-prod-01")
    csv_path = deployment["tmp"] / "changes.csv"
    csv_path.write_text(
        "vm_name,scope,tag,action\n"
        "web-prod-01,env,prod,add\n"
        "web-prod-01,env,dev,remove\n"
        "db-prod-01,tier,db,add\n", encoding="utf-8")

    preview = run(deployment, "tag", "apply", str(csv_path), "--dry-run").stdout
    assert "DRY RUN" in preview
    assert "+ env=prod" in preview
    assert lm.state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]

    run(deployment, "tag", "apply", str(csv_path), "--enable-writes", "--yes")
    tags = {v["display_name"]: {t["tag"] for t in v["tags"]} for v in lm.state.vms}
    assert tags["web-prod-01"] == {"prod"}
    assert tags["db-prod-01"] == {"db"}

    # And the write is in the audit log the tool wrote to $HOME.
    audit = deployment["tmp"] / ".nsx_toolkit" / "audit.log"
    entries = [json.loads(ln) for ln in audit.read_text().splitlines() if ln.strip()]
    assert {e["vm_display_name"] for e in entries} == {"web-prod-01", "db-prod-01"}


def test_reverse_lookup_dedupes_a_gm_rule_across_two_lms(deployment):
    gpath = "/global-infra/domains/default/groups/gg1"
    for key in ("gm", "lm1", "lm2"):
        st = deployment[key].state
        st.add_group("gg1", "Global Web", origin="GM")
        st.add_policy("gpol", "Global Policy", origin="GM")
        st.add_rule("gpol", "grule", source_groups=[gpath], origin="GM",
                    display_name="Allow Web")
    vm = deployment["lm1"].state.add_vm("web1")
    deployment["lm1"].state.associate(vm, deployment["lm1"].state.groups[0])

    payload = json.loads(run(deployment, "impact", "web1", "--json").stdout)
    rows = next(r for r in payload["results"]
                if r["label"] == "reverse_lookup")
    assert rows["count"] == 1, "a GM rule must not be reported once per LM"
    assert rows["records"][0]["manager"] == "gm"


def test_write_without_yes_is_refused(deployment):
    lm = deployment["lm1"]
    lm.state.add_vm("web1", tags=[("env", "dev")])
    csv_path = deployment["tmp"] / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    result = run(deployment, "tag", "apply", str(csv_path), "--enable-writes")
    assert "Refusing to" in result.stderr
    assert lm.state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]


def test_debug_traces_requests_to_stderr_only(deployment):
    deployment["lm1"].state.add_vm("web1")
    result = run(deployment, "compliance", "--json", "--debug")
    json.loads(result.stdout)      # stdout stays a clean envelope
    assert "GET http://" in result.stderr
    assert "/api/v1/fabric/virtual-machines" in result.stderr


def test_retry_recovers_from_a_transient_failure(deployment):
    deployment["lm1"].state.add_vm("web1", tags=[("env", "prod")])
    deployment["lm2"].state.add_vm("web2", tags=[("env", "prod")])
    deployment["lm1"].state.fail_next("/api/v1/fabric/virtual-machines", times=2)
    payload = json.loads(run(deployment, "compliance", "--json").stdout)
    records = next(r for r in payload["results"]
                   if r["label"] == "dashboard")["records"]
    assert len(records) == 2


@pytest.fixture
def no_requests(tmp_path):
    """A PYTHONPATH entry that makes `import requests` fail, so the stdlib
    transport is genuinely exercised rather than assumed."""
    blocker = tmp_path / "blocker"
    blocker.mkdir()
    (blocker / "sitecustomize.py").write_text(
        "import sys\n"
        "class _Block:\n"
        "    def find_module(self, name, path=None):\n"
        "        return self if name == 'requests' else None\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'requests':\n"
        "            raise ImportError('blocked for testing')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n", encoding="utf-8")
    return str(blocker)


def test_everything_works_with_no_third_party_packages(deployment, no_requests):
    """The promise on the front page: download one file, run it, no install."""
    deployment["env"]["PYTHONPATH"] = no_requests
    lm = deployment["lm1"]
    lm.state.add_vm("web1", tags=[("env", "prod")])
    lm.state.add_vm("db1")
    group = lm.state.add_group("g1", "Web Group")
    lm.state.associate(lm.state.vms[0], group)
    lm.state.add_policy("pol1")
    lm.state.add_rule("pol1", "r1", source_groups=[group["path"]])

    assert "transport=urllib" in run(deployment, "status").stdout

    payload = json.loads(run(deployment, "compliance", "--json").stdout)
    statuses = {r["vm_name"]: r["status"] for r in
                next(x for x in payload["results"]
                     if x["label"] == "dashboard")["records"]}
    assert statuses == {"web1": "partial", "db1": "untagged"}

    reverse = json.loads(run(deployment, "impact", "web1", "--json").stdout)
    assert next(x for x in reverse["results"]
                if x["label"] == "reverse_lookup")["count"] == 1

    csv_path = deployment["tmp"] / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\ndb1,tier,db,add\n",
                        encoding="utf-8")
    run(deployment, "tag", "apply", str(csv_path), "--enable-writes", "--yes")
    tags = {v["display_name"]: [t["tag"] for t in v["tags"]] for v in lm.state.vms}
    assert tags["db1"] == ["db"]


def test_change_plan_is_written_to_the_change_plans_directory(deployment):
    deployment["lm1"].state.add_vm("web1", tags=[("env", "dev")])
    csv_path = deployment["tmp"] / "c.csv"
    csv_path.write_text("vm_name,scope,tag,action\nweb1,env,prod,add\n",
                        encoding="utf-8")
    run(deployment, "tag", "ticket", str(csv_path))
    plans = list((deployment["tmp"] / "nsxtoolkit" / "change_plans").glob("*.txt"))
    assert len(plans) == 1
    body = plans[0].read_text(encoding="utf-8")
    assert "current : env=dev" in body
    # 'add' does not imply 'replace': NSX scopes are not unique keys, so both
    # tags are proposed unless the CSV also asks for a remove.
    assert "proposed: env=dev, env=prod" in body
    assert "+ env=prod" in body


def test_list_managers_and_audit_log_run_cleanly(deployment):
    out = run(deployment, "managers").stdout
    for name in ("gm", "lm-london", "lm-frankfurt"):
        assert name in out
    assert run(deployment, "audit", "list").returncode == 0
