"""Bulk tagging: planning, scale, and write safety."""

import pytest

from nsx_toolkit.actions.bulk import act_bulk_tag, plan_bulk, read_bulk_csv
from nsx_toolkit.audit import AuditLog
from nsx_toolkit.taxonomy import Taxonomy


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=str(tmp_path / "audit.log"))


def write_csv(tmp_path, rows, header="vm_name,scope,tag,action"):
    p = tmp_path / "changes.csv"
    p.write_text("\n".join([header] + rows) + "\n", encoding="utf-8")
    return str(p)


def test_rejects_csv_missing_required_columns(tmp_path):
    p = write_csv(tmp_path, ["web1,env,prod"], header="vm_name,scope,tag")
    with pytest.raises(Exception) as exc:
        read_bulk_csv(p)
    assert "action" in str(exc.value)


def test_reports_bad_rows_without_discarding_good_ones(tmp_path):
    p = write_csv(tmp_path, [
        "web1,env,prod,add",
        "web2,env,prod,frobnicate",
        ",env,prod,add",
        "web3,env,prod,remove",
    ])
    rows, problems = read_bulk_csv(p)
    assert [r["vm_name"] for r in rows] == ["web1", "web3"]
    assert len(problems) == 2


def test_plan_computes_adds_and_removes(lm, make_session, tmp_path):
    lm.state.add_vm("web1", tags=[("env", "dev"), ("tier", "web")])
    s = make_session(lm)
    rows, _ = read_bulk_csv(write_csv(tmp_path, [
        "web1,env,prod,add",
        "web1,env,dev,remove",
    ]))
    plan, unresolved, ambiguous = plan_bulk([s], rows)
    assert not unresolved and not ambiguous
    assert plan[0]["added"] == [("env", "prod")]
    assert plan[0]["removed"] == [("env", "dev")]
    assert plan[0]["after"] == [("env", "prod"), ("tier", "web")]


def test_index_is_built_once_regardless_of_row_count(lm, make_session, tmp_path):
    """The regression test for the O(rows x managers) inventory sweep.

    Resolving 200 rows previously triggered up to 200 full inventory fetches
    per manager; it must now be exactly one.
    """
    for i in range(200):
        lm.state.add_vm("web{:03d}".format(i))
    s = make_session(lm)
    rows, _ = read_bulk_csv(write_csv(tmp_path, [
        "web{:03d},env,prod,add".format(i) for i in range(200)]))
    plan, unresolved, _ = plan_bulk([s], rows)
    assert len(plan) == 200
    assert not unresolved
    assert lm.state.count("GET /api/v1/fabric/virtual-machines") == 1


def test_dry_run_writes_nothing(lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1", tags=[("env", "dev")])
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,prod,add"])
    result = act_bulk_tag([s], p, audit, write_enabled=True, dry_run=True)
    assert result["applied"] == 1
    assert lm.state.vms[0]["tags"] == [{"scope": "env", "tag": "dev"}]


def test_apply_matches_the_dry_run_plan(lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1", tags=[("env", "dev")])
    lm.state.add_vm("web2")
    s = make_session(lm)
    p = write_csv(tmp_path, [
        "web1,env,prod,add", "web1,env,dev,remove", "web2,tier,web,add"])

    preview = act_bulk_tag([s], p, audit, write_enabled=True, dry_run=True)
    s.invalidate_vms()
    applied = act_bulk_tag([s], p, audit, write_enabled=True, dry_run=False)

    assert preview["applied"] == applied["applied"] == 2
    assert applied["failed"] == 0
    by_name = {v["display_name"]: v["tags"] for v in lm.state.vms}
    assert by_name["web1"] == [{"scope": "env", "tag": "prod"}]
    assert by_name["web2"] == [{"scope": "tier", "tag": "web"}]


def test_apply_is_blocked_when_writes_are_disabled(lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1")
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,prod,add"])
    result = act_bulk_tag([s], p, audit, write_enabled=False, dry_run=False)
    assert result["applied"] == 0
    assert lm.state.vms[0]["tags"] == []


def test_concurrent_change_is_detected_not_clobbered(
        lm, make_session, tmp_path, audit, monkeypatch):
    """Another operator's edit between plan and write must fail the row."""
    vm = lm.state.add_vm("web1", tags=[("env", "dev")])
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,prod,add"])
    rows, _ = read_bulk_csv(p)
    plan, _, _ = plan_bulk([s], rows)

    # Someone else retags the VM after the plan was computed.
    vm["tags"] = [{"scope": "env", "tag": "uat"}, {"scope": "owner", "tag": "ops"}]
    s.invalidate_vms()

    from nsx_toolkit.actions.bulk import _write_row
    from nsx_toolkit.errors import NsxError
    with pytest.raises(NsxError) as exc:
        _write_row(plan[0], audit, force=False)
    assert "changed on NSX" in str(exc.value)
    assert vm["tags"] == [{"scope": "env", "tag": "uat"},
                          {"scope": "owner", "tag": "ops"}]


def test_force_overrides_the_concurrency_check(
        lm, make_session, tmp_path, audit):
    vm = lm.state.add_vm("web1", tags=[("env", "dev")])
    s = make_session(lm)
    rows, _ = read_bulk_csv(write_csv(tmp_path, ["web1,env,prod,add"]))
    plan, _, _ = plan_bulk([s], rows)
    vm["tags"] = [{"scope": "env", "tag": "uat"}]
    s.invalidate_vms()

    from nsx_toolkit.actions.bulk import _write_row
    _write_row(plan[0], audit, force=True)
    assert {t["tag"] for t in vm["tags"]} == {"dev", "prod"}


def test_unresolved_vm_is_reported_not_silently_skipped(
        lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1")
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,prod,add", "ghost,env,prod,add"])
    result = act_bulk_tag([s], p, audit, write_enabled=True, dry_run=True)
    assert result["unresolved"] == 1
    assert result["applied"] == 1


def test_same_name_on_two_managers_is_ambiguous(make_session, tmp_path, audit):
    from fake_nsx import FakeNsx
    with FakeNsx(role="lm", name="lm1") as a, FakeNsx(role="lm", name="lm2") as b:
        a.state.add_vm("web1")
        b.state.add_vm("web1")
        sa, sb = make_session(a), make_session(b)
        rows, _ = read_bulk_csv(write_csv(tmp_path, ["web1,env,prod,add"]))
        plan, unresolved, ambiguous = plan_bulk([sa, sb], rows)
        assert plan == [] and not unresolved
        assert ambiguous[0][0] == "web1"
        assert sorted(ambiguous[0][1]) == ["lm1", "lm2"]


def test_audit_log_records_before_and_after(lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1", tags=[("env", "dev")])
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,prod,add"])
    act_bulk_tag([s], p, audit, write_enabled=True, dry_run=False)
    entries = audit.last_n(5)
    assert entries[-1]["vm_display_name"] == "web1"
    assert entries[-1]["tags_before"] == [{"scope": "env", "tag": "dev"}]
    assert {t["tag"] for t in entries[-1]["tags_after"]} == {"dev", "prod"}


def test_taxonomy_warnings_do_not_block_the_plan(lm, make_session, tmp_path, audit):
    lm.state.add_vm("web1")
    s = make_session(lm)
    p = write_csv(tmp_path, ["web1,env,banana,add"])
    result = act_bulk_tag([s], p, audit, write_enabled=True, dry_run=True,
                          taxonomy=Taxonomy())
    assert result["applied"] == 1
