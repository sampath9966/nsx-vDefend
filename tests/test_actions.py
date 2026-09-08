"""Dashboard, tag inspection, and audit undo."""

import pytest

from nsx_toolkit.actions.audit_view import act_audit_log
from nsx_toolkit.actions.dashboard import act_dashboard
from nsx_toolkit.actions.tags import act_vm_tags, act_vms_by_tag
from nsx_toolkit.audit import AuditLog
from nsx_toolkit.export import Exporter
from nsx_toolkit.taxonomy import Taxonomy


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=str(tmp_path / "audit.log"))


FULL = [("tenant", "acme"), ("app", "shop"), ("env", "prod"),
        ("tier", "web"), ("site", "lon"), ("server", "web1")]


def test_dashboard_classifies_complete_partial_and_untagged(lm, make_session):
    lm.state.add_vm("full1", tags=FULL)
    lm.state.add_vm("partial1", tags=[("env", "prod")])
    lm.state.add_vm("bare1")
    exp = Exporter()
    act_dashboard([make_session(lm)], exp, Taxonomy())
    status = {r[0]: r[5] for r in exp.sets[0].rows}
    assert status == {"full1": "complete", "partial1": "partial",
                      "bare1": "untagged"}


def test_dashboard_lists_the_missing_scopes(lm, make_session):
    lm.state.add_vm("partial1", tags=[("env", "prod"), ("app", "shop")])
    exp = Exporter()
    act_dashboard([make_session(lm)], exp, Taxonomy())
    missing = exp.sets[0].rows[0][4]
    assert "tenant" in missing and "server" in missing
    assert "env" not in missing


def test_dashboard_with_no_local_managers_stages_an_empty_set(gm, make_session):
    exp = Exporter()
    act_dashboard([make_session(gm)], exp, Taxonomy())
    assert exp.sets[0].rows == []


def test_vm_tags_exports_every_match_beyond_the_console_cap(lm, make_session):
    """The console shows the first 50; the export must carry all of them."""
    for i in range(60):
        lm.state.add_vm("web{:03d}".format(i), tags=[("env", "prod")])
    exp = Exporter()
    act_vm_tags([make_session(lm)], "web", exp, Taxonomy())
    assert len({r[1] for r in exp.sets[0].rows}) == 60


def test_vms_by_tag_filters_on_scope_and_value(lm, make_session):
    lm.state.add_vm("prod1", tags=[("env", "prod")])
    lm.state.add_vm("dev1", tags=[("env", "dev")])
    lm.state.add_vm("bare1")
    exp = Exporter()
    act_vms_by_tag([make_session(lm)], "env", "prod", exp)
    assert [r[1] for r in exp.sets[0].rows] == ["prod1"]


def test_vms_by_tag_matches_on_scope_alone(lm, make_session):
    lm.state.add_vm("a", tags=[("env", "prod")])
    lm.state.add_vm("b", tags=[("env", "dev")])
    lm.state.add_vm("c", tags=[("owner", "ops")])
    exp = Exporter()
    act_vms_by_tag([make_session(lm)], "env", "", exp)
    assert sorted(r[1] for r in exp.sets[0].rows) == ["a", "b"]


def test_audit_log_rotates_at_the_size_cap(tmp_path):
    log = AuditLog(path=str(tmp_path / "audit.log"), max_bytes=2000, keep=2)
    for i in range(200):
        log.log("update_tags", "lm1", "vm{}".format(i), "ext", [], [("env", "prod")])
    assert (tmp_path / "audit.log.1").exists()
    # Recent entries still read back from the live file.
    assert log.last_n(5)[-1]["vm_display_name"] == "vm199"


def test_audit_tail_read_returns_the_last_entries(tmp_path):
    log = AuditLog(path=str(tmp_path / "audit.log"))
    for i in range(50):
        log.log("update_tags", "lm1", "vm{}".format(i), "ext", [], [])
    names = [e["vm_display_name"] for e in log.last_n(3)]
    assert names == ["vm47", "vm48", "vm49"]


def test_audit_view_exports_added_and_removed(lm, make_session, audit):
    audit.log("update_tags", "lm1", "web1", "ext-web1",
              [("env", "dev")], [("env", "prod")])
    exp = Exporter()
    act_audit_log(audit, [make_session(lm)], write_enabled=False, exporter=exp)
    # The export gained an object_type column when the audit log grew to
    # cover groups and rules as well as tags, so index by header name rather
    # than by position.
    columns = dict(zip(exp.sets[0].headers, exp.sets[0].rows[0]))
    assert columns["object_type"] == "vm_tags"
    assert columns["object"] == "web1"
    assert columns["added"] == "env=prod"
    assert columns["removed"] == "env=dev"


def test_empty_audit_log_reads_cleanly(tmp_path, lm, make_session):
    log = AuditLog(path=str(tmp_path / "nothing.log"))
    exp = Exporter()
    act_audit_log(log, [make_session(lm)], write_enabled=False, exporter=exp)
    assert exp.sets[0].rows == []
