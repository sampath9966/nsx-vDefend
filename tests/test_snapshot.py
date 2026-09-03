"""Configuration snapshots.

The first test is the one the whole feature rests on. If snapshots of an
unchanged NSX are not identical, every drift report is noise and nobody will
run it twice.
"""

import json
import os

import pytest

from nsx_toolkit.errors import NsxError
from nsx_toolkit.snapshot import (
    PROVENANCE_FIELDS,
    VOLATILE_FIELDS,
    capture_snapshot,
    list_snapshots,
    load_snapshot,
    normalise_object,
    resolve_snapshot,
    save_snapshot,
)

VM_CRITERIA = [{"resource_type": "Condition", "member_type": "VirtualMachine",
                "key": "Tag", "operator": "EQUALS", "value": "env|prod"}]
IP_CRITERIA = [{"resource_type": "IPAddressExpression",
                "ip_addresses": ["10.0.0.0/8"]}]


@pytest.fixture
def estate(lm):
    group = lm.state.add_group("g-web", "Web", expression=VM_CRITERIA)
    lm.state.group_members["g-web"] = [{"display_name": "web1", "id": "1"}]
    lm.state.add_policy("p1", "Perimeter")
    lm.state.add_rule("p1", "https", source_groups=[group["path"]],
                      destination_groups=[group["path"]],
                      scope=[group["path"]], sequence_number=10)
    lm.state.add_rule("p1", "ssh", source_groups=[group["path"]],
                      destination_groups=[group["path"]],
                      scope=[group["path"]], action="DROP",
                      sequence_number=20)
    return lm, group


def tree_contents(root):
    """Every file in a snapshot except the manifest, which carries the
    capture time and is expected to differ."""
    out = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            if name == "manifest.json":
                continue
            full = os.path.join(dirpath, name)
            out[os.path.relpath(full, root)] = open(full, encoding="utf-8").read()
    return out


# --- the load-bearing test ----------------------------------------------
def test_an_unchanged_nsx_snapshots_identically(estate, make_session, tmp_path):
    """A revision bump and a modified timestamp must produce a byte-identical
    tree. Everything else here is worthless if this fails."""
    lm, _ = estate
    session = make_session(lm)

    first = save_snapshot(capture_snapshot([session], "default"), "a",
                          root_dir=str(tmp_path))
    lm.state.touch("rule", "https", pid="p1")     # revision + timestamp only
    lm.state.touch("group", "g-web")
    second = save_snapshot(capture_snapshot([session], "default"), "b",
                           root_dir=str(tmp_path))

    assert tree_contents(first) == tree_contents(second)


def test_object_files_contain_no_volatile_fields(estate, make_session, tmp_path):
    """Volatile fields in the git-diffable artifact would make every diff
    noisy -- provenance rides in the manifest instead."""
    lm, _ = estate
    root = save_snapshot(
        capture_snapshot([make_session(lm)], "default"), "a",
        root_dir=str(tmp_path))
    for relative, body in tree_contents(root).items():
        payload = json.loads(body)
        leaked = VOLATILE_FIELDS & set(payload)
        assert not leaked, "{} leaked {}".format(relative, leaked)
        assert "_provenance" not in payload


def test_provenance_is_kept_in_the_manifest(estate, make_session, tmp_path):
    lm, _ = estate
    lm.state.touch("rule", "https", pid="p1", user="dave")
    root = save_snapshot(
        capture_snapshot([make_session(lm)], "default"), "a",
        root_dir=str(tmp_path))
    manifest = json.loads(
        open(os.path.join(root, "manifest.json"), encoding="utf-8").read())
    provenance = [meta.get("provenance") for meta in manifest["paths"].values()
                  if meta.get("provenance")]
    assert any(p.get("_last_modified_user") == "dave" for p in provenance)


# --- normalisation --------------------------------------------------------
def test_normalise_strips_volatile_and_returns_provenance():
    body, provenance = normalise_object({
        "id": "r1", "action": "ALLOW",
        "_revision": 7, "_last_modified_user": "dave",
        "_last_modified_time": 123, "realization_id": "abc",
    })
    assert body == {"id": "r1", "action": "ALLOW"}
    assert provenance["_last_modified_user"] == "dave"
    assert provenance["_revision"] == 7


def test_normalise_strips_nested_volatile_fields():
    body, _ = normalise_object({
        "id": "g1",
        "expression": [{"resource_type": "Condition", "value": "x",
                        "_revision": 3}],
    })
    assert body["expression"] == [{"resource_type": "Condition", "value": "x"}]


def test_resource_type_survives_normalisation():
    """It looks like metadata, but inside an expression it is the
    discriminator that tells a Condition from an IPAddressExpression."""
    body, _ = normalise_object({"expression": IP_CRITERIA})
    assert body["expression"][0]["resource_type"] == "IPAddressExpression"
    assert "resource_type" not in VOLATILE_FIELDS


def test_every_provenance_field_is_also_volatile():
    """Provenance is reported but never compared -- so each of those fields
    must also be stripped from the body."""
    assert set(PROVENANCE_FIELDS) <= VOLATILE_FIELDS


# --- capture --------------------------------------------------------------
def test_capture_records_groups_policies_and_rules(estate, make_session):
    lm, _ = estate
    snapshot = capture_snapshot([make_session(lm)], "default")
    counts = snapshot["manifest"]["counts"]
    assert counts["groups"] == 1
    assert counts["policies"] == 1
    assert counts["rules"] == 2
    assert counts["tags"] == 0


def test_evaluation_order_lives_on_the_policy(estate, make_session):
    """Rule files are named by id, so a reorder is one change on the policy
    rather than N deletes plus N adds."""
    lm, _ = estate
    snapshot = capture_snapshot([make_session(lm)], "default")
    policy = next(e["body"] for e in snapshot["objects"].values()
                  if e["kind"] == "policies")
    assert policy["order"] == ["https", "ssh"]


def test_tags_are_excluded_unless_asked_for(estate, make_session):
    lm, _ = estate
    lm.state.add_vm("web1", tags=[("env", "prod")])
    without = capture_snapshot([make_session(lm)], "default")
    assert without["manifest"]["counts"]["tags"] == 0
    with_tags = capture_snapshot([make_session(lm)], "default", with_tags=True)
    assert with_tags["manifest"]["counts"]["tags"] == 1
    assert with_tags["manifest"]["with_tags"] is True


def test_a_gm_rule_realized_on_two_lms_is_captured_once(make_session):
    from fake_nsx import FakeNsx
    with FakeNsx(role="gm", name="gm") as gm, \
            FakeNsx(role="lm", name="lm1") as lm1, \
            FakeNsx(role="lm", name="lm2") as lm2:
        for fake in (gm, lm1, lm2):
            fake.state.add_policy("gpol", origin="GM")
            fake.state.add_rule("gpol", "grule", origin="GM")
        snapshot = capture_snapshot(
            [make_session(gm), make_session(lm1), make_session(lm2)],
            "default")
        assert snapshot["manifest"]["counts"]["rules"] == 1
        rule = next(e for e in snapshot["objects"].values()
                    if e["kind"] == "rules")
        assert rule["manager"] == "gm"


# --- storage --------------------------------------------------------------
def test_round_trip_preserves_bodies_and_provenance(estate, make_session,
                                                    tmp_path):
    lm, _ = estate
    lm.state.touch("rule", "ssh", pid="p1", user="carol")
    original = capture_snapshot([make_session(lm)], "default")
    root = save_snapshot(original, "a", root_dir=str(tmp_path))
    reloaded = load_snapshot(root)
    assert reloaded["objects"] == original["objects"]
    assert reloaded["provenance"] == original["provenance"]


def test_the_tree_layout_is_predictable(estate, make_session, tmp_path):
    lm, _ = estate
    root = save_snapshot(capture_snapshot([make_session(lm)], "default"), "a",
                         root_dir=str(tmp_path))
    files = set(tree_contents(root))
    assert "groups/lm1/g-web.json" in files
    assert os.path.join("policies", "lm1", "p1", "_policy.json") in files
    assert os.path.join("policies", "lm1", "p1", "rules", "https.json") in files


def test_files_are_sorted_and_newline_terminated(estate, make_session,
                                                 tmp_path):
    """Both are what make `git diff` on the tree readable."""
    lm, _ = estate
    root = save_snapshot(capture_snapshot([make_session(lm)], "default"), "a",
                         root_dir=str(tmp_path))
    body = open(os.path.join(root, "groups", "lm1", "g-web.json"),
                encoding="utf-8").read()
    assert body.endswith("\n")
    keys = [line.split('"')[1] for line in body.splitlines()
            if line.startswith('  "')]
    assert keys == sorted(keys)


def test_listing_is_newest_first(estate, make_session, tmp_path):
    lm, _ = estate
    session = make_session(lm)
    save_snapshot(capture_snapshot([session], "default"), "older",
                  root_dir=str(tmp_path))
    later = capture_snapshot([session], "default")
    later["manifest"]["taken"] = "2999-01-01T00:00:00Z"
    save_snapshot(later, "newer", root_dir=str(tmp_path))
    assert [item["name"] for item in list_snapshots(str(tmp_path))] == [
        "newer", "older"]


def test_resolve_falls_back_to_the_newest_snapshot(estate, make_session,
                                                   tmp_path):
    lm, _ = estate
    save_snapshot(capture_snapshot([make_session(lm)], "default"), "only",
                  root_dir=str(tmp_path))
    assert resolve_snapshot(None, str(tmp_path)).endswith("only")
    assert resolve_snapshot("only", str(tmp_path)).endswith("only")


def test_resolving_a_missing_snapshot_says_so(tmp_path):
    with pytest.raises(NsxError) as exc:
        resolve_snapshot("nope", str(tmp_path))
    assert "No snapshot named" in str(exc.value)


def test_resolving_with_no_snapshots_suggests_taking_one(tmp_path):
    with pytest.raises(NsxError) as exc:
        resolve_snapshot(None, str(tmp_path))
    assert "snapshot save" in str(exc.value)


def test_loading_a_directory_that_is_not_a_snapshot_is_rejected(tmp_path):
    with pytest.raises(NsxError) as exc:
        load_snapshot(str(tmp_path))
    assert "not a snapshot" in str(exc.value)


def test_a_truncated_snapshot_is_reported_not_silently_partial(
        estate, make_session, tmp_path):
    lm, _ = estate
    root = save_snapshot(capture_snapshot([make_session(lm)], "default"), "a",
                         root_dir=str(tmp_path))
    os.remove(os.path.join(root, "groups", "lm1", "g-web.json"))
    with pytest.raises(NsxError) as exc:
        load_snapshot(root)
    assert "incomplete" in str(exc.value)
