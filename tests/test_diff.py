"""The diff engine.

Two failure modes matter more than anything else here: reporting a change that
did not happen (nobody trusts the report), and missing one that did (worse).
The set-versus-sequence tests below are aimed squarely at both.
"""

from nsx_toolkit.diff import (
    COSMETIC_FIELDS,
    SET_LIKE_FIELDS,
    at_impact,
    diff_objects,
    diff_rows,
    diff_snapshots,
    summarise_diff,
)


def obj(oid, kind="rules", manager="lm1", **body):
    body.setdefault("id", oid)
    return {"kind": kind, "manager": manager, "body": body}


def snap(objects, provenance=None):
    return {"objects": objects, "provenance": provenance or {},
            "manifest": {"taken": "T"}}


def fields_named(changes, prefix):
    return [c for c in changes if c.field.startswith(prefix)]


# --- list handling: the subtle part --------------------------------------
def test_reordering_a_set_like_field_is_not_a_change():
    """NSX may return source_groups in any order. Reporting that as drift
    would fire on every run and train people to ignore the report."""
    for field in SET_LIKE_FIELDS:
        before = {field: ["/x/a", "/x/b", "/x/c"]}
        after = {field: ["/x/c", "/x/a", "/x/b"]}
        assert diff_objects(before, after) == [], field


def test_a_membership_change_reports_what_joined_and_what_left():
    changes = diff_objects({"services": ["/s/https", "/s/ssh"]},
                           {"services": ["/s/https", "/s/rdp"]})
    by_kind = {c.kind: c for c in changes}
    assert by_kind["added"].after == ["/s/rdp"]
    assert by_kind["removed"].before == ["/s/ssh"]


def test_reordering_an_expression_is_a_change():
    """Group criteria are Condition AND Condition -- order is meaning, and
    reordering them changes which workloads match."""
    a = {"expression": [{"resource_type": "Condition", "value": "env|prod"},
                        {"resource_type": "ConjunctionOperator",
                         "conjunction_operator": "AND"}]}
    b = {"expression": [{"resource_type": "ConjunctionOperator",
                         "conjunction_operator": "AND"},
                        {"resource_type": "Condition", "value": "env|prod"}]}
    assert fields_named(diff_objects(a, b), "expression")


def test_an_unchanged_expression_is_not_a_change():
    a = {"expression": [{"resource_type": "Condition", "value": "env|prod"}]}
    assert diff_objects(a, dict(a)) == []


def test_a_longer_list_reports_the_added_item():
    changes = diff_objects({"expression": [{"a": 1}]},
                           {"expression": [{"a": 1}, {"b": 2}]})
    assert changes[0].kind == "added"
    assert changes[0].field == "expression[1]"


def test_nested_dictionaries_are_walked():
    changes = diff_objects({"outer": {"inner": {"leaf": 1}}},
                           {"outer": {"inner": {"leaf": 2}}})
    assert changes[0].field == "outer.inner.leaf"
    assert (changes[0].before, changes[0].after) == (1, 2)


def test_an_added_or_removed_key_is_reported():
    changes = {c.field: c for c in diff_objects({"a": 1}, {"b": 2})}
    assert changes["a"].kind == "removed"
    assert changes["b"].kind == "added"


# --- classification -------------------------------------------------------
def test_only_naming_fields_are_cosmetic():
    assert COSMETIC_FIELDS == frozenset({"display_name", "description",
                                         "notes"})
    for field in COSMETIC_FIELDS:
        change = diff_objects({field: "old"}, {field: "new"})[0]
        assert change.impact == "cosmetic", field


def test_anything_touching_enforcement_is_security_relevant():
    for field in ("action", "source_groups", "destination_groups", "services",
                  "scope", "disabled", "direction", "logged", "expression"):
        before = {field: ["a"] if field.endswith("s") else "a"}
        after = {field: ["b"] if field.endswith("s") else "b"}
        change = diff_objects(before, after)[0]
        assert change.impact == "security", field


def test_an_unrecognised_field_defaults_to_security_relevant():
    """Conservative by design: a false 'security' costs a second look, a
    missed one costs an incident."""
    change = diff_objects({"some_future_nsx_field": 1},
                          {"some_future_nsx_field": 2})[0]
    assert change.impact == "security"


def test_nested_field_impact_comes_from_the_outermost_name():
    change = diff_objects(
        {"expression": [{"value": "a"}]},
        {"expression": [{"value": "b"}]})[0]
    assert change.field.startswith("expression")
    assert change.impact == "security"


# --- snapshot level -------------------------------------------------------
def test_added_removed_and_modified_are_detected_by_path():
    before = snap({"/r/keep": obj("keep", action="ALLOW"),
                   "/r/gone": obj("gone", action="ALLOW")})
    after = snap({"/r/keep": obj("keep", action="DROP"),
                  "/r/new": obj("new", action="ALLOW")})
    by_status = {c.status: c for c in diff_snapshots(before, after)}
    assert set(by_status) == {"added", "removed", "modified"}
    assert by_status["added"].name == "new"
    assert by_status["removed"].name == "gone"
    assert by_status["modified"].fields[0].field == "action"


def test_an_identical_snapshot_reports_no_changes():
    before = snap({"/r/1": obj("1", action="ALLOW")})
    assert diff_snapshots(before, snap({"/r/1": obj("1", action="ALLOW")})) == []


def test_a_renamed_object_is_matched_by_path_not_by_name():
    """People rename policies; that must read as a modification, not as one
    object vanishing and another appearing."""
    before = snap({"/p/1": obj("1", kind="policies", display_name="Old")})
    after = snap({"/p/1": obj("1", kind="policies", display_name="New")})
    changes = diff_snapshots(before, after)
    assert [c.status for c in changes] == ["modified"]
    assert changes[0].impact == "cosmetic"


def test_added_and_removed_objects_are_always_security_relevant():
    before = snap({"/r/gone": obj("gone", display_name="only a name")})
    after = snap({"/r/new": obj("new", display_name="only a name")})
    assert {c.impact for c in diff_snapshots(before, after)} == {"security"}


def test_security_changes_are_listed_before_cosmetic_ones():
    before = snap({"/p/1": obj("1", kind="policies", display_name="Old"),
                   "/r/1": obj("1", action="ALLOW")})
    after = snap({"/p/1": obj("1", kind="policies", display_name="New"),
                  "/r/1": obj("1", action="DROP")})
    assert [c.impact for c in diff_snapshots(before, after)] == [
        "security", "cosmetic"]


def test_who_changed_it_comes_from_the_after_provenance():
    before = snap({"/r/1": obj("1", action="ALLOW")})
    after = snap({"/r/1": obj("1", action="DROP")},
                 provenance={"/r/1": {"_last_modified_user": "dave",
                                      "_last_modified_time": 1700000060000}})
    change = diff_snapshots(before, after)[0]
    assert change.changed_by == "dave"
    assert change.changed_at == 1700000060000


def test_summary_counts_status_and_impact():
    before = snap({"/r/1": obj("1", action="ALLOW"),
                   "/r/2": obj("2", action="ALLOW")})
    after = snap({"/r/1": obj("1", action="DROP"),
                  "/r/3": obj("3", action="ALLOW")})
    counts = summarise_diff(diff_snapshots(before, after))
    assert counts["added"] == 1
    assert counts["removed"] == 1
    assert counts["modified"] == 1
    assert counts["security"] == 3


# --- export and gating ----------------------------------------------------
def test_rows_carry_one_line_per_changed_field():
    before = snap({"/r/1": obj("1", action="ALLOW", display_name="x")})
    after = snap({"/r/1": obj("1", action="DROP", display_name="y")})
    rows = diff_rows(diff_snapshots(before, after))
    assert len(rows) == 2
    assert {row[5] for row in rows} == {"action", "display_name"}
    assert {row[1] for row in rows} == {"security", "cosmetic"}


def test_added_objects_get_a_row_even_with_no_field_changes():
    rows = diff_rows(diff_snapshots(snap({}), snap({"/r/1": obj("1")})))
    assert len(rows) == 1
    assert rows[0][0] == "added"


def test_fail_on_drift_levels():
    before = snap({"/p/1": obj("1", kind="policies", display_name="Old")})
    after = snap({"/p/1": obj("1", kind="policies", display_name="New")})
    changes = diff_snapshots(before, after)
    assert at_impact(changes, "any") == changes
    assert at_impact(changes, "security") == []       # only a rename
    assert at_impact(changes, "nonsense") == []
