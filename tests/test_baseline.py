"""Hit-count baselines, and the counter-reset trap they exist to avoid."""

import json

import pytest

from nsx_toolkit.baseline import (
    STATUS_ORDER,
    build_hit_baseline,
    compare_hit_baselines,
    hit_baseline_rows,
    hit_baseline_summary,
    load_hit_baseline,
    save_hit_baseline,
)
from nsx_toolkit.errors import NsxError
from nsx_toolkit.policy import sweep_rules


def snapshot(taken, rules):
    return {"taken": taken, "rules": {
        path: {"hit_count": hits, "policy": "P", "rule": path.rsplit("/", 1)[-1],
               "manager": "lm1"} for path, hits in rules.items()}}


def by_rule(results):
    return {r["rule"]: r for r in results}


def test_a_counter_that_did_not_move_is_unused_in_that_window():
    before = snapshot("T1", {"/r/quiet": 55})
    after = snapshot("T2", {"/r/quiet": 55})
    result = by_rule(compare_hit_baselines(before, after))["quiet"]
    assert result["status"] == "unused_since_baseline"
    assert result["delta"] == 0
    assert "T1" in result["detail"] and "T2" in result["detail"]


def test_a_counter_that_moved_is_active():
    before = snapshot("T1", {"/r/busy": 10})
    after = snapshot("T2", {"/r/busy": 40})
    result = by_rule(compare_hit_baselines(before, after))["busy"]
    assert result["status"] == "active"
    assert result["delta"] == 30


def test_a_counter_that_went_backwards_is_a_reset_not_unused():
    """The trap. Claiming no traffic when the evidence was wiped is how a
    live firewall rule gets deleted."""
    before = snapshot("T1", {"/r/reset": 900})
    after = snapshot("T2", {"/r/reset": 5})
    result = by_rule(compare_hit_baselines(before, after))["reset"]
    assert result["status"] == "counter_reset"
    assert result["status"] != "unused_since_baseline"
    assert "proves nothing" in result["detail"]


def test_a_counter_reset_to_exactly_zero_is_still_a_reset():
    before = snapshot("T1", {"/r/reset": 12})
    after = snapshot("T2", {"/r/reset": 0})
    assert by_rule(compare_hit_baselines(before, after))["reset"]["status"] \
        == "counter_reset"


def test_zero_in_both_reads_is_genuinely_unused():
    """Zero to zero did not go backwards, so the window is valid."""
    before = snapshot("T1", {"/r/quiet": 0})
    after = snapshot("T2", {"/r/quiet": 0})
    assert by_rule(compare_hit_baselines(before, after))["quiet"]["status"] \
        == "unused_since_baseline"


def test_a_new_rule_is_reported_as_added_not_unused():
    before = snapshot("T1", {})
    after = snapshot("T2", {"/r/fresh": 0})
    result = by_rule(compare_hit_baselines(before, after))["fresh"]
    assert result["status"] == "added"
    assert "did not exist" in result["detail"]


def test_a_deleted_rule_is_reported_as_removed():
    before = snapshot("T1", {"/r/gone": 3})
    after = snapshot("T2", {})
    assert by_rule(compare_hit_baselines(before, after))["gone"]["status"] \
        == "removed"


def test_missing_counters_are_unknown_not_zero():
    before = snapshot("T1", {"/r/x": None})
    after = snapshot("T2", {"/r/x": None})
    result = by_rule(compare_hit_baselines(before, after))["x"]
    assert result["status"] == "unknown"
    assert "unavailable" in result["detail"]


def test_results_are_ordered_worst_news_first():
    before = snapshot("T1", {"/r/a": 5, "/r/b": 5, "/r/c": 900})
    after = snapshot("T2", {"/r/a": 9, "/r/b": 5, "/r/c": 1})
    statuses = [r["status"] for r in compare_hit_baselines(before, after)]
    assert statuses[0] == "counter_reset"
    assert statuses.index("unused_since_baseline") < statuses.index("active")


def test_summary_counts_each_status():
    before = snapshot("T1", {"/r/a": 5, "/r/b": 5})
    after = snapshot("T2", {"/r/a": 9, "/r/b": 5})
    assert hit_baseline_summary(compare_hit_baselines(before, after)) == {
        "active": 1, "unused_since_baseline": 1}


def test_every_status_has_a_place_in_the_reporting_order():
    before = snapshot("T1", {"/r/a": 5, "/r/b": 5, "/r/c": 9, "/r/d": 1,
                             "/r/e": None})
    after = snapshot("T2", {"/r/a": 9, "/r/b": 5, "/r/c": 1, "/r/f": 1,
                            "/r/e": None})
    for result in compare_hit_baselines(before, after):
        assert result["status"] in STATUS_ORDER


def test_rows_are_exportable():
    before = snapshot("T1", {"/r/quiet": 5})
    after = snapshot("T2", {"/r/quiet": 5})
    rows = hit_baseline_rows(compare_hit_baselines(before, after))
    assert rows[0][0] == "unused_since_baseline"
    assert rows[0][3] == "quiet"
    assert rows[0][6] == "0"        # delta


# --- round trip against a live fake -------------------------------------
def test_build_and_save_round_trip(lm, make_session, tmp_path):
    lm.state.add_policy("p1", "Perimeter")
    lm.state.add_rule("p1", "r1")
    lm.state.add_rule("p1", "r2")
    lm.state.set_hit_count("p1", "r1", 42)
    session = make_session(lm)

    from nsx_toolkit.actions.hygiene import fetch_hit_counts
    records = sweep_rules([session], "default")
    stats, supported = fetch_hit_counts(records, "default")
    assert supported is True

    built = build_hit_baseline(records, stats, domain="default")
    assert built["rule_count"] == 2
    counters = {v["rule"]: v["hit_count"] for v in built["rules"].values()}
    assert counters["r1"] == 42
    assert counters["r2"] is None       # no statistics for that rule

    path = save_hit_baseline(built, str(tmp_path / "b.json"))
    reloaded = load_hit_baseline(path)
    assert reloaded["rules"] == built["rules"]


def test_loading_a_missing_baseline_is_a_clear_error(tmp_path):
    with pytest.raises(NsxError) as exc:
        load_hit_baseline(str(tmp_path / "nope.json"))
    assert "not found" in str(exc.value)


def test_loading_malformed_json_is_a_clear_error(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("{oops", encoding="utf-8")
    with pytest.raises(NsxError) as exc:
        load_hit_baseline(str(path))
    assert "not valid JSON" in str(exc.value)


def test_loading_the_wrong_kind_of_json_is_rejected(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"something": "else"}), encoding="utf-8")
    with pytest.raises(NsxError) as exc:
        load_hit_baseline(str(path))
    assert "does not look like a hit baseline" in str(exc.value)
