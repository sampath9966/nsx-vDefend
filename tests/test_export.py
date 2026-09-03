"""Exporter: multiple result sets, and no silent data loss."""

import csv
import json

from nsx_toolkit.export import Exporter


def test_two_actions_in_one_run_both_reach_disk(tmp_path):
    """Staging used to overwrite, so --groups --dashboard --out-csv wrote only
    the dashboard and silently dropped the groups."""
    e = Exporter(str(tmp_path))
    e.stage("groups", ["a"], [["g1"], ["g2"]])
    e.stage("dashboard", ["b"], [["d1"]])
    written = e.to_csv(str(tmp_path / "out.csv"))
    assert len(written) == 2
    names = sorted(p.split("/")[-1] for p in written)
    assert names == ["out_dashboard.csv", "out_groups.csv"]


def test_single_set_uses_the_exact_path_given(tmp_path):
    e = Exporter(str(tmp_path))
    e.stage("groups", ["a"], [["g1"]])
    target = str(tmp_path / "out.csv")
    assert e.to_csv(target) == [target]


def test_csv_content_round_trips(tmp_path):
    e = Exporter(str(tmp_path))
    e.stage("vm_tags", ["vm", "scope", "tag"], [["web1", "env", "prod"]])
    path = e.to_csv(str(tmp_path / "t.csv"))[0]
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows == [{"vm": "web1", "scope": "env", "tag": "prod"}]


def test_multiple_sets_share_one_json_file(tmp_path):
    e = Exporter(str(tmp_path))
    e.stage("groups", ["a"], [["g1"]])
    e.stage("dashboard", ["b"], [["d1"]])
    path = e.to_json(str(tmp_path / "out.json"))[0]
    payload = json.loads(open(path, encoding="utf-8").read())
    assert [r["label"] for r in payload["results"]] == ["groups", "dashboard"]


def test_empty_sets_are_recorded_for_json_but_not_written_as_files(tmp_path):
    e = Exporter(str(tmp_path))
    e.stage("groups", ["a"], [])
    assert e.has_staged() is False
    assert e.to_csv(str(tmp_path / "out.csv")) == []
    # --json still reports that the action ran and found nothing.
    assert e.json_payload() == [{"label": "groups", "count": 0, "records": []}]


def test_rows_shorter_than_headers_are_padded(tmp_path):
    e = Exporter(str(tmp_path))
    e.stage("x", ["a", "b", "c"], [["1"]])
    assert e.json_payload()[0]["records"] == [{"a": "1", "b": "", "c": ""}]
