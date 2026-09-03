"""The HTML report must survive being emailed and opened offline."""

import re

from nsx_toolkit.report import write_report

SECTIONS = [("Findings", ["severity", "check", "confidence", "policy", "rule",
                          "detail"],
             [["critical", "any_any_allow", "provable", "Perimeter", "r1",
               "permits all traffic"],
              ["medium", "unused_rule", "soft", "App", "r2", "no hits"]])]


def render(tmp_path, **kwargs):
    kwargs.setdefault("sections", SECTIONS)
    path = write_report(str(tmp_path / "r.html"), "Report", **kwargs)
    return open(path, encoding="utf-8").read()


def test_report_is_entirely_self_contained(tmp_path):
    """No stylesheet, font, script or image fetched from anywhere."""
    body = render(tmp_path)
    assert re.search(r'(?:src|href)\s*=\s*["\']https?://', body) is None
    assert "<style>" in body        # styling is inline
    assert "<script" not in body


def test_report_contains_the_data(tmp_path):
    body = render(tmp_path)
    for text in ("any_any_allow", "Perimeter", "permits all traffic",
                 "unused_rule"):
        assert text in body


def test_severity_and_soft_findings_are_marked_up(tmp_path):
    body = render(tmp_path)
    assert 'class="sev sev-critical"' in body
    assert 'class="soft"' in body


def test_html_in_the_data_is_escaped(tmp_path):
    """Rule names come from NSX, so they are untrusted input for a document."""
    body = render(tmp_path, sections=[
        ("Findings", ["rule", "detail"],
         [["<script>alert(1)</script>", "a & b < c"]])])
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    assert "a &amp; b &lt; c" in body


def test_tiles_and_notes_render(tmp_path):
    body = render(tmp_path, notes=["Counters are cumulative."],
                  tiles=[("critical", 2), ("high", 0)])
    assert "Counters are cumulative." in body
    assert 'class="tile"' in body
    assert ">2<" in body


def test_an_empty_section_says_so_rather_than_rendering_a_bare_table(tmp_path):
    body = render(tmp_path, sections=[("Findings", ["a"], [])])
    assert "Nothing to report." in body
    assert "<tbody>" not in body


def test_short_rows_do_not_break_the_table(tmp_path):
    body = render(tmp_path, sections=[("F", ["a", "b", "c"], [["only"]])])
    assert body.count("<td") == 3


def test_report_creates_missing_directories(tmp_path):
    target = tmp_path / "deep" / "nested" / "r.html"
    path = write_report(str(target), "Report", sections=SECTIONS)
    assert open(path, encoding="utf-8").read().startswith("<!doctype html>")
