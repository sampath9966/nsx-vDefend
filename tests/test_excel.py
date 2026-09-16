"""Tests for the minimal XLSX writer and Exporter.to_xlsx()."""
import zipfile

from nsx_toolkit.excel import write_xlsx
from nsx_toolkit.export import Exporter


def test_write_xlsx_creates_zip(tmp_path):
    path = str(tmp_path / "out.xlsx")
    write_xlsx(path, [("Data", ["col1", "col2"], [["a", "b"], ["c", "d"]])])
    assert zipfile.is_zipfile(path)


def test_write_xlsx_sheet_names(tmp_path):
    path = str(tmp_path / "out.xlsx")
    write_xlsx(path, [("Sheet One", ["x"], [["1"]]), ("Sheet Two", ["y"], [["2"]])])
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    assert "xl/worksheets/sheet1.xml" in names
    assert "xl/worksheets/sheet2.xml" in names


def test_write_xlsx_cell_values(tmp_path):
    path = str(tmp_path / "out.xlsx")
    write_xlsx(path, [("Test", ["header"], [["hello world"], ["plain"]])])
    with zipfile.ZipFile(path) as zf:
        ws = zf.read("xl/worksheets/sheet1.xml").decode()
    assert "hello world" in ws
    assert "plain" in ws


def test_write_xlsx_xml_escaping(tmp_path):
    path = str(tmp_path / "out.xlsx")
    write_xlsx(path, [("T", ["h"], [["a & b"], ["<test>"]])])
    with zipfile.ZipFile(path) as zf:
        ws = zf.read("xl/worksheets/sheet1.xml").decode()
    assert "a &amp; b" in ws
    assert "&lt;test&gt;" in ws


def test_exporter_to_xlsx_single_set(tmp_path):
    exp = Exporter(export_dir=str(tmp_path))
    exp.stage("rules", ["name", "action"], [["r1", "ALLOW"], ["r2", "DROP"]])
    paths = exp.to_xlsx(str(tmp_path / "rules.xlsx"))
    assert len(paths) == 1
    assert zipfile.is_zipfile(paths[0])


def test_exporter_to_xlsx_multi_set_one_workbook(tmp_path):
    exp = Exporter(export_dir=str(tmp_path))
    exp.stage("rules", ["name"], [["r1"]])
    exp.stage("groups", ["name"], [["g1"]])
    out = str(tmp_path / "export.xlsx")
    paths = exp.to_xlsx(out)
    assert paths == [out]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    assert "xl/worksheets/sheet1.xml" in names
    assert "xl/worksheets/sheet2.xml" in names


def test_exporter_to_xlsx_empty_set_skipped(tmp_path):
    exp = Exporter(export_dir=str(tmp_path))
    exp.stage("empty", ["col"], [])
    exp.stage("data", ["col"], [["val"]])
    paths = exp.to_xlsx(str(tmp_path / "out.xlsx"))
    assert len(paths) == 1
    with zipfile.ZipFile(paths[0]) as zf:
        ws = zf.read("xl/worksheets/sheet1.xml").decode()
    assert "val" in ws
