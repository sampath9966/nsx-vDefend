"""Minimal XLSX writer — stdlib only, no third-party dependencies.

XLSX is a ZIP archive of XML files. All cell values are stored as inline
strings (t="inlineStr"), which eliminates the need for a shared-strings table
and keeps the implementation self-contained.
"""
import re
import zipfile


def _xml_escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _col_letter(n):
    """0-based column index → Excel column letter (A, B, …, Z, AA, …)."""
    result = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        result = chr(65 + r) + result
    return result


def _cell_ref(row, col):
    """1-based row + 0-based col → 'A1' cell reference."""
    return "{}{}".format(_col_letter(col), row)


def _sheet_xml(headers, rows):
    """Build worksheet XML. Header row uses cell style 1 (bold)."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        "<sheetData>",
        '<row r="1">',
    ]
    for ci, h in enumerate(headers):
        lines.append('<c r="{}" t="inlineStr" s="1"><is><t>{}</t></is></c>'.format(
            _cell_ref(1, ci), _xml_escape(h)))
    lines.append("</row>")
    for ri, row in enumerate(rows, 2):
        lines.append('<row r="{}">'.format(ri))
        for ci, val in enumerate(row):
            lines.append('<c r="{}" t="inlineStr"><is><t>{}</t></is></c>'.format(
                _cell_ref(ri, ci), _xml_escape(val)))
        lines.append("</row>")
    lines += ["</sheetData>", "</worksheet>"]
    return "\n".join(lines)


def _safe_sheet_name(s, n):
    """Valid Excel sheet name: ≤31 chars, no []:*?/\\."""
    name = re.sub(r'[\[\]:*?/\\]', "_", str(s or "Sheet{}".format(n)))[:31]
    return name or "Sheet{}".format(n)


_STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2">'
    '<font><sz val="11"/></font>'
    '<font><b/><sz val="11"/></font>'
    '</fonts>'
    '<fills count="2">'
    '<fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '</fills>'
    '<borders count="1">'
    '<border><left/><right/><top/><bottom/><diagonal/></border>'
    '</borders>'
    '<cellStyleXfs count="1">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
    '</cellStyleXfs>'
    '<cellXfs count="2">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/>'
    '</cellXfs>'
    '</styleSheet>'
)


def write_xlsx(path, sheets):
    """Write an XLSX workbook.

    sheets: list of (name, headers, rows) where headers is list[str]
            and rows is list[list[str]].
    """
    sheet_names = [_safe_sheet_name(name, i + 1) for i, (name, _, _) in enumerate(sheets)]

    wb_sheets = "\n".join(
        '<sheet name="{}" sheetId="{}" r:id="rId{}"/>'.format(
            _xml_escape(n), i + 1, i + 1)
        for i, n in enumerate(sheet_names))
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook'
        ' xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets>{}</sheets>'
        '</workbook>'.format(wb_sheets))

    styles_rel_id = len(sheets) + 1
    wb_rels_entries = "\n".join(
        '<Relationship Id="rId{}"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
        ' Target="worksheets/sheet{}.xml"/>'.format(i + 1, i + 1)
        for i in range(len(sheets)))
    wb_rels_entries += (
        '\n<Relationship Id="rId{}"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"'
        ' Target="styles.xml"/>'.format(styles_rel_id))
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships'
        ' xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '{}'
        '</Relationships>'.format(wb_rels_entries))

    sheet_overrides = "".join(
        '<Override PartName="/xl/worksheets/sheet{}.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument'
        '.spreadsheetml.worksheet+xml"/>'.format(i + 1)
        for i in range(len(sheets)))
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels"'
        ' ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument'
        '.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument'
        '.spreadsheetml.styles+xml"/>'
        '{}'
        '</Types>'.format(sheet_overrides))

    dot_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships'
        ' xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1"'
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
        ' Target="xl/workbook.xml"/>'
        '</Relationships>')

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", dot_rels)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        zf.writestr("xl/styles.xml", _STYLES_XML)
        for i, (_, headers, rows) in enumerate(sheets):
            zf.writestr(
                "xl/worksheets/sheet{}.xml".format(i + 1),
                _sheet_xml(headers, rows))
