"""Self-contained HTML reports.

Deliberately no external stylesheet, font or script: the file gets emailed as
an attachment or opened from a share, often on a machine with no network
route to the internet, so everything it needs is inline. It also has to print
sanely, because change boards print things.
"""

import html
import os

from .paths import utc_now_stamp
from .version import TOOL_NAME, VERSION

STYLE = """
:root {
  --ink: #1a1d21; --muted: #5b6570; --rule: #dfe3e8; --bg: #ffffff;
  --panel: #f6f8fa; --critical: #b3261e; --high: #a5590a;
  --medium: #7a6100; --low: #57606a; --ok: #1a7f37;
}
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; background: var(--bg); color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  Helvetica, Arial, sans-serif; }
.wrap { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 32px 0 10px; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--muted); }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
.meta code { background: var(--panel); padding: 1px 5px; border-radius: 3px; }
.notes { background: var(--panel); border-left: 3px solid var(--rule);
  padding: 12px 16px; margin: 0 0 24px; border-radius: 0 4px 4px 0; }
.notes p { margin: 0 0 6px; } .notes p:last-child { margin: 0; }
.tiles { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
.tile { border: 1px solid var(--rule); border-radius: 6px; padding: 12px 18px;
  min-width: 120px; }
.tile .n { font-size: 24px; font-weight: 600; line-height: 1.1; }
.tile .k { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em;
  color: var(--muted); margin-top: 2px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--rule);
  vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--muted); border-bottom: 2px solid var(--rule); white-space: nowrap; }
tbody tr:nth-child(even) { background: var(--panel); }
td.mono, th.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; }
.sev { font-weight: 600; text-transform: uppercase; font-size: 11px;
  letter-spacing: 0.05em; white-space: nowrap; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); }
.soft { color: var(--muted); font-size: 11px; }
.empty { color: var(--ok); font-weight: 600; }
footer { margin-top: 40px; padding-top: 14px; border-top: 1px solid var(--rule);
  color: var(--muted); font-size: 12px; }
@media print {
  body { padding: 0; font-size: 11px; }
  .tile { break-inside: avoid; } tr { break-inside: avoid; }
}
"""

SEVERITY_CLASSES = ("critical", "high", "medium", "low")


def _esc(value):
    return html.escape("" if value is None else str(value))


def _cell(column, value):
    text = _esc(value)
    if column == "severity" and value in SEVERITY_CLASSES:
        return '<td class="sev sev-{}">{}</td>'.format(value, text)
    if column == "confidence" and value == "soft":
        return '<td class="soft">soft</td>'
    if column in ("rule", "policy", "path", "manager"):
        return '<td class="mono">{}</td>'.format(text)
    return "<td>{}</td>".format(text)


def _table(headers, rows):
    if not rows:
        return '<p class="empty">Nothing to report.</p>'
    out = ['<div class="scroll"><table><thead><tr>']
    out.extend("<th>{}</th>".format(_esc(h.replace("_", " "))) for h in headers)
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for i, header in enumerate(headers):
            out.append(_cell(header, row[i] if i < len(row) else ""))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _tiles(counts):
    if not counts:
        return ""
    out = ['<div class="tiles">']
    for key, value in counts:
        out.append('<div class="tile"><div class="n">{}</div>'
                   '<div class="k">{}</div></div>'.format(
                       _esc(value), _esc(key)))
    out.append("</div>")
    return "".join(out)


def write_report(path, title, subtitle="", notes=(), tiles=(), sections=()):
    """Write a standalone HTML report.

    sections: iterable of (heading, headers, rows).
    tiles:    iterable of (label, value) summary counters.
    notes:    iterable of caveat strings shown before the data.
    """
    body = ['<div class="wrap">',
            "<h1>{}</h1>".format(_esc(title))]
    if subtitle:
        body.append('<div class="meta">{}</div>'.format(subtitle))
    if notes:
        body.append('<div class="notes">')
        body.extend("<p>{}</p>".format(_esc(n)) for n in notes)
        body.append("</div>")
    body.append(_tiles(list(tiles)))
    for heading, headers, rows in sections:
        body.append("<h2>{}</h2>".format(_esc(heading)))
        body.append(_table(headers, rows))
    body.append(
        "<footer>Generated by {} v{} &middot; {}</footer>".format(
            _esc(TOOL_NAME), _esc(VERSION), _esc(utc_now_stamp())))
    body.append("</div>")

    document = (
        "<!doctype html>\n<html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>{}</title><style>{}</style></head><body>{}</body></html>\n"
    ).format(_esc(title), STYLE, "".join(body))

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(document)
    return path
