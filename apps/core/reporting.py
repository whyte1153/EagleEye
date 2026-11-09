"""Shared report document model and renderers (HTML / JSON / PDF).  Pure Python: no Django imports.

A report is a plain dict::

    {"title": str, "subtitle": str, "generated_at": str, "generated_by": str,
     "meta": [(label, value), ...],
     "sections": [{"heading": str, "paragraphs": [str], "kv": [(label, value)], "bullets": [str],
                   "table": {"columns": [str], "rows": [[str, ...]]}}],
     "caveat": str}

Everything is escaped on output.  Values are converted to text; nothing is ever interpreted as markup.
"""
from __future__ import annotations

import html
import json
import textwrap

from .pdf import text_pdf


def _t(value) -> str:
    return "" if value is None else str(value)


def render_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str).encode("utf-8")


def render_html(report: dict) -> bytes:
    e = html.escape
    out = []
    for sec in report.get("sections", []):
        out.append(f"<section><h2>{e(_t(sec.get('heading')))}</h2>")
        for p in sec.get("paragraphs", []):
            out.append(f"<p>{e(_t(p))}</p>")
        if sec.get("kv"):
            out.append("<table class='kv'>" + "".join(
                f"<tr><th>{e(_t(k))}</th><td>{e(_t(v))}</td></tr>" for k, v in sec["kv"]) + "</table>")
        if sec.get("bullets"):
            out.append("<ul>" + "".join(f"<li>{e(_t(b))}</li>" for b in sec["bullets"]) + "</ul>")
        tbl = sec.get("table")
        if tbl:
            if tbl["rows"]:
                head = "".join(f"<th>{e(_t(c))}</th>" for c in tbl["columns"])
                rows = "".join("<tr>" + "".join(f"<td>{e(_t(c))}</td>" for c in r) + "</tr>" for r in tbl["rows"])
                out.append(f"<table class='grid'><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
            else:
                out.append(f"<p class='empty'>{e(_t(tbl.get('empty', 'None.')))}</p>")
        out.append("</section>")
    meta = "".join(f"<tr><th>{e(_t(k))}</th><td>{e(_t(v))}</td></tr>" for k, v in report.get("meta", []))
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(_t(report['title']))}</title>
<style>
body{{font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;max-width:960px;margin:2rem auto;padding:0 1.2rem;color:#111}}
header{{border-bottom:4px solid #0aa;padding-bottom:.6rem;margin-bottom:1rem}}h1{{margin:0 0 .2rem;font-size:26px}}.sub{{color:#555;margin:0}}
h2{{font-size:18px;border-bottom:1px solid #ccc;padding-bottom:.2rem;margin-top:2rem}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:.6rem 0}}td,th{{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#f4f4f4}}table.kv th{{width:200px}}.empty{{color:#666;font-style:italic}}
.note{{font-size:12px;color:#555;border-top:1px solid #ccc;margin-top:2.5rem;padding-top:.6rem}}
@media print{{body{{max-width:none;margin:0}}section{{break-inside:avoid-page}}h2{{break-after:avoid}}a{{color:inherit}}}}
</style></head><body>
<header><h1>{e(_t(report['title']))}</h1><p class="sub">{e(_t(report.get('subtitle')))}</p>
<p class="sub">Generated {e(_t(report['generated_at']))} by {e(_t(report.get('generated_by')) or '-')}</p></header>
{('<table class="kv">' + meta + '</table>') if meta else ''}
{''.join(out)}
<p class="note">{e(_t(report.get('caveat')))}</p></body></html>"""
    return doc.encode("utf-8")


def report_lines(report: dict) -> list[str]:
    L = [_t(report["title"]).upper(), "=" * 60]
    if report.get("subtitle"):
        L.append(_t(report["subtitle"]))
    L.append(f"Generated {report['generated_at']} by {report.get('generated_by') or '-'}")
    for k, v in report.get("meta", []):
        L.append(f"{_t(k)}: {_t(v)}")
    L.append("")
    for sec in report.get("sections", []):
        L += ["-" * 60, _t(sec.get("heading")).upper(), ""]
        for p in sec.get("paragraphs", []):
            L += textwrap.wrap(_t(p), 92) + [""]
        for k, v in sec.get("kv", []):
            L.append(f"  {_t(k)}: {_t(v)}")
        for b in sec.get("bullets", []):
            L.append(f"  * {_t(b)}")
        tbl = sec.get("table")
        if tbl:
            if not tbl["rows"]:
                L.append(f"  ({_t(tbl.get('empty', 'None.'))})")
            for r in tbl["rows"]:
                L.append("  - " + " | ".join(_t(c) for c in r))
        L.append("")
    L += ["-" * 60] + textwrap.wrap(_t(report.get("caveat")), 92)
    return L


def render_pdf(report: dict) -> bytes:
    return text_pdf(report_lines(report), _t(report["title"])[:60])
