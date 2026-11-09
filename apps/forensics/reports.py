"""Evidence exports: inventory (CSV/JSON) and integrity / evidence-record reports (HTML/JSON/PDF).

Pure Python (no Django): functions take plain dicts built by ``services`` from saved rows.
"""
from __future__ import annotations

import csv
import html
import io
import json

from apps.core.pdf import text_pdf

CAVEAT = ("A matching SHA-256 proves the stored copy is bit-identical to what EagleEye received; it does not prove the "
          "evidence was unaltered before upload. File timestamps and other metadata can be changed by acquisition and "
          "upload. MD5 is shown for legacy identification only. Type detection is signature-based and limited to common formats.")

CSV_COLUMNS = ["evidence_id", "original_filename", "size_bytes", "sha256", "md5", "detected_type", "detected_mime",
               "extension_check", "extension_note", "case_reference", "uploaded_by", "uploaded_at",
               "integrity_status", "last_verified_at", "last_verified_by"]


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (cells starting with = + - @ tab CR)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_inventory_csv(items: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for i in items:
        writer.writerow([csv_safe(v) for v in (
            i["evidence_id"], i["original_filename"], i["size"], i["sha256"], i["md5"], i["detected_kind"],
            i["detected_mime"], i["extension_severity"], i["extension_note"], i["case_reference"], i["uploaded_by"],
            i["uploaded_at"], i["integrity_status"], i["last_verified_at"], i["last_verified_by"])])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so spreadsheets read UTF-8 correctly


def render_json(report: dict) -> bytes:
    return json.dumps({**report, "caveat": CAVEAT}, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ HTML
def render_html(report: dict) -> bytes:
    e = html.escape
    s = report["summary"]
    parts = []
    for it in report["items"]:
        notes = "".join(f"<li><b>{e(n['author'])}</b> <i>{e(n['created_at'])}</i><br>{e(n['text'])}</li>" for n in it.get("notes", []))
        events = "".join(
            f"<tr><td>{n}</td><td>{e(ev['created_at'])}</td><td>{e(ev['actor'])}</td><td>{e(ev['action'])}</td>"
            f"<td>{e(ev['detail'])}</td><td><code>{e(ev['entry_hash'][:16])}…</code></td></tr>"
            for n, ev in ((i + 1, ev) for i, ev in enumerate(it.get("events", []))))
        chain = it.get("chain")
        parts.append(f"""
<section class="item"><h2>{e(it['evidence_id'])} &mdash; {e(it['original_filename'])}</h2>
<table>
<tr><th>Integrity</th><td><b>{e(it['integrity_status'].upper())}</b>{(' (last checked ' + e(it['last_verified_at']) + ' by ' + e(it['last_verified_by'] or '-') + ')') if it['last_verified_at'] else ' (never re-verified)'}</td></tr>
<tr><th>SHA-256</th><td><code>{e(it['sha256'])}</code></td></tr>
<tr><th>MD5 (legacy)</th><td><code>{e(it['md5'] or '-')}</code></td></tr>
<tr><th>Size</th><td>{it['size']} bytes</td></tr>
<tr><th>Detected type</th><td>{e(it['detected_kind'])} {e(it['detected_mime'])}</td></tr>
<tr><th>Extension check</th><td>{e(it['extension_severity'])}: {e(it['extension_note'])}</td></tr>
<tr><th>Uploaded</th><td>{e(it['uploaded_at'])} by {e(it['uploaded_by'] or '-')}</td></tr>
<tr><th>Case reference</th><td>{e(it['case_reference'] or '-')}</td></tr>
<tr><th>Description</th><td>{e(it['description'] or '-')}</td></tr>
</table>
{('<h3>Notes</h3><ul>' + notes + '</ul>') if notes else ''}
{('<h3>Chain of custody</h3><p>Hash chain: <b>' + ('VALID' if chain['ok'] else 'BROKEN') + '</b> &mdash; ' + e(chain['message']) + '</p><table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th><th>Entry hash</th></tr>' + events + '</table>') if chain else ''}
</section>""")
    body = "".join(parts) or "<p>No evidence items.</p>"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(report['title'])}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:.5rem 0}}td,th{{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}}th{{width:170px;background:#f5f5f5}}
code{{background:#f3f3f3;padding:1px 4px;word-break:break-all;font-size:12px}}.item{{border-top:3px solid #0aa;margin-top:2rem}}.note{{font-size:12px;color:#555;border-top:1px solid #ccc;margin-top:2rem;padding-top:.6rem}}</style></head><body>
<h1>{e(report['title'])}</h1>
<p>Generated {e(report['generated_at'])} by {e(report['generated_by'] or '-')}</p>
<p><b>{s['total']}</b> item(s): {s['verified']} verified, {s['failed']} failed, {s['missing']} missing, {s['unverified']} unverified; {s['mismatches']} with extension warnings.</p>
{body}
<p class="note">{e(CAVEAT)}</p></body></html>"""
    return doc.encode("utf-8")


# ------------------------------------------------------------------- PDF
def report_lines(report: dict) -> list[str]:
    s = report["summary"]
    L = [report["title"].upper(), "=" * 60, f"Generated {report['generated_at']} by {report['generated_by'] or '-'}",
         f"Items: {s['total']}  verified: {s['verified']}  failed: {s['failed']}  missing: {s['missing']}  "
         f"unverified: {s['unverified']}  extension warnings: {s['mismatches']}", ""]
    for it in report["items"]:
        L += ["-" * 60, f"{it['evidence_id']}  {it['original_filename']}",
              f"  Integrity:   {it['integrity_status'].upper()}" + (f" (checked {it['last_verified_at']} by {it['last_verified_by'] or '-'})" if it["last_verified_at"] else " (never re-verified)"),
              f"  SHA-256:     {it['sha256']}", f"  MD5 (legacy): {it['md5'] or '-'}", f"  Size:        {it['size']} bytes",
              f"  Type:        {it['detected_kind']} {it['detected_mime']}",
              f"  Extension:   {it['extension_severity']} - {it['extension_note']}",
              f"  Uploaded:    {it['uploaded_at']} by {it['uploaded_by'] or '-'}",
              f"  Case ref:    {it['case_reference'] or '-'}", f"  Description: {it['description'] or '-'}"]
        for n in it.get("notes", []):
            L.append(f"  NOTE {n['created_at']} {n['author']}: {n['text']}")
        chain = it.get("chain")
        if chain:
            L.append(f"  Custody hash chain: {'VALID' if chain['ok'] else 'BROKEN'} - {chain['message']}")
            for i, ev in enumerate(it.get("events", []), 1):
                L.append(f"   {i:>2}. {ev['created_at']} {ev['actor'] or '-'} {ev['action']}: {ev['detail']}  [{ev['entry_hash'][:12]}]")
        L.append("")
    import textwrap
    return L + ["-" * 60] + textwrap.wrap(CAVEAT, 88)


def render_pdf(report: dict) -> bytes:
    return text_pdf(report_lines(report), report["title"][:60])
