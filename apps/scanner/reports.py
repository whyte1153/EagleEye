"""Report rendering (JSON / HTML / PDF) from a plain ``dict``.  No Django, no third-party libraries.

The dict is produced by ``services.scan_to_report_dict`` from saved database rows,
so every report reflects stored data only.
"""
from __future__ import annotations

import html
import json
import textwrap

from apps.core.pdf import text_pdf

DISCLAIMER = ("Automated configuration check of HTTP response headers, cookies, redirects and TLS. "
              "It does not test for application vulnerabilities such as injection or broken access control. "
              "Only scan systems you are authorized to assess.")


def render_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


# ----------------------------------------------------------------- HTML
_SEV_COLOR = {"Critical": "#c2185b", "High": "#d32f2f", "Medium": "#ef6c00", "Low": "#f9a825", "Informational": "#1976d2"}


def render_html(report: dict) -> bytes:
    e = html.escape
    rows = []
    for f in report["findings"]:
        color = _SEV_COLOR.get(f["severity_label"], "#555")
        rows.append(f"""
<section class="finding">
  <h3><span class="sev" style="background:{color}">{e(f['severity_label'])}</span> {e(f['title'])}</h3>
  <p><b>What was found:</b> {e(f['description'])}</p>
  <p><b>Impact:</b> {e(f['impact'])}</p>
  <p><b>Remediation:</b> {e(f['remediation'])}</p>
  <p><b>Evidence:</b> <code>{e(f['evidence'])}</code></p>
  <p><b>Reproduce:</b> <code>{e(f['reproduce'])}</code></p>
</section>""")
    findings_html = "".join(rows) or "<p>No findings were recorded for this scan.</p>"
    checks_html = "".join(
        f"<tr><td>{e(c['title'])}</td><td>{e(c['outcome'].upper())}</td><td>{e(c.get('detail', ''))}</td></tr>"
        for c in report["checks"])
    hops_html = "".join(
        f"<tr><td>{i}</td><td>{e(str(h['status']))}</td><td>{e(h['url'])}</td><td>{e(h['ip'])}</td><td>{h['elapsed_ms']} ms</td></tr>"
        for i, h in enumerate(report["hops"], 1))
    counts = " &nbsp; ".join(f"{e(k)}: <b>{v}</b>" for k, v in report["severity_counts"].items())
    tls = report.get("tls")
    tls_html = ""
    if tls:
        tls_html = (f"<h2>TLS</h2><p>Version {e(tls.get('version', ''))}, cipher {e(tls.get('cipher', ''))}, "
                    f"certificate verified: <b>{'yes' if tls.get('verified') else 'NO'}</b>"
                    + (f" ({e(tls['error'])})" if tls.get("error") else "")
                    + (f", expires in {tls['days_left']} day(s)" if tls.get("days_left") is not None else "") + ".</p>")
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EagleEye scan report #{report['id']}</title>
<style>
body{{font:15px/1.55 system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#111}}
h1{{margin-bottom:0}} .sub{{color:#555;margin-top:.2rem}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #ccc;padding:5px 8px;text-align:left;vertical-align:top}}
code{{background:#f3f3f3;padding:1px 4px;word-break:break-all;font-size:12px}}
.finding{{border:1px solid #ddd;border-left:4px solid #0aa;padding:.4rem 1rem;margin:1rem 0;page-break-inside:avoid}}
.sev{{color:#fff;padding:2px 8px;border-radius:3px;font-size:12px}} .note{{font-size:12px;color:#555;border-top:1px solid #ccc;margin-top:2rem;padding-top:.6rem}}
</style></head><body>
<h1>EagleEye scan report</h1>
<p class="sub">Scan #{report['id']} &middot; generated {e(report['generated_at'])}</p>
<table>
<tr><th>Target</th><td>{e(report['normalized_url'])}</td></tr>
<tr><th>Status</th><td>{e(report['status'])}{(' - ' + e(report['error'])) if report['error'] else ''}</td></tr>
<tr><th>Started</th><td>{e(report['started_at'] or '-')}</td></tr>
<tr><th>Duration</th><td>{report['duration_ms'] if report['duration_ms'] is not None else '-'} ms</td></tr>
<tr><th>Final URL / HTTP status</th><td>{e(report['final_url'] or '-')} / {e(str(report['final_status_code'] or '-'))}</td></tr>
<tr><th>Response time</th><td>{report['response_time_ms'] if report['response_time_ms'] is not None else '-'} ms</td></tr>
<tr><th>Scanned by</th><td>{e(report['scanned_by'] or '-')}</td></tr>
<tr><th>Authorization note</th><td>{e(report['authorization_note'] or '-')}</td></tr>
</table>
<h2>Findings by severity</h2><p>{counts}</p>
{findings_html}
<h2>Request chain</h2>
<table><tr><th>#</th><th>Status</th><th>URL</th><th>IP</th><th>Time</th></tr>{hops_html}</table>
{tls_html}
<h2>Checks performed</h2>
<table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>{checks_html}</table>
<p class="note">{e(DISCLAIMER)}</p>
</body></html>"""
    return doc.encode("utf-8")


# ------------------------------------------------------------------ PDF
def report_lines(report: dict) -> list[str]:
    """Plain-text rendering used for the PDF."""
    L = ["EAGLEEYE SCAN REPORT", "=" * 60,
         f"Scan #{report['id']}   generated {report['generated_at']}", "",
         f"Target:        {report['normalized_url']}",
         f"Status:        {report['status']}" + (f" - {report['error']}" if report["error"] else ""),
         f"Final URL:     {report['final_url'] or '-'}",
         f"HTTP status:   {report['final_status_code'] or '-'}",
         f"Response time: {report['response_time_ms'] if report['response_time_ms'] is not None else '-'} ms",
         f"Scanned by:    {report['scanned_by'] or '-'}",
         f"Authorization: {report['authorization_note'] or '-'}", "",
         "FINDINGS BY SEVERITY", "-" * 60,
         "  ".join(f"{k}: {v}" for k, v in report["severity_counts"].items()), ""]
    L += ["FINDINGS", "-" * 60]
    if not report["findings"]:
        L.append("No findings were recorded for this scan.")
    for n, f in enumerate(report["findings"], 1):
        L += ["", f"{n}. [{f['severity_label'].upper()}] {f['title']}",
              f"   What:        {f['description']}", f"   Impact:      {f['impact']}",
              f"   Remediation: {f['remediation']}", f"   Evidence:    {f['evidence']}",
              f"   Reproduce:   {f['reproduce']}"]
    L += ["", "REQUEST CHAIN", "-" * 60]
    L += [f"{i}. {h['status']} {h['url']} ({h['ip']}, {h['elapsed_ms']} ms)" for i, h in enumerate(report["hops"], 1)] or ["(none)"]
    tls = report.get("tls")
    if tls:
        L += ["", "TLS", "-" * 60, f"{tls.get('version', '')} {tls.get('cipher', '')}; certificate verified: "
              f"{'yes' if tls.get('verified') else 'NO'}" + (f" ({tls['error']})" if tls.get("error") else "")]
    L += ["", "CHECKS PERFORMED", "-" * 60]
    L += [f"[{c['outcome'].upper():4}] {c['title']}" + (f" - {c['detail']}" if c.get("detail") else "") for c in report["checks"]]
    L += ["", "-" * 60] + textwrap.wrap(DISCLAIMER, 88)
    return L


def render_pdf(report: dict) -> bytes:
    return text_pdf(report_lines(report), f"EagleEye scan #{report['id']}")
