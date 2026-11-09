"""Report builders.  Every number comes from saved rows."""
from __future__ import annotations

from datetime import timedelta

from django.db.models import Count
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.cases.models import Case
from apps.forensics.models import EvidenceItem
from apps.network_analysis.models import NetworkImport
from apps.scanner.engine.datatypes import SEVERITY_LABELS
from apps.scanner.models import Finding, Scan

AUDIT_REPORT_MAX = 2000


def fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def latest_scan_per_host():
    """Latest completed scan for each host (dashboard-consistent)."""
    seen, out = set(), []
    for s in Scan.objects.filter(status=Scan.COMPLETED).order_by("-created_at", "-id"):
        if s.host not in seen:
            seen.add(s.host)
            out.append(s)
    return out


CAVEAT = ("Generated from records saved in EagleEye. Scan findings are configuration observations only and a clean result "
          "does not mean a target is secure. Network indicators are heuristic. Evidence hashes prove integrity since receipt, "
          "not before.")


def build_overview(user) -> dict:
    now = timezone.now()
    scans = latest_scan_per_host()
    sev = {label: 0 for label in reversed(list(SEVERITY_LABELS.values()))}
    rows = []
    for s in scans:
        for label, n in (s.severity_counts or {}).items():
            if label in sev:
                sev[label] += n
        rows.append([s.host, f"#{s.pk}", fmt(s.created_at), s.findings_count, s.highest_severity_label])
    ev = {r["integrity_status"]: r["n"] for r in EvidenceItem.objects.values("integrity_status").annotate(n=Count("id"))}
    cases = {r["status"]: r["n"] for r in Case.objects.values("status").annotate(n=Count("id"))}
    active_cases = [[c.case_id, c.title, c.get_status_display(), c.get_priority_display(),
                     c.assigned_to.get_username() if c.assigned_to else "-"]
                    for c in Case.objects.exclude(status=Case.CLOSED).select_related("assigned_to")[:50]]
    imports = NetworkImport.objects.order_by("-imported_at")[:20]
    flagged = [[n.import_id, n.get_kind_display(), n.original_filename, SEVERITY_LABELS.get(n.max_severity, "none flagged")]
               for n in imports]
    sections = [
        {"heading": "At a glance", "kv": [
            ("Targets with a completed scan", len(scans)), ("Open findings (latest scan per target)", sum(sev.values())),
            ("Evidence items", sum(ev.values())),
            ("Evidence needing attention (failed or missing)", ev.get("failed", 0) + ev.get("missing", 0)),
            ("Network imports", NetworkImport.objects.count()),
            ("Cases not closed", sum(v for k, v in cases.items() if k != "closed")), ("Cases closed", cases.get("closed", 0)),
        ]},
        {"heading": "Findings by severity (latest scan of each target)", "kv": list(sev.items())},
        {"heading": "Latest scan per target", "table": {"columns": ["Target", "Scan", "Scanned", "Findings", "Highest"],
                                                         "rows": rows, "empty": "No completed scans."}},
        {"heading": "Evidence integrity", "kv": [(k.title(), ev.get(k, 0)) for k in ("verified", "unverified", "failed", "missing")]},
        {"heading": "Recent network imports", "table": {"columns": ["ID", "Kind", "File", "Highest indicator"], "rows": flagged,
                                                          "empty": "No network imports."}},
        {"heading": "Cases not closed", "table": {"columns": ["Case", "Title", "Status", "Priority", "Assigned"],
                                                    "rows": active_cases, "empty": "No open cases."}},
    ]
    return {"title": "Security overview", "subtitle": "Summary of scans, evidence, network imports and cases",
            "generated_at": fmt(now), "generated_by": user.get_username(), "meta": [], "sections": sections, "caveat": CAVEAT}


def audit_queryset(start=None, end=None, action="", actor=""):
    qs = AuditEvent.objects.all()
    if start:
        qs = qs.filter(created_at__date__gte=start)
    if end:
        qs = qs.filter(created_at__date__lte=end)
    if action:
        qs = qs.filter(action=action)
    if actor:
        qs = qs.filter(actor_name=actor)
    return qs


def build_audit_report(user, start=None, end=None, action="", actor="") -> dict:
    qs = audit_queryset(start, end, action, actor)
    total = qs.count()
    by_action = list(qs.order_by().values_list("action").annotate(n=Count("id")).order_by("-n")[:30])
    rows = [[fmt(e.created_at), e.actor_name or "-", e.action, e.target, e.detail, e.ip_address or ""] for e in qs[:AUDIT_REPORT_MAX]]
    flt = [("From", start or "any"), ("To", end or "any"), ("Action", action or "any"), ("Actor", actor or "any"), ("Events matched", total)]
    sections = [
        {"heading": "Filters", "kv": flt},
        {"heading": "Events by action", "table": {"columns": ["Action", "Count"], "rows": [[a, n] for a, n in by_action], "empty": "No events."}},
        {"heading": f"Events (newest first, up to {AUDIT_REPORT_MAX})",
         "paragraphs": ([f"Showing {AUDIT_REPORT_MAX} of {total}. Narrow the date range to see the rest."] if total > AUDIT_REPORT_MAX else []),
         "table": {"columns": ["Time (UTC)", "Actor", "Action", "Target", "Detail", "IP"], "rows": rows, "empty": "No events match."}},
    ]
    return {"title": "Audit report", "subtitle": "Append-only record of actions in EagleEye", "generated_at": fmt(timezone.now()),
            "generated_by": user.get_username(), "meta": [], "sections": sections,
            "caveat": "Audit events cannot be edited or deleted through the application. A database administrator could still alter the "
                      "database directly; ship logs to external storage for stronger guarantees."}
