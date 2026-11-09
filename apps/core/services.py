"""Dashboard data.  Everything here comes from the database."""
from __future__ import annotations

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from apps.audit.models import AuditEvent

from apps.forensics.models import EvidenceItem
from apps.network_analysis.models import NetworkImport
from apps.scanner.models import Finding, Scan


from .models import Module

User = get_user_model()

# Metrics owned by modules that do not exist yet.  They are shown as "not yet
# available" rather than as zeros, so nothing implies data that cannot exist.
PENDING_METRICS = [
    ("Open cases", "Under investigation", 5),
]

SEVERITY_ORDER = [(4, "Critical", "critical"), (3, "High", "high"), (2, "Medium", "medium"),
                  (1, "Low", "low"), (0, "Informational", "info")]


def scan_stats() -> dict:
    """Assessment totals and findings by severity, from saved scans.

    Severity counts use only the LATEST completed scan of each target, so
    re-scanning a site does not double-count its findings.
    """
    completed = Scan.objects.filter(status=Scan.COMPLETED)
    latest_ids, seen = [], set()
    for scan_id, host in completed.order_by("-created_at", "-id").values_list("id", "host")[:1000]:
        if host not in seen:
            seen.add(host)
            latest_ids.append(scan_id)
    counts = {row["severity"]: row["n"] for row in
              Finding.objects.filter(scan_id__in=latest_ids).values("severity").annotate(n=Count("id"))}
    total = sum(counts.values())
    rows = [{"label": label, "slug": slug, "count": counts.get(sev, 0),
             "pct": round(counts.get(sev, 0) / total * 100) if total else 0} for sev, label, slug in SEVERITY_ORDER]
    return {"assessments": completed.count(), "targets": len(latest_ids), "findings": total, "severity_rows": rows}


def activity_last_days(days: int = 7) -> list[dict]:
    """Audit events per day for the last ``days`` days (including empty days)."""
    today = timezone.localdate()
    start = today - timedelta(days=days - 1)
    counts = {
        row["day"]: row["n"]
        for row in AuditEvent.objects.filter(created_at__date__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(n=Count("id"))
    }
    series = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        series.append({"day": day, "label": day.strftime("%a"), "count": counts.get(day, 0)})
    peak = max((d["count"] for d in series), default=0)
    for d in series:
        d["height"] = round(d["count"] / peak * 100) if peak else 0
    return series


def evidence_stats() -> dict:
    counts = {row["integrity_status"]: row["n"] for row in
              EvidenceItem.objects.values("integrity_status").annotate(n=Count("id"))}
    total = sum(counts.values())
    rows = [{"label": label, "slug": slug, "count": counts.get(key, 0),
             "pct": round(counts.get(key, 0) / total * 100) if total else 0}
            for key, label, slug in (("verified", "Verified", "info"), ("unverified", "Unverified", "low"),
                                     ("missing", "Missing", "medium"), ("failed", "Failed", "high"))]
    return {"total": total, "rows": rows, "problems": counts.get("failed", 0) + counts.get("missing", 0),
            "mismatches": EvidenceItem.objects.filter(mismatch=True).count()}


def dashboard_context() -> dict:
    modules = list(Module.objects.all())
    now = timezone.now()
    ready = [m for m in modules if m.is_ready]
    planned = [m for m in modules if not m.is_ready]
    activity = activity_last_days()
    stats = scan_stats()
    ev = evidence_stats()
    stat_cards = [
        {"label": "Assessments", "value": stats["assessments"], "sub": f"{stats['targets']} target(s) scanned"},
        {"label": "Findings", "value": stats["findings"], "sub": "latest scan of each target"},
        {"label": "Evidence items", "value": ev["total"],
         "sub": f"{ev['problems']} need attention" if ev["problems"] else "integrity OK" if ev["total"] else "none stored yet"},
        {"label": "Network imports", "value": NetworkImport.objects.count(),
         "sub": f"{NetworkImport.objects.filter(max_severity__gte=2).count()} with medium+ indicators"
                if NetworkImport.objects.exists() else "Nmap / PCAP, none yet"},
    ] + [{"label": l, "sub": f"{sub} · available in phase {ph}", "pending": True} for l, sub, ph in PENDING_METRICS]
    return {
        "stat_cards": stat_cards, "evidence": ev, "severity_rows": stats["severity_rows"], "has_findings": stats["findings"] > 0,
        "has_scans": stats["assessments"] > 0, "recent_scans": list(Scan.objects.select_related("created_by")[:5]),
        "modules": modules,
        "modules_ready": len(ready),
        "modules_total": len(modules),
        "next_phase": min((m.phase for m in planned), default=None),
        "users_total": User.objects.count(),
        "audit_total": AuditEvent.objects.count(),
        "audit_24h": AuditEvent.objects.filter(created_at__gte=now - timedelta(hours=24)).count(),
        "recent_events": list(AuditEvent.objects.all()[:8]),
        "activity": activity,
        "activity_total": sum(d["count"] for d in activity),
    }
