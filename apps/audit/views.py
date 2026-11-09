import csv
import hashlib
import io
import json
from datetime import date, timedelta
from urllib.parse import urlencode

from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404, HttpResponse
from django.shortcuts import render
from django.utils import timezone

from apps.accounts.roles import ROLE_ADMIN, role_required
from apps.forensics.reports import csv_safe

from .models import AuditEvent
from .services import log_event

EXPORT_MAX = 50_000


def _parse_date(value):
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _filtered(request):
    action = request.GET.get("action", "").strip()[:64]
    actor = request.GET.get("actor", "").strip()[:150]
    query = request.GET.get("q", "").strip()[:200]
    start, end = _parse_date(request.GET.get("from", "")), _parse_date(request.GET.get("to", ""))
    events = AuditEvent.objects.select_related("actor")
    if action:
        events = events.filter(action=action)
    if actor:
        events = events.filter(actor_name=actor)
    if query:
        events = events.filter(Q(actor_name__icontains=query) | Q(target__icontains=query) | Q(detail__icontains=query)
                               | Q(action__icontains=query))
    if start:
        events = events.filter(created_at__date__gte=start)
    if end:
        events = events.filter(created_at__date__lte=end)
    return events, {"action": action, "actor": actor, "q": query, "from": start.isoformat() if start else "",
                    "to": end.isoformat() if end else ""}


@role_required(ROLE_ADMIN)
def audit_list(request):
    events, f = _filtered(request)
    page = Paginator(events, 25).get_page(request.GET.get("page"))
    actions = AuditEvent.objects.order_by().values_list("action", flat=True).distinct()
    actors = AuditEvent.objects.order_by().exclude(actor_name="").values_list("actor_name", flat=True).distinct()
    since = timezone.now() - timedelta(hours=24)
    top = list(AuditEvent.objects.filter(created_at__gte=since).order_by().values_list("action").annotate(n=Count("id")).order_by("-n")[:5])
    pager = urlencode({k: v for k, v in f.items() if v})
    return render(request, "audit/audit_list.html", {
        "page": page, "actions": sorted(actions), "actors": sorted(actors), "f": f,
        "selected_action": f["action"], "query": f["q"], "pager_query": pager, "total": AuditEvent.objects.count(),
        "matched": page.paginator.count, "top_24h": top,
    })


@role_required(ROLE_ADMIN)
def audit_export(request, fmt):
    if fmt not in ("csv", "json"):
        raise Http404
    events, f = _filtered(request)
    rows = list(events[:EXPORT_MAX])
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(["time_utc", "actor", "action", "target", "detail", "ip_address"])
        for e in rows:
            w.writerow([csv_safe(v) for v in (e.created_at.strftime("%Y-%m-%d %H:%M:%S"), e.actor_name, e.action, e.target,
                                              e.detail, e.ip_address or "")])
        body, ctype = ("﻿" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8"
    else:
        body = json.dumps({"filters": f, "count": len(rows), "truncated": len(rows) >= EXPORT_MAX,
                           "events": [{"time_utc": e.created_at.isoformat(), "actor": e.actor_name, "action": e.action,
                                       "target": e.target, "detail": e.detail, "ip_address": e.ip_address} for e in rows]},
                          indent=2, ensure_ascii=False).encode("utf-8")
        ctype = "application/json"
    response = HttpResponse(body, content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="eagleeye-audit-log.{fmt}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["X-Content-SHA256"] = hashlib.sha256(body).hexdigest()  # lets the recipient confirm the file was not altered in transit
    log_event(request, "audit.exported", target=fmt, detail=f"rows={len(rows)}; sha256={response['X-Content-SHA256']}")
    return response
