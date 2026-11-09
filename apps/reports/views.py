from datetime import date

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse

from django.shortcuts import render

from apps.accounts.roles import ROLE_ADMIN, has_role, role_required
from apps.audit.services import log_event
from apps.cases.models import Case
from apps.core import reporting
from apps.forensics.models import EvidenceItem
from apps.network_analysis.models import NetworkImport
from apps.scanner.models import Scan

from . import services

_RENDER = {"html": ("text/html; charset=utf-8", reporting.render_html), "json": ("application/json", reporting.render_json),
           "pdf": ("application/pdf", reporting.render_pdf)}


def _send(request, report, fmt, name, action):
    if fmt not in _RENDER:
        raise Http404
    ctype, fn = _RENDER[fmt]
    response = HttpResponse(fn(report), content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="{name}.{fmt}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    log_event(request, action, target=name, detail=f"format={fmt}")
    return response


def _date(value):
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


@login_required
def home(request):
    return render(request, "reports/home.html", {
        "cases": Case.objects.all()[:25], "scans": Scan.objects.exclude(status=Scan.BLOCKED)[:25],
        "imports": NetworkImport.objects.all()[:15], "evidence_total": EvidenceItem.objects.count(),
        "is_admin": has_role(request.user, ROLE_ADMIN),
    })


@login_required
def overview(request, fmt):
    return _send(request, services.build_overview(request.user), fmt, "eagleeye-security-overview", "report.overview_exported")


@role_required(ROLE_ADMIN)
def audit_report(request, fmt):
    start, end = _date(request.GET.get("from")), _date(request.GET.get("to"))
    report = services.build_audit_report(request.user, start, end, request.GET.get("action", "")[:64], request.GET.get("actor", "")[:150])
    return _send(request, report, fmt, "eagleeye-audit-report", "report.audit_exported")
