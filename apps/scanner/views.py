from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages
from urllib.parse import urlencode

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, has_role
from apps.audit.services import log_event

from . import reports
from .engine.datatypes import SEVERITY_LABELS
from .forms import ScanForm
from .models import SEVERITY_CHOICES, Scan
from .services import RateLimited, ScannerBusy, diff_scans, execute_scan, scan_to_report_dict


def _can_run(user) -> bool:
    return has_role(user, ROLE_ADMIN, ROLE_INVESTIGATOR)


@login_required
def home(request):
    can_run = _can_run(request.user)
    status = 200
    if request.method == "POST":
        if not can_run:
            raise PermissionDenied
        form = ScanForm(request.POST)
        if form.is_valid():
            try:
                scan = execute_scan(request, request.user, form.cleaned_data["url"],
                                    form.cleaned_data["authorization_note"])
            except RateLimited:
                form.add_error(None, f"Rate limit reached ({settings.SCAN_RATE_LIMIT} scans per 10 minutes). Try again later.")
                status = 429
            except ScannerBusy:
                form.add_error(None, "The scanner is busy with other scans. Please try again shortly.")
                status = 503
            else:
                return redirect(scan)
        else:
            status = 400
    else:
        form = ScanForm(initial={"url": request.GET.get("url", "")[:2048]})

    return render(request, "scanner/home.html", {
        "form": form, "can_run": can_run,
        "recent": Scan.objects.select_related("created_by")[:6],
        "lab_mode": settings.EAGLEEYE_LAB_MODE,
        "lab_targets": settings.EAGLEEYE_LAB_TARGETS,
        "limits": {
            "rate": settings.SCAN_RATE_LIMIT, "concurrent": settings.SCAN_MAX_CONCURRENT,
            "timeout": settings.SCAN_TIMEOUT_SECONDS, "deadline": settings.SCAN_DEADLINE_SECONDS,
            "body_kb": settings.SCAN_MAX_BODY_BYTES // 1024, "ports": ", ".join(map(str, settings.SCAN_ALLOWED_PORTS)),
        },
    }, status=status)


@login_required
def history(request):
    scans = Scan.objects.select_related("created_by")
    q = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip()
    severity = request.GET.get("severity", "").strip()
    if q:
        scans = scans.filter(Q(host__icontains=q) | Q(normalized_url__icontains=q))
    if status in dict(Scan.STATUS_CHOICES):
        scans = scans.filter(status=status)
    if severity.isdigit() and int(severity) in SEVERITY_LABELS:
        scans = scans.filter(highest_severity__gte=int(severity))
    page = Paginator(scans, 20).get_page(request.GET.get("page"))
    return render(request, "scanner/history.html", {
        "page": page, "q": q, "status": status, "severity": severity,
        "status_choices": Scan.STATUS_CHOICES, "severity_choices": SEVERITY_CHOICES,
        "pager_query": urlencode({k: v for k, v in {"q": q, "status": status, "severity": severity}.items() if v}),
    })


@login_required
def detail(request, pk: int):
    scan = get_object_or_404(Scan.objects.select_related("created_by"), pk=pk)
    return render(request, "scanner/detail.html", {
        "scan": scan, "findings": scan.findings.all(), "can_run": _can_run(request.user),
        "counts": [(label, (scan.severity_counts or {}).get(label, 0)) for label in reversed(list(SEVERITY_LABELS.values()))],
    })


@login_required
def compare(request):
    ids = request.GET.getlist("id")
    if len(ids) != 2 or not all(i.isdigit() for i in ids) or ids[0] == ids[1]:
        messages.error(request, "Select exactly two different scans to compare.")
        return redirect("scanner:history")
    scans = list(Scan.objects.filter(pk__in=[int(i) for i in ids]))
    if len(scans) != 2:
        raise Http404
    older, newer = sorted(scans, key=lambda s: (s.created_at, s.pk))
    return render(request, "scanner/compare.html", {
        "older": older, "newer": newer, "diff": diff_scans(older, newer),
        "different_hosts": older.host != newer.host,
    })


_FORMATS = {
    "json": ("application/json", reports.render_json),
    "html": ("text/html; charset=utf-8", reports.render_html),
    "pdf": ("application/pdf", reports.render_pdf),
}


@login_required
def download_report(request, pk: int, fmt: str):
    if fmt not in _FORMATS:
        raise Http404
    scan = get_object_or_404(Scan.objects.select_related("created_by").prefetch_related("findings"), pk=pk)
    content_type, render_fn = _FORMATS[fmt]
    response = HttpResponse(render_fn(scan_to_report_dict(scan)), content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="eagleeye-scan-{scan.pk}.{fmt}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    log_event(request, "scan.report_downloaded", target=f"scan #{scan.pk}", detail=f"format={fmt}")
    return response
