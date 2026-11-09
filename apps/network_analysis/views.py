import re
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, has_role
from apps.audit.services import log_event

from .engine.limits import ParseError
from .engine.pcap_analyzer import filter_flows
from .forms import ImportForm
from .models import NetworkImport
from .services import (export_json, flows_csv, host_ports, import_stats, import_upload, ports_csv, sev_label, sev_slug)

IID_RE = re.compile(r"^NI-\d{4}-\d{6}$")
CAVEAT = ("Findings come from transparent rules (service name and port, script output, traffic patterns). They are indicators "
          "for a human to review, not proof of a vulnerability or an attack. Packet payloads are never stored.")


def _can_modify(user) -> bool:
    return has_role(user, ROLE_ADMIN, ROLE_INVESTIGATOR)


def _get(iid):
    if not IID_RE.fullmatch(iid):
        raise Http404
    return get_object_or_404(NetworkImport.objects.select_related("imported_by"), import_id=iid)


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@login_required
def home(request):
    status = 200
    can_modify = _can_modify(request.user)
    if request.method == "POST":
        if not can_modify:
            raise PermissionDenied
        form = ImportForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                ni = import_upload(request.user, form.cleaned_data["file"], form.cleaned_data["description"],
                                   form.cleaned_data["case_reference"])
            except ParseError as exc:
                form.add_error("file", str(exc))
                status = 400
                log_event(request, "network.import_rejected", target=form.cleaned_data["file"].name[:200], detail=str(exc)[:300])
            else:
                log_event(request, "network.imported", target=ni.import_id, detail=f"kind={ni.kind}; sha256={ni.sha256}")
                messages.success(request, f"{ni.import_id} imported.")
                return redirect(ni)
        else:
            status = 400
    else:
        form = ImportForm()
    from django.conf import settings
    return render(request, "network_analysis/home.html", {
        "form": form, "can_modify": can_modify, "stats": import_stats(), "recent": NetworkImport.objects.select_related("imported_by")[:6],
        "max_mb": settings.NETWORK_MAX_BYTES // (1024 * 1024)}, status=status)


@login_required
def imports(request):
    qs = NetworkImport.objects.select_related("imported_by")
    q, kind = request.GET.get("q", "").strip(), request.GET.get("kind", "").strip()
    if q:
        qs = qs.filter(Q(import_id__icontains=q) | Q(original_filename__icontains=q) | Q(sha256__icontains=q)
                       | Q(case_reference__icontains=q))
    if kind in (NetworkImport.NMAP, NetworkImport.PCAP):
        qs = qs.filter(kind=kind)
    page = Paginator(qs, 20).get_page(request.GET.get("page"))
    return render(request, "network_analysis/imports.html", {
        "page": page, "q": q, "kind": kind, "pager_query": urlencode({k: v for k, v in {"q": q, "kind": kind}.items() if v})})


@login_required
def detail(request, iid):
    ni = _get(iid)
    ctx = {"ni": ni, "caveat": CAVEAT, "max_label": sev_label(ni.max_severity), "max_slug": sev_slug(ni.max_severity),
           "findings": [{**f, "sev_slug": sev_slug(f["severity"]), "sev_label": sev_label(f["severity"])} for f in ni.findings]}
    if ni.kind == NetworkImport.NMAP:
        q = request.GET.get("q", "").strip()[:100]
        min_sev = _int_or_none(request.GET.get("min_sev"))
        port = _int_or_none(request.GET.get("port"))
        show_all = request.GET.get("all") == "1"
        rows = host_ports(ni, q, min_sev, port, only_open=not show_all)
        page = Paginator(rows, 50).get_page(request.GET.get("page"))
        ctx.update(page=page, q=q, min_sev=request.GET.get("min_sev", ""), port=request.GET.get("port", ""), show_all=show_all,
                   total_rows=len(rows), scanner=ni.data.get("scanner", {}),
                   pager_query=urlencode({k: v for k, v in {"q": q, "min_sev": request.GET.get("min_sev", ""),
                                                           "port": request.GET.get("port", ""), "all": "1" if show_all else ""}.items() if v}),
                   hosts=ni.hosts.all()[:200], host_total=ni.hosts.count())
    else:
        q, ip, proto = request.GET.get("q", "").strip()[:100], request.GET.get("ip", "").strip()[:45], request.GET.get("proto", "").strip()[:10]
        port = _int_or_none(request.GET.get("port"))
        flows = filter_flows(ni.data.get("flows", []), ip=ip, port=port, proto=proto, text=q)
        page = Paginator(flows, 50).get_page(request.GET.get("page"))
        ctx.update(page=page, q=q, ip=ip, proto=proto, port=request.GET.get("port", ""), total_rows=len(flows),
                   protocols=ni.data.get("protocols", []), talkers=ni.data.get("talkers", [])[:15], dns=ni.data.get("dns", [])[:30],
                   pager_query=urlencode({k: v for k, v in {"q": q, "ip": ip, "proto": proto, "port": request.GET.get("port", "")}.items() if v}))
    return render(request, "network_analysis/detail.html", ctx)


def _send(request, body, ctype, filename, ni, fmt):
    response = HttpResponse(body, content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'"
    log_event(request, "network.exported", target=ni.import_id, detail=fmt)
    return response


@login_required
def export(request, iid, fmt):
    ni = _get(iid)
    if fmt not in ("csv", "json"):
        raise Http404
    base = f"eagleeye-{ni.import_id}"
    if ni.kind == NetworkImport.NMAP:
        rows = host_ports(ni, request.GET.get("q", "")[:100], _int_or_none(request.GET.get("min_sev")),
                          _int_or_none(request.GET.get("port")), only_open=request.GET.get("all") != "1")
        if fmt == "csv":
            return _send(request, ports_csv(rows), "text/csv; charset=utf-8", f"{base}-ports.csv", ni, fmt)
        return _send(request, export_json(ni, {"ports": rows}), "application/json", f"{base}.json", ni, fmt)
    flows = filter_flows(ni.data.get("flows", []), ip=request.GET.get("ip", "")[:45], port=_int_or_none(request.GET.get("port")),
                         proto=request.GET.get("proto", "")[:10], text=request.GET.get("q", "")[:100])
    if fmt == "csv":
        return _send(request, flows_csv(flows), "text/csv; charset=utf-8", f"{base}-flows.csv", ni, fmt)
    return _send(request, export_json(ni, {"flows": flows, "protocols": ni.data.get("protocols", []),
                                           "dns": ni.data.get("dns", [])}), "application/json", f"{base}.json", ni, fmt)
