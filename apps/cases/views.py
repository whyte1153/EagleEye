import re
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, has_role
from apps.audit.services import log_event
from apps.core import reporting

from . import services
from .forms import CaseForm, LinkForm, NoteForm, StatusForm
from .models import Case, CaseLink

CID_RE = re.compile(r"^CS-\d{4}-\d{6}$")
User = get_user_model()


def _can_modify(user) -> bool:
    return has_role(user, ROLE_ADMIN, ROLE_INVESTIGATOR)


def _require_modify(request):
    if not _can_modify(request.user):
        raise PermissionDenied


def _get(cid: str) -> Case:
    if not CID_RE.fullmatch(cid):
        raise Http404
    return get_object_or_404(Case.objects.select_related("created_by", "assigned_to"), case_id=cid)


@login_required
def case_list(request):
    qs = Case.objects.select_related("assigned_to", "created_by")
    q = request.GET.get("q", "").strip()[:100]
    status = request.GET.get("status", "").strip()
    priority = request.GET.get("priority", "").strip()
    mine = request.GET.get("mine") == "1"
    if q:
        qs = qs.filter(Q(case_id__icontains=q) | Q(title__icontains=q) | Q(description__icontains=q))
    if status == "active":
        qs = qs.exclude(status=Case.CLOSED)
    elif status in dict(Case.STATUS_CHOICES):
        qs = qs.filter(status=status)
    if priority in dict(Case.PRIORITY_CHOICES):
        qs = qs.filter(priority=priority)
    if mine:
        qs = qs.filter(assigned_to=request.user)
    page = Paginator(qs, 20).get_page(request.GET.get("page"))
    counts = {s: Case.objects.filter(status=s).count() for s, _ in Case.STATUS_CHOICES}
    return render(request, "cases/list.html", {
        "page": page, "q": q, "status": status, "priority": priority, "mine": mine, "counts": counts,
        "status_choices": Case.STATUS_CHOICES, "priority_choices": Case.PRIORITY_CHOICES, "can_modify": _can_modify(request.user),
        "pager_query": urlencode({k: v for k, v in {"q": q, "status": status, "priority": priority, "mine": "1" if mine else ""}.items() if v}),
    })


@login_required
def case_new(request):
    _require_modify(request)
    if request.method == "POST":
        form = CaseForm(request.POST)
        if form.is_valid():
            d = form.cleaned_data
            case = services.create_case(request, request.user, d["title"], d["description"], d["priority"], d["assigned_to"])
            messages.success(request, f"{case.case_id} created.")
            return redirect(case)
        status = 400
    else:
        form, status = CaseForm(initial={"assigned_to": request.user.pk}), 200
    return render(request, "cases/form.html", {"form": form, "case": None}, status=status)


@login_required
def edit(request, cid):
    _require_modify(request)
    case = _get(cid)
    if request.method == "POST":
        form = CaseForm(request.POST)
        if form.is_valid():
            d = form.cleaned_data
            try:
                changes = services.update_case(request, request.user, case, d["title"], d["description"], d["priority"], d["assigned_to"])
            except services.WorkflowError as exc:
                form.add_error(None, str(exc))
                return render(request, "cases/form.html", {"form": form, "case": case}, status=400)
            messages.success(request, "Case updated." if changes else "No changes.")
            return redirect(case)
        status = 400
    else:
        form = CaseForm(initial={"title": case.title, "description": case.description, "priority": case.priority,
                                 "assigned_to": case.assigned_to_id})
        status = 200
    return render(request, "cases/form.html", {"form": form, "case": case}, status=status)


@login_required
def detail(request, cid):
    case = _get(cid)
    items = services.linked_items(case)
    modify = _can_modify(request.user)
    ctx = {
        "case": case, "items": items, "events": list(case.events.select_related("actor")), "can_modify": modify,
        "status_form": StatusForm(initial={"status": case.status}), "note_form": NoteForm(),
        "removed_links": [l for l in case.links.all() if not l.active],
        "suggest": services.suggestions(case) if modify else {"evidence": [], "network": []},
        "cand": services.candidates(case) if modify and not case.is_closed else None,
        "allowed_next": sorted(services.TRANSITIONS[case.status]),
    }
    return render(request, "cases/detail.html", ctx)


def _back(case, request, form=None):
    if form is not None and form.errors:
        for errs in form.errors.values():
            for e in errs:
                messages.error(request, e)
    return redirect(case)


@login_required
@require_POST
def change_status(request, cid):
    _require_modify(request)
    case = _get(cid)
    form = StatusForm(request.POST)
    if form.is_valid():
        try:
            services.change_status(request, request.user, case, form.cleaned_data["status"], form.cleaned_data["note"])
            messages.success(request, "Status updated.")
        except services.WorkflowError as exc:
            messages.error(request, str(exc))
    return _back(case, request, form)


@login_required
@require_POST
def add_note_view(request, cid):
    _require_modify(request)
    case = _get(cid)
    form = NoteForm(request.POST)
    if form.is_valid():
        services.add_note(request, request.user, case, form.cleaned_data["text"])
        messages.success(request, "Note added.")
    return _back(case, request, form)


@login_required
@require_POST
def link_item(request, cid):
    _require_modify(request)
    case = _get(cid)
    form = LinkForm(request.POST)
    if form.is_valid():
        try:
            services.link_item(request, request.user, case, form.cleaned_data["kind"], form.cleaned_data["ref"])
            messages.success(request, "Item linked.")
        except services.WorkflowError as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Choose an item to link.")
    return redirect(case)


@login_required
@require_POST
def unlink_item(request, cid, link_id):
    _require_modify(request)
    case = _get(cid)
    link = get_object_or_404(CaseLink, pk=link_id, case=case)
    try:
        services.unlink_item(request, request.user, case, link)
        messages.success(request, "Item unlinked (kept in the case record).")
    except services.WorkflowError as exc:
        messages.error(request, str(exc))
    return redirect(case)


_RENDER = {"html": ("text/html; charset=utf-8", reporting.render_html), "json": ("application/json", reporting.render_json),
           "pdf": ("application/pdf", reporting.render_pdf)}


@login_required
def case_report(request, cid, fmt):
    if fmt not in _RENDER:
        raise Http404
    case = _get(cid)
    report = services.build_case_report(case, request.user)
    ctype, fn = _RENDER[fmt]
    response = HttpResponse(fn(report), content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="eagleeye-{case.case_id}.{fmt}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    log_event(request, "case.report_exported", target=case.case_id, detail=f"format={fmt}")
    return response
