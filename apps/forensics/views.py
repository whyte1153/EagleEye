import re
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, has_role
from apps.audit.services import log_event

from . import reports
from .engine.storage import EmptyFile, IntegrityError, StorageError, TooLarge
from .forms import EvidenceUploadForm, NoteForm
from .models import EvidenceItem
from .services import (DownloadRefused, add_event, add_note, build_report, chain_status, ingest_upload, item_dict,
                       fmt_dt, open_for_download, reanalyze, summary_of, verify_integrity)

EID_RE = re.compile(r"^EV-\d{4}-\d{6}$")


def _can_modify(user) -> bool:
    return has_role(user, ROLE_ADMIN, ROLE_INVESTIGATOR)


def _require_modify(request):
    if not _can_modify(request.user):
        raise PermissionDenied


def _get_item(eid: str) -> EvidenceItem:
    if not EID_RE.fullmatch(eid):
        raise Http404
    return get_object_or_404(EvidenceItem.objects.select_related("uploaded_by", "last_verified_by"), evidence_id=eid)


@login_required
def home(request):
    can_modify = _can_modify(request.user)
    status = 200
    if request.method == "POST":
        _require_modify(request)
        form = EvidenceUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                ev = ingest_upload(request, request.user, form.cleaned_data["file"],
                                   form.cleaned_data["description"], form.cleaned_data["case_reference"])
            except TooLarge:
                form.add_error("file", f"File is larger than the {settings.EVIDENCE_MAX_BYTES // (1024 * 1024)} MB limit.")
                status = 413
            except EmptyFile:
                form.add_error("file", "The file is empty.")
                status = 400
            except StorageError:
                form.add_error(None, "The file could not be stored safely.")
                status = 400
            else:
                messages.success(request, f"{ev.evidence_id} stored and hashed.")
                return redirect(ev)
        else:
            status = 400
    else:
        form = EvidenceUploadForm()

    items = EvidenceItem.objects.all()
    all_items = list(items.values("integrity_status", "extension_severity"))
    stats = summary_of(all_items)
    return render(request, "forensics/home.html", {
        "form": form, "can_modify": can_modify, "stats": stats, "recent": items.select_related("uploaded_by")[:6],
        "max_mb": settings.EVIDENCE_MAX_BYTES // (1024 * 1024),
    }, status=status)


def _filtered(request):
    qs = EvidenceItem.objects.select_related("uploaded_by", "last_verified_by")
    q = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip()
    flag = request.GET.get("flag", "").strip()
    if q:
        qs = qs.filter(Q(evidence_id__icontains=q) | Q(original_filename__icontains=q) | Q(sha256__icontains=q)
                       | Q(case_reference__icontains=q) | Q(md5__icontains=q))
    if status in dict(EvidenceItem.INTEGRITY_CHOICES):
        qs = qs.filter(integrity_status=status)
    if flag == "mismatch":
        qs = qs.filter(mismatch=True)
    return qs, q, status, flag


@login_required
def vault(request):
    qs, q, status, flag = _filtered(request)
    page = Paginator(qs, 20).get_page(request.GET.get("page"))
    return render(request, "forensics/vault.html", {
        "page": page, "q": q, "status": status, "flag": flag, "status_choices": EvidenceItem.INTEGRITY_CHOICES,
        "can_modify": _can_modify(request.user),
        "pager_query": urlencode({k: v for k, v in {"q": q, "status": status, "flag": flag}.items() if v}),
    })


@login_required
def detail(request, eid: str):
    ev = _get_item(eid)
    ok, bad, message, events = chain_status(ev)
    meta = ev.metadata or {}
    simple = {k: v for k, v in meta.items() if not isinstance(v, (list, dict))}
    return render(request, "forensics/detail.html", {
        "ev": ev, "can_modify": _can_modify(request.user), "note_form": NoteForm(),
        "notes": ev.notes.all(), "events": events, "chain_ok": ok, "chain_bad": bad, "chain_message": message,
        "meta_simple": simple, "zip_entries": meta.get("entries"), "fs_times": meta.get("filesystem_timestamps"),
        "caveat": reports.CAVEAT,
    })


@login_required
@require_POST
def verify(request, eid: str):
    _require_modify(request)
    ev = _get_item(eid)
    status = verify_integrity(request, request.user, ev)
    (messages.success if status == "verified" else messages.error)(
        request, "Integrity verified: the file matches its recorded SHA-256." if status == "verified"
        else f"INTEGRITY CHECK {status.upper()}. This has been recorded in the chain of custody.")
    return redirect(ev)


@login_required
@require_POST
def reanalyze_view(request, eid: str):
    _require_modify(request)
    ev = _get_item(eid)
    try:
        reanalyze(request, request.user, ev)
        messages.success(request, "Analysis re-run on a verified working copy.")
    except IntegrityError:
        messages.error(request, "Analysis refused: the stored original no longer matches its recorded hash.")
    return redirect(ev)


@login_required
@require_POST
def add_note_view(request, eid: str):
    _require_modify(request)
    ev = _get_item(eid)
    form = NoteForm(request.POST)
    if form.is_valid():
        add_note(request, request.user, ev, form.cleaned_data["text"])
        messages.success(request, "Note added.")
    else:
        messages.error(request, "Note was empty or too long (2000 characters max).")
    return redirect(ev)


@login_required
def download(request, eid: str):
    _require_modify(request)  # raw evidence (possibly malware) is restricted to administrators and investigators
    ev = _get_item(eid)
    try:
        handle = open_for_download(request, request.user, ev)
    except DownloadRefused as exc:
        messages.error(request, f"Download refused: integrity check result is '{exc}'. Recorded in the chain of custody.")
        return redirect(ev)
    response = FileResponse(handle, as_attachment=True, filename=ev.original_filename, content_type="application/octet-stream")
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "no-store"
    response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@login_required
@require_POST
def verify_all(request):
    _require_modify(request)
    counts = {"verified": 0, "failed": 0, "missing": 0}
    for ev in EvidenceItem.objects.all()[:200]:
        counts[verify_integrity(request, request.user, ev)] += 1
    level = messages.SUCCESS if not counts["failed"] and not counts["missing"] else messages.ERROR
    messages.add_message(request, level, f"Verified {counts['verified']}, FAILED {counts['failed']}, missing {counts['missing']} (up to 200 items per run).")
    return redirect("forensics:vault")


# ------------------------------------------------------------------ exports
def _send(request, body: bytes, content_type: str, filename: str, action: str, target: str) -> HttpResponse:
    response = HttpResponse(body, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    log_event(request, action, target=target)
    return response


@login_required
def export_inventory(request, fmt: str):
    qs, *_ = _filtered(request)
    items = [item_dict(e) for e in qs]
    if fmt == "csv":
        return _send(request, reports.render_inventory_csv(items), "text/csv; charset=utf-8",
                     "eagleeye-evidence-inventory.csv", "evidence.inventory_exported", "csv")
    if fmt == "json":
        report = {"title": "Evidence inventory", "kind": "inventory", "generated_at": "", "generated_by": request.user.get_username(),
                  "summary": summary_of(items), "items": items}
        report["generated_at"] = fmt_dt(timezone.now())
        return _send(request, reports.render_json(report), "application/json", "eagleeye-evidence-inventory.json",
                     "evidence.inventory_exported", "json")
    raise Http404


_RENDER = {"html": ("text/html; charset=utf-8", reports.render_html), "json": ("application/json", reports.render_json),
           "pdf": ("application/pdf", reports.render_pdf)}


@login_required
def integrity_report(request, fmt: str):
    if fmt not in _RENDER:
        raise Http404
    qs, *_ = _filtered(request)
    report = build_report("Evidence integrity report", "integrity", qs, request.user, full=False)
    ctype, fn = _RENDER[fmt]
    return _send(request, fn(report), ctype, f"eagleeye-integrity-report.{fmt}", "evidence.integrity_report_exported", fmt)


@login_required
def item_report(request, eid: str, fmt: str):
    if fmt not in _RENDER:
        raise Http404
    ev = _get_item(eid)
    report = build_report(f"Evidence record {ev.evidence_id}", "item", [ev], request.user, full=True)
    ctype, fn = _RENDER[fmt]
    return _send(request, fn(report), ctype, f"eagleeye-{ev.evidence_id}.{fmt}", "evidence.record_exported",
                 f"{ev.evidence_id} ({fmt})")
