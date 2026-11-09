"""Evidence workflows: ingest, verify, analyse, custody log, reports.  Glue between the engine and the database."""
from __future__ import annotations

import ipaddress
import logging
import os
from datetime import timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit.services import log_event

from .engine import custody
from .engine.filetype import analyze_file
from .engine.sanitize import safe_display_name
from .engine.storage import EvidenceStore, IntegrityError
from .models import CustodyEvent, EvidenceItem, EvidenceNote

logger = logging.getLogger(__name__)

_store: EvidenceStore | None = None


class DownloadRefused(Exception):
    """Raised when an item fails its pre-download integrity check."""


def get_store() -> EvidenceStore:
    """The evidence store (created on first use; never inside a web-served directory)."""
    global _store
    root = Path(settings.EVIDENCE_ROOT).resolve()
    if _store is None or _store.root != root:
        base = Path(settings.BASE_DIR)
        _store = EvidenceStore(root, forbidden_roots=[base / "static", base / "staticfiles", base / "templates",
                                                      base / "media", base / "eagleeye"])
    return _store


def fmt_dt(dt) -> str:
    return dt.astimezone(dt_timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


# ------------------------------------------------------------ custody log
def _client_ip(request) -> str:
    raw = request.META.get("REMOTE_ADDR") if request is not None else None
    try:
        return ipaddress.ip_address(raw).compressed if raw else ""
    except ValueError:
        return ""


def add_event(evidence: EvidenceItem, action: str, request=None, actor=None, detail: str = "") -> CustodyEvent:
    """Append a hash-chained custody event (and mirror it to the global audit log)."""
    user = actor
    if user is None and request is not None and getattr(request, "user", None) and request.user.is_authenticated:
        user = request.user
    actor_name = user.get_username()[:150] if user else ""
    ip = _client_ip(request)
    with transaction.atomic():
        EvidenceItem.objects.select_for_update().filter(pk=evidence.pk).first()  # serialise writers per item
        last = CustodyEvent.objects.filter(evidence=evidence).order_by("-id").first()
        prev = last.entry_hash if last else custody.GENESIS
        now = timezone.now()
        entry_hash = custody.compute_entry_hash(prev, evidence.evidence_id, action, actor_name, detail,
                                                now.astimezone(dt_timezone.utc).isoformat(), ip)
        event = CustodyEvent.objects.create(
            evidence=evidence, actor=user, actor_name=actor_name, action=action, detail=detail,
            ip_address=ip or None, created_at=now, prev_hash=prev, entry_hash=entry_hash)
    log_event(request, f"evidence.{action}", target=evidence.evidence_id, detail=detail[:500], actor=user)
    return event


def chain_status(evidence: EvidenceItem):
    events = list(evidence.events.all())
    entries = [{
        "evidence_id": evidence.evidence_id, "action": e.action, "actor": e.actor_name, "detail": e.detail,
        "created_iso": e.created_at.astimezone(dt_timezone.utc).isoformat(), "ip": e.ip_address or "",
        "prev_hash": e.prev_hash, "entry_hash": e.entry_hash} for e in events]
    ok, bad, message = custody.verify_chain(entries)
    return ok, bad, message, events


# ---------------------------------------------------------------- analysis
def _safe_analyze(path, name, size, times) -> dict:
    try:
        return analyze_file(path, name, size, times)
    except Exception:  # a parser problem must never lose the evidence
        logger.exception("Analysis failed for %s", name)
        return {"detected_kind": "analysis-failed", "detected_mime": "", "detected_category": "unknown",
                "declared_extension": "", "extension_severity": "info",
                "extension_note": "Automatic analysis failed; the file was preserved and hashed.", "mismatch": False,
                "metadata": {}}


def _apply_analysis(ev: EvidenceItem, a: dict) -> None:
    ev.detected_kind = a["detected_kind"][:40]
    ev.detected_mime = a["detected_mime"][:120]
    ev.detected_category = a["detected_category"][:20]
    ev.declared_extension = a["declared_extension"][:20]
    ev.extension_severity = a["extension_severity"]
    ev.extension_note = a["extension_note"]
    ev.mismatch = bool(a["mismatch"])
    ev.metadata = {**a.get("metadata", {}), "analyzed_at": a.get("analyzed_at", "")}


def ingest_upload(request, user, upload, description: str = "", case_reference: str = "") -> EvidenceItem:
    """Store, hash and analyse an uploaded file.  Raises storage.TooLarge / EmptyFile on rejected input."""
    store = get_store()
    display = safe_display_name(upload.name)
    stored = store.ingest(upload.chunks(), settings.EVIDENCE_MAX_BYTES)  # streams; hashes while writing
    try:
        times = store.stat_times(stored.name)
        with store.working_copy(stored.name, stored.sha256) as work:  # analysis never touches the original
            analysis = _safe_analyze(work, display, stored.size, times)
        with transaction.atomic():
            ev = EvidenceItem(
                original_filename=display, stored_name=stored.name, size=stored.size, sha256=stored.sha256,
                md5=stored.md5, case_reference=case_reference[:100], description=description[:2000],
                uploaded_by=user, integrity_status=EvidenceItem.VERIFIED, last_verified_at=timezone.now(),
                last_verified_by=user)
            _apply_analysis(ev, analysis)
            ev.save()
            ev.evidence_id = f"EV-{ev.uploaded_at.year}-{ev.pk:06d}"
            ev.save(update_fields=["evidence_id"])
            add_event(ev, "uploaded", request, user,
                      f"name={display}; size={stored.size}; sha256={stored.sha256}; md5={stored.md5}")
            add_event(ev, "analyzed", request, user,
                      f"type={ev.detected_kind}; extension_check={ev.extension_severity}")
        return ev
    except BaseException:
        # The row was not committed: remove the orphaned file we just wrote (it is ours alone).
        try:
            p = store.path(stored.name)
            os.chmod(p, 0o600)
            p.unlink()
        except OSError:
            pass
        raise


def verify_integrity(request, user, evidence: EvidenceItem) -> str:
    """Re-hash the stored original and compare with the recorded SHA-256.  Returns the new status."""
    result = get_store().verify(evidence.stored_name, evidence.sha256)
    evidence.integrity_status = {"verified": EvidenceItem.VERIFIED, "failed": EvidenceItem.FAILED,
                                 "missing": EvidenceItem.MISSING}[result.status]
    evidence.last_verified_at = timezone.now()
    evidence.last_verified_by = user
    evidence.save(update_fields=["integrity_status", "last_verified_at", "last_verified_by"])
    if result.status == "verified":
        add_event(evidence, "integrity_verified", request, user, "SHA-256 matches the recorded value.")
    elif result.status == "failed":
        add_event(evidence, "integrity_failed", request, user,
                  f"MISMATCH expected={evidence.sha256} actual={result.actual_sha256}")
    else:
        add_event(evidence, "integrity_missing", request, user, "Stored original could not be found.")
    return evidence.integrity_status


def reanalyze(request, user, evidence: EvidenceItem) -> None:
    """Re-run analysis on a verified working copy.  Raises IntegrityError if the original changed."""
    store = get_store()
    try:
        with store.working_copy(evidence.stored_name, evidence.sha256) as work:
            analysis = _safe_analyze(work, evidence.original_filename, evidence.size, store.stat_times(evidence.stored_name))
    except IntegrityError:
        verify_integrity(request, user, evidence)  # record the failure in the custody log
        raise
    _apply_analysis(evidence, analysis)
    evidence.save()
    add_event(evidence, "reanalyzed", request, user,
              f"type={evidence.detected_kind}; extension_check={evidence.extension_severity}")


def open_for_download(request, user, evidence: EvidenceItem):
    """Verify, log, and return an open binary file handle.  Refuses if integrity fails."""
    status = verify_integrity(request, user, evidence)
    if status != EvidenceItem.VERIFIED:
        raise DownloadRefused(status)
    add_event(evidence, "downloaded", request, user, "Original file downloaded.")
    return open(get_store().path(evidence.stored_name), "rb")


def add_note(request, user, evidence: EvidenceItem, text: str) -> EvidenceNote:
    with transaction.atomic():
        note = EvidenceNote.objects.create(evidence=evidence, author=user, author_name=user.get_username(), text=text)
        add_event(evidence, "note_added", request, user, f"note #{note.pk} ({len(text)} characters)")
    return note


# ----------------------------------------------------------------- reports
def item_dict(ev: EvidenceItem, full: bool = False) -> dict:
    d = {
        "evidence_id": ev.evidence_id, "original_filename": ev.original_filename, "size": ev.size, "sha256": ev.sha256,
        "md5": ev.md5, "declared_extension": ev.declared_extension, "detected_kind": ev.detected_kind,
        "detected_mime": ev.detected_mime, "extension_severity": ev.extension_severity,
        "extension_note": ev.extension_note,
        "uploaded_by": ev.uploaded_by.get_username() if ev.uploaded_by else "", "uploaded_at": fmt_dt(ev.uploaded_at),
        "case_reference": ev.case_reference, "description": ev.description, "integrity_status": ev.integrity_status,
        "last_verified_at": fmt_dt(ev.last_verified_at),
        "last_verified_by": ev.last_verified_by.get_username() if ev.last_verified_by else "",
    }
    if full:
        ok, _bad, message, events = chain_status(ev)
        d["metadata"] = ev.metadata
        d["notes"] = [{"author": n.author_name, "created_at": fmt_dt(n.created_at), "text": n.text} for n in ev.notes.all()]
        d["events"] = [{"created_at": fmt_dt(e.created_at), "actor": e.actor_name, "action": e.action, "detail": e.detail,
                        "ip": e.ip_address or "", "prev_hash": e.prev_hash, "entry_hash": e.entry_hash} for e in events]
        d["chain"] = {"ok": ok, "message": message}
    return d


def summary_of(items) -> dict:
    def n(status):
        return sum(1 for i in items if i["integrity_status"] == status)
    return {"total": len(items), "verified": n("verified"), "failed": n("failed"), "missing": n("missing"),
            "unverified": n("unverified"), "mismatches": sum(1 for i in items if i["extension_severity"] in ("warn", "high"))}


def build_report(title: str, kind: str, evidence_qs, user, full: bool) -> dict:
    items = [item_dict(e, full=full) for e in evidence_qs]
    return {"title": title, "kind": kind, "generated_at": fmt_dt(timezone.now()),
            "generated_by": user.get_username(), "summary": summary_of(items), "items": items}
