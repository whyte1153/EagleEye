"""Glue between the Django models and the pure-Python scanner engine."""
from __future__ import annotations

import logging
import threading
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.audit.services import log_event

from .engine.datatypes import SEVERITY_LABELS
from .engine.scanner import ScanOutcome, run_scan
from .engine.ssrf import InvalidTarget, ScanPolicy, normalize_url
from .models import Finding, Scan

logger = logging.getLogger(__name__)

_slots: threading.BoundedSemaphore | None = None
_slots_lock = threading.Lock()


class RateLimited(Exception):
    pass


class ScannerBusy(Exception):
    pass


def policy_from_settings() -> ScanPolicy:
    return ScanPolicy(
        lab_mode=settings.EAGLEEYE_LAB_MODE,
        lab_targets=tuple(settings.EAGLEEYE_LAB_TARGETS),
        allowed_ports=frozenset(settings.SCAN_ALLOWED_PORTS),
        timeout=float(settings.SCAN_TIMEOUT_SECONDS),
        max_body_bytes=settings.SCAN_MAX_BODY_BYTES,
        deadline=float(settings.SCAN_DEADLINE_SECONDS),
    )


def _get_slots() -> threading.BoundedSemaphore:
    global _slots
    with _slots_lock:
        if _slots is None:
            _slots = threading.BoundedSemaphore(max(1, settings.SCAN_MAX_CONCURRENT))
        return _slots


def is_rate_limited(user) -> bool:
    window_start = timezone.now() - timedelta(minutes=10)
    return Scan.objects.filter(created_by=user, created_at__gte=window_start).count() >= settings.SCAN_RATE_LIMIT


def execute_scan(request, user, raw_url: str, note: str = "") -> Scan:
    """Run a scan synchronously and save the result.

    Raises RateLimited / ScannerBusy before doing any network work.
    Scans run inside the web request: simple and predictable, bounded by the
    per-request timeout and overall deadline (see settings).  If you later need
    long scans, move this call into a background worker.
    """
    if is_rate_limited(user):
        log_event(request, "scan.rate_limited", target=raw_url[:255])
        raise RateLimited

    try:
        host = normalize_url(raw_url).host
    except InvalidTarget:
        host = ""
    scan = Scan.objects.create(
        target_url=raw_url[:2048], host=host[:255], status=Scan.RUNNING, created_by=user,
        started_at=timezone.now(), authorization_confirmed=True, authorization_note=note[:300],
    )

    slots = _get_slots()
    if not slots.acquire(blocking=False):
        scan.status, scan.finished_at = Scan.FAILED, timezone.now()
        scan.error_message = "The scanner is busy with other scans. Please try again shortly."
        scan.save(update_fields=["status", "finished_at", "error_message"])
        raise ScannerBusy
    try:
        outcome = run_scan(raw_url, policy_from_settings())
    except Exception:  # never show internals to the user
        logger.exception("Unexpected scanner failure for scan %s", scan.pk)
        outcome = ScanOutcome("failed", error="Internal scanner error. The details were written to the server log.")
    finally:
        slots.release()

    save_outcome(scan, outcome)
    action = "scan.blocked" if outcome.status == "blocked" else "scan.run"
    log_event(request, action, target=(outcome.normalized_url or raw_url)[:255],
              detail=f"scan #{scan.pk} status={outcome.status} findings={scan.findings_count}"
                     + (f" reason={outcome.error}" if outcome.error else ""))
    return scan


def save_outcome(scan: Scan, outcome: ScanOutcome) -> None:
    counts = outcome.severity_counts()
    with transaction.atomic():
        scan.status = outcome.status
        scan.normalized_url = outcome.normalized_url[:2048]
        scan.host = (outcome.host or scan.host)[:255]
        scan.error_message = outcome.error
        scan.final_url = outcome.final_url[:2048]
        scan.final_status_code = outcome.final_status
        scan.response_time_ms = outcome.response_time_ms
        scan.duration_ms = outcome.duration_ms
        scan.hops, scan.tls, scan.checks = outcome.hops, outcome.tls, outcome.checks
        scan.severity_counts = counts
        scan.findings_count = len(outcome.findings)
        scan.highest_severity = max((f.severity for f in outcome.findings), default=-1)
        scan.finished_at = timezone.now()
        scan.save()
        Finding.objects.bulk_create([
            Finding(scan=scan, check_id=f.check_id, title=f.title, severity=f.severity, description=f.description,
                    impact=f.impact, remediation=f.remediation, evidence=f.evidence, reproduce=f.reproduce)
            for f in outcome.findings
        ])


def scan_to_report_dict(scan: Scan) -> dict:
    """Everything a report needs, taken from saved rows only."""
    return {
        "id": scan.pk,
        "generated_at": timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target": scan.target_url,
        "normalized_url": scan.normalized_url or scan.target_url,
        "status": scan.status,
        "error": scan.error_message,
        "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "",
        "duration_ms": scan.duration_ms,
        "final_url": scan.final_url,
        "final_status_code": scan.final_status_code,
        "response_time_ms": scan.response_time_ms,
        "scanned_by": scan.created_by.get_username() if scan.created_by else "",
        "authorization_note": scan.authorization_note,
        "severity_counts": scan.severity_counts or {label: 0 for label in SEVERITY_LABELS.values()},
        "hops": scan.hops,
        "tls": scan.tls,
        "checks": scan.checks,
        "findings": [
            {"check_id": f.check_id, "title": f.title, "severity": f.severity, "severity_label": f.severity_label,
             "description": f.description, "impact": f.impact, "remediation": f.remediation,
             "evidence": f.evidence, "reproduce": f.reproduce}
            for f in scan.findings.all()
        ],
    }


def diff_scans(older: Scan, newer: Scan) -> dict:
    """Compare two scans by (check, title): what is new, what was resolved, what persists."""
    def key(f):
        return (f.check_id, f.title)

    old = {key(f): f for f in older.findings.all()}
    new = {key(f): f for f in newer.findings.all()}
    return {
        "new": [new[k] for k in new if k not in old],
        "resolved": [old[k] for k in old if k not in new],
        "unchanged": [new[k] for k in new if k in old],
        "changed_severity": [(old[k], new[k]) for k in new if k in old and old[k].severity != new[k].severity],
    }
