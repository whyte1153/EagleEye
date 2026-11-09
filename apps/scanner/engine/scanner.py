"""Orchestrates a scan: validate -> fetch -> run checks.  Pure Python, no Django."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from .checks import ALL_CHECKS, ScanContext
from .datatypes import SEVERITY_LABELS
from .fetcher import fetch_chain, probe_http_upgrade
from .ssrf import InvalidTarget, ResolveError, ScanPolicy, TargetBlocked, normalize_url


@dataclass
class ScanOutcome:
    status: str  # completed | failed | blocked
    normalized_url: str = ""
    host: str = ""
    error: str = ""
    final_url: str = ""
    final_status: int | None = None
    response_time_ms: int | None = None
    duration_ms: int = 0
    hops: list = field(default_factory=list)
    tls: dict | None = None
    checks: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def severity_counts(self) -> dict:
        counts = {label: 0 for label in SEVERITY_LABELS.values()}
        for f in self.findings:
            counts[SEVERITY_LABELS[f.severity]] += 1
        return counts


def run_scan(raw_url: str, policy: ScanPolicy) -> ScanOutcome:
    started = time.monotonic()

    def done(outcome: ScanOutcome) -> ScanOutcome:
        outcome.duration_ms = int((time.monotonic() - started) * 1000)
        return outcome

    try:
        target = normalize_url(raw_url)
    except InvalidTarget as exc:
        return done(ScanOutcome("blocked", error=str(exc)))
    base = dict(normalized_url=target.url, host=target.host)

    try:
        fetched = fetch_chain(target.url, policy)
    except (TargetBlocked, InvalidTarget) as exc:
        return done(ScanOutcome("blocked", error=getattr(exc, "reason", str(exc)), **base))
    except ResolveError as exc:
        return done(ScanOutcome("failed", error=str(exc), **base))

    if not fetched.hops:
        return done(ScanOutcome("failed", error=fetched.error or "No response received.", **base))

    probe = None
    try:
        probe = probe_http_upgrade(target, policy)
    except Exception:  # the probe is best-effort and must never fail the scan
        probe = None

    ctx = ScanContext(start_url=target.url, fetch=fetched, probe=probe)
    checks, findings = [], []
    for check in ALL_CHECKS:
        result = check(ctx)
        findings.extend(result.findings)
        checks.append({"check_id": result.check_id, "title": result.title,
                       "outcome": result.outcome, "detail": result.detail})
    findings.sort(key=lambda f: (-f.severity, f.check_id))

    final = fetched.hops[-1]
    return done(ScanOutcome(
        status="completed", error=fetched.error, final_url=final.url, final_status=final.status,
        response_time_ms=final.elapsed_ms, hops=[asdict(h) for h in fetched.hops],
        tls=asdict(fetched.tls) if fetched.tls else None, checks=checks, findings=findings, **base,
    ))
