"""Plain data types shared by the scanner engine (no Django imports)."""
from __future__ import annotations

from dataclasses import dataclass, field

# Severity levels, ordered. CRITICAL is reserved: no current check produces it,
# because header/cookie/TLS-configuration checks cannot prove a critical flaw.
INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
SEVERITY_LABELS = {INFO: "Informational", LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical"}


@dataclass
class Hop:
    """One HTTP response in the redirect chain."""
    url: str
    status: int
    reason: str
    headers: list  # list of [name, value] pairs (duplicates such as Set-Cookie are kept)
    elapsed_ms: int
    ip: str
    location: str = ""
    body_bytes: int = 0
    body_truncated: bool = False


@dataclass
class TlsInfo:
    version: str = ""
    cipher: str = ""
    verified: bool = True
    error: str = ""
    not_after: str = ""
    days_left: int | None = None
    issuer: str = ""
    subject: str = ""


@dataclass
class FetchResult:
    hops: list = field(default_factory=list)
    tls: TlsInfo | None = None
    error: str = ""
    redirect_blocked: dict | None = None  # {"location": ..., "reason": ...}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: int
    description: str
    impact: str
    remediation: str
    evidence: str
    reproduce: str


@dataclass
class CheckResult:
    check_id: str
    title: str
    outcome: str  # "pass" | "fail" | "skip"
    detail: str = ""
    findings: list = field(default_factory=list)
