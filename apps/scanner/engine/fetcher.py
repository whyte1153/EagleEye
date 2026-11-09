"""Safe HTTP(S) fetching.

* Resolves DNS itself, validates every address (ssrf.py) and then connects to
  that exact IP, so there is no second lookup an attacker could poison.
* Follows redirects manually; every hop is re-validated; unapproved
  destinations are recorded but never contacted.
* Hard limits: per-request timeout, overall deadline, body-size cap, redirect cap.
* Only GET requests are made; response bodies are never executed or stored.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import time
from urllib.parse import urljoin

from .datatypes import FetchResult, Hop, TlsInfo
from .ssrf import (InvalidTarget, ResolveError, ScanPolicy, Target, TargetBlocked,
                   normalize_url, resolve_and_validate)

USER_AGENT = "EagleEye-Scanner/1.0 (authorized security assessment)"
REDIRECT_CODES = {301, 302, 303, 307, 308}


class _PinnedConnection(http.client.HTTPConnection):
    """HTTP(S) connection that dials a pre-validated IP but keeps the real Host/SNI."""

    def __init__(self, host, port, ip, timeout, context=None):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        if self._ctx is not None:
            try:
                sock = self._ctx.wrap_socket(sock, server_hostname=self.host)
            except BaseException:
                sock.close()
                raise
        self.sock = sock


def _context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _redact_header(name: str, value: str) -> list:
    """Never keep cookie VALUES: they can be live session tokens.  Names and flags are kept."""
    if name.lower() == "set-cookie":
        first, sep, rest = value.partition(";")
        cookie_name = first.split("=", 1)[0].strip()
        value = f"{cookie_name}=<redacted>{sep}{rest}"
    return [name, value]


def _name(rdn_sequence) -> str:
    parts = []
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def fetch_one(target: Target, ip: str, policy: ScanPolicy, verify: bool, timeout: float):
    """One GET request to ``ip``.  Returns (Hop, TlsInfo | None)."""
    ctx = _context(verify) if target.scheme == "https" else None
    conn = _PinnedConnection(target.host, target.port, ip, timeout, ctx)
    started = time.monotonic()
    try:
        conn.request("GET", target.path, headers={
            "User-Agent": USER_AGENT, "Accept": "*/*",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        # Read TLS details now: http.client closes the socket once a
        # "Connection: close" response has been received.
        tls = None
        if isinstance(conn.sock, ssl.SSLSocket):
            tls = TlsInfo(version=conn.sock.version() or "", verified=verify)
            cipher = conn.sock.cipher()
            tls.cipher = cipher[0] if cipher else ""
            cert = conn.sock.getpeercert() if verify else None
            if cert:
                tls.not_after = cert.get("notAfter", "")
                tls.issuer = _name(cert.get("issuer"))
                tls.subject = _name(cert.get("subject"))
                try:
                    tls.days_left = int((ssl.cert_time_to_seconds(tls.not_after) - time.time()) // 86400)
                except (ValueError, OverflowError):
                    tls.days_left = None

        response = conn.getresponse()
        body = response.read(policy.max_body_bytes + 1)
        elapsed = int((time.monotonic() - started) * 1000)

        hop = Hop(
            url=target.url, status=response.status, reason=response.reason or "",
            headers=[_redact_header(k, v) for k, v in response.getheaders()], elapsed_ms=elapsed, ip=ip,
            location=response.getheader("Location") or "",
            body_bytes=min(len(body), policy.max_body_bytes),
            body_truncated=len(body) > policy.max_body_bytes,
        )
        return hop, tls
    finally:
        conn.close()


def _attempt(target, ips, policy, deadline):
    """Try validated IPs in turn; on a bad certificate retry unverified to still inspect headers."""
    last_exc: Exception | None = None
    for ip in ips[:3]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Scan deadline exceeded.")
        timeout = min(policy.timeout, remaining)
        try:
            try:
                return fetch_one(target, ip, policy, True, timeout)
            except ssl.SSLCertVerificationError as exc:
                message = f"{exc.verify_message} (code {exc.verify_code})"
                hop, tls = fetch_one(target, ip, policy, False, max(0.5, min(timeout, deadline - time.monotonic())))
                if tls is None:
                    tls = TlsInfo()
                tls.verified = False
                tls.error = message
                return hop, tls
        except (TimeoutError, socket.timeout):
            raise
        except (ConnectionError, OSError) as exc:
            if isinstance(exc, ssl.SSLError):
                raise
            last_exc = exc
    raise last_exc or ConnectionError("Connection failed.")


def fetch_chain(start_url: str, policy: ScanPolicy) -> FetchResult:
    """Fetch ``start_url`` and follow redirects.

    Raises TargetBlocked / InvalidTarget when the *initial* target is not allowed.
    Later problems are recorded on the result instead.
    """
    result = FetchResult()
    deadline = time.monotonic() + policy.deadline
    target = normalize_url(start_url)

    for index in range(policy.max_redirects + 1):
        try:
            ips = resolve_and_validate(target, policy)
        except TargetBlocked as exc:
            if index == 0:
                raise
            result.redirect_blocked = {"location": target.url, "reason": exc.reason}
            return result
        except ResolveError as exc:
            if index == 0:
                raise
            result.redirect_blocked = {"location": target.url, "reason": str(exc)}
            return result

        try:
            hop, tls = _attempt(target, ips, policy, deadline)
        except (TimeoutError, socket.timeout):
            result.error = "The request timed out."
            return result
        except ssl.SSLError as exc:
            result.error = f"TLS handshake failed: {(exc.reason or type(exc).__name__)}"
            return result
        except (OSError, http.client.HTTPException, ValueError) as exc:
            result.error = f"Connection or protocol error: {type(exc).__name__}: {str(exc)[:120]}"
            return result

        result.hops.append(hop)
        if tls is not None:
            result.tls = tls

        if hop.status in REDIRECT_CODES and hop.location:
            try:
                target = normalize_url(urljoin(target.url, hop.location))
            except InvalidTarget as exc:
                result.redirect_blocked = {"location": hop.location[:300], "reason": str(exc)}
                return result
            continue
        return result

    result.error = f"Too many redirects (more than {policy.max_redirects})."
    return result


def probe_http_upgrade(target: Target, policy: ScanPolicy) -> dict | None:
    """For https targets on port 443, request http://host/ once (no redirects followed).

    Returns None when not applicable, else a dict with ``status``/``location`` or ``error``/``skipped``.
    """
    if target.scheme != "https" or target.port != 443:
        return None
    shown = f"[{target.host}]" if ":" in target.host else target.host
    try:
        plain = normalize_url(f"http://{shown}/")
        ips = resolve_and_validate(plain, policy)
    except (TargetBlocked, InvalidTarget, ResolveError) as exc:
        return {"skipped": str(getattr(exc, "reason", exc))}
    try:
        hop, _ = _attempt(plain, ips, policy, time.monotonic() + policy.timeout + 1)
    except (OSError, http.client.HTTPException, ValueError):
        return {"error": "No response on HTTP port 80."}
    return {"status": hop.status, "location": hop.location}
