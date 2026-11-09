"""Security checks.

Every check inspects only data actually collected by the fetcher and returns a
``CheckResult`` (pass / fail / skip) plus zero or more ``Finding`` objects.
Each finding carries a ``reproduce`` command so a person can confirm it
independently with curl.  Cookie VALUES are never stored; only names/flags.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .datatypes import (HIGH, INFO, LOW, MEDIUM, CheckResult, FetchResult, Finding)


@dataclass
class ScanContext:
    start_url: str
    fetch: FetchResult
    probe: dict | None = None
    hops: list = field(init=False)

    def __post_init__(self):
        self.hops = self.fetch.hops

    @property
    def final(self):
        return self.hops[-1] if self.hops else None

    @property
    def final_is_https(self) -> bool:
        return bool(self.final) and self.final.url.lower().startswith("https://")


# ---------------------------------------------------------------- helpers
def header(hop, name: str) -> str | None:
    values = [v for k, v in hop.headers if k.lower() == name.lower()]
    return ", ".join(values) if values else None


def _curl(url: str, grep: str = "") -> str:
    cmd = f"curl -sS -D - -o /dev/null '{url}'"
    return f"{cmd} | grep -i '{grep}'" if grep else cmd


def _finding(check_id, title, severity, description, impact, remediation, evidence, reproduce):
    return Finding(check_id, title, severity, description, impact, remediation, evidence, reproduce)


def _result(check_id, title, findings=None, detail="", skip=False):
    if skip:
        return CheckResult(check_id, title, "skip", detail)
    return CheckResult(check_id, title, "fail" if findings else "pass", detail, findings or [])


# ----------------------------------------------------------- transport
def check_https(ctx):
    cid, title = "https_used", "HTTPS is used for the final response"
    if not ctx.final:
        return _result(cid, title, skip=True, detail="No response received.")
    if ctx.final_is_https:
        return _result(cid, title, detail="Final response was served over HTTPS.")
    return _result(cid, title, [_finding(
        cid, "Site served over unencrypted HTTP", HIGH,
        "The final response was delivered over plain HTTP.",
        "Traffic can be read or modified by anyone on the network path (credentials, cookies, content).",
        "Serve the site over HTTPS with a valid certificate and redirect all HTTP traffic to HTTPS.",
        f"Final URL: {ctx.final.url}", _curl(ctx.final.url))])


def check_downgrade(ctx):
    cid, title = "https_downgrade", "Redirects never downgrade from HTTPS to HTTP"
    for a, b in zip(ctx.hops, ctx.hops[1:]):
        if a.url.startswith("https://") and b.url.startswith("http://"):
            return _result(cid, title, [_finding(
                cid, "Redirect downgrades from HTTPS to HTTP", HIGH,
                "A redirect leads from an HTTPS URL to an HTTP URL.",
                "Users are moved onto an unencrypted connection and can be intercepted.",
                "Redirect only to HTTPS URLs.", f"{a.url} -> {b.url}", _curl(a.url, "location"))])
    return _result(cid, title, detail="No HTTPS to HTTP redirect observed.")


def check_http_upgrade(ctx):
    cid, title = "http_redirects_to_https", "Plain HTTP (port 80) redirects to HTTPS"
    p = ctx.probe
    if p is None:
        return _result(cid, title, skip=True, detail="Only tested for https targets on port 443.")
    if "skipped" in p:
        return _result(cid, title, skip=True, detail=f"Probe not permitted: {p['skipped']}")
    if "error" in p:
        return _result(cid, title, detail="Nothing answered on HTTP port 80 (acceptable).")
    host = urlsplit(ctx.start_url).hostname
    status, loc = p["status"], p.get("location", "")
    if 300 <= status < 400 and loc.lower().startswith("https://"):
        return _result(cid, title, detail=f"HTTP answered {status} and redirects to HTTPS.")
    return _result(cid, title, [_finding(
        cid, "HTTP does not redirect to HTTPS", MEDIUM,
        "Requesting the http:// version returned a response that does not redirect to HTTPS.",
        "Users who type the bare domain or follow an http:// link stay on an unencrypted connection.",
        "Return a 301/308 redirect from http:// to the https:// URL (then add HSTS).",
        f"http://{host}/ -> status {status}" + (f", Location: {loc}" if loc else ""),
        f"curl -sS -D - -o /dev/null 'http://{host}/'")])


def check_redirects(ctx):
    cid, title = "redirect_behaviour", "Redirect chain is short and stays within approved destinations"
    findings = []
    redirects = [h for h in ctx.hops if 300 <= h.status < 400 and h.location]
    f = ctx.fetch
    if f.redirect_blocked:
        findings.append(_finding(
            cid, "Redirect to an unapproved destination was not followed", INFO,
            "The site redirected to a destination that EagleEye's policy does not allow, so it was not contacted.",
            "The scan covers only the response before the redirect. Results for the destination are unknown.",
            "If the destination is also yours, scan it separately.",
            f"Location: {f.redirect_blocked['location']} - {f.redirect_blocked['reason']}",
            _curl(ctx.hops[-1].url if ctx.hops else ctx.start_url, "location")))
    if f.error.startswith("Too many redirects"):
        findings.append(_finding(
            cid, "Redirect chain is too long or loops", LOW,
            "The redirect limit was reached before a final response.",
            "Redirect loops break the site for users and indicate a misconfiguration.",
            "Fix the redirect rules so the chain ends in at most two hops.",
            f.error, f"curl -sSIL --max-redirs 5 '{ctx.start_url}'"))
    elif len(redirects) > 3:
        findings.append(_finding(
            cid, "Long redirect chain", LOW, "More than three redirects were needed to reach the page.",
            "Each hop slows loading and gives more places for misconfiguration.",
            "Redirect directly to the final URL.", " -> ".join(h.url for h in ctx.hops),
            f"curl -sSIL '{ctx.start_url}'"))
    hosts = {urlsplit(h.url).hostname for h in ctx.hops}
    if len(hosts) > 1:
        findings.append(_finding(
            cid, "Redirect crosses to another host", INFO, "The chain visits more than one host name.",
            "Informational: confirm every host in the chain is intended and under your control.",
            "No action needed if expected.", ", ".join(sorted(h for h in hosts if h)),
            f"curl -sSIL '{ctx.start_url}'"))
    return _result(cid, title, findings, detail=f"{len(redirects)} redirect(s) observed.")


# ------------------------------------------------------------- headers
def _hdr_checks(ctx, cid, title, fn):
    if not ctx.final:
        return _result(cid, title, skip=True, detail="No response received.")
    return fn(ctx.final, ctx)


def check_csp(ctx):
    cid, title = "header_csp", "Content-Security-Policy"

    def run(hop, ctx):
        value = header(hop, "Content-Security-Policy")
        url = hop.url
        if not value:
            ro = header(hop, "Content-Security-Policy-Report-Only")
            return _result(cid, title, [_finding(
                cid, "Content-Security-Policy header missing", MEDIUM,
                "The response has no enforced Content-Security-Policy." +
                (" Only a Report-Only policy is present, which does not block anything." if ro else ""),
                "Without CSP, injected scripts (XSS) run unrestricted and data can be exfiltrated.",
                "Add a CSP, e.g. \"default-src 'self'; frame-ancestors 'none'\", and tighten it over time.",
                "Header not present", _curl(url, "content-security-policy"))])
        directives = {}
        for part in value.split(";"):
            bits = part.strip().split()
            if bits:
                directives.setdefault(bits[0].lower(), [t.lower() for t in bits[1:]])
        src = directives.get("script-src") or directives.get("default-src") or []
        problems = []
        if "'unsafe-inline'" in src and not any(t.startswith(("'nonce-", "'sha")) or t == "'strict-dynamic'" for t in src):
            problems.append("'unsafe-inline' allowed for scripts")
        if "'unsafe-eval'" in src:
            problems.append("'unsafe-eval' allowed")
        if any(t in ("*", "data:", "http:", "https:") for t in src):
            problems.append("overly broad script source (" + ", ".join(t for t in src if t in ("*", "data:", "http:", "https:")) + ")")
        if not src:
            problems.append("no script-src or default-src directive")
        if problems:
            return _result(cid, title, [_finding(
                cid, "Weak Content-Security-Policy", LOW,
                "A CSP is present but contains directives that weaken its protection.",
                "A weak CSP gives limited defense against cross-site scripting.",
                "Remove unsafe-inline/unsafe-eval, use nonces or hashes, and list explicit sources.",
                "; ".join(problems) + f" | Policy: {value[:300]}", _curl(url, "content-security-policy"))])
        return _result(cid, title, detail="CSP present with no weak script sources.")

    return _hdr_checks(ctx, cid, title, run)


def check_hsts(ctx):
    cid, title = "header_hsts", "Strict-Transport-Security"
    if not ctx.final:
        return _result(cid, title, skip=True, detail="No response received.")
    if not ctx.final_is_https:
        return _result(cid, title, skip=True, detail="HSTS only applies to HTTPS responses.")
    hop = ctx.final
    value = header(hop, "Strict-Transport-Security")
    if not value:
        return _result(cid, title, [_finding(
            cid, "Strict-Transport-Security header missing", MEDIUM,
            "The HTTPS response does not tell browsers to always use HTTPS.",
            "Users can be downgraded to HTTP on their first visit or after a certificate-stripping attack.",
            "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            "Header not present", _curl(hop.url, "strict-transport-security"))])
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15_552_000:
        return _result(cid, title, [_finding(
            cid, "HSTS max-age is too short", LOW,
            "HSTS is set but for less than 180 days.", "Short lifetimes leave a window for downgrade attacks.",
            "Use max-age of at least 15552000 (180 days); 31536000 is typical.",
            f"Strict-Transport-Security: {value}", _curl(hop.url, "strict-transport-security"))])
    return _result(cid, title, detail=f"max-age={age}.")


def check_xcto(ctx):
    cid, title = "header_xcto", "X-Content-Type-Options"

    def run(hop, ctx):
        value = header(hop, "X-Content-Type-Options")
        if value and value.strip().lower() == "nosniff":
            return _result(cid, title, detail="nosniff set.")
        return _result(cid, title, [_finding(
            cid, "X-Content-Type-Options: nosniff missing", LOW,
            "Browsers may guess (sniff) content types instead of trusting the declared one.",
            "Uploaded or reflected content could be interpreted as script or HTML.",
            "Send 'X-Content-Type-Options: nosniff' on all responses.",
            f"Value: {value}" if value else "Header not present", _curl(hop.url, "x-content-type-options"))])

    return _hdr_checks(ctx, cid, title, run)


def check_xfo(ctx):
    cid, title = "header_xfo", "Clickjacking protection (X-Frame-Options / frame-ancestors)"

    def run(hop, ctx):
        xfo = (header(hop, "X-Frame-Options") or "").strip().upper()
        csp = header(hop, "Content-Security-Policy") or ""
        if "frame-ancestors" in csp.lower() or xfo in ("DENY", "SAMEORIGIN"):
            return _result(cid, title, detail="Framing is restricted.")
        if xfo:
            return _result(cid, title, [_finding(
                cid, "X-Frame-Options has an unsupported value", LOW,
                "The header value is not DENY or SAMEORIGIN (ALLOW-FROM is obsolete and ignored by browsers).",
                "The page may be framed by other sites.", "Use DENY/SAMEORIGIN or CSP frame-ancestors.",
                f"X-Frame-Options: {xfo}", _curl(hop.url, "x-frame-options"))])
        return _result(cid, title, [_finding(
            cid, "No clickjacking protection", MEDIUM,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
            "Another site can embed the page in a hidden frame and trick users into clicking.",
            "Send \"Content-Security-Policy: frame-ancestors 'none'\" (or 'self') and/or X-Frame-Options: DENY.",
            "Both absent", _curl(hop.url, "x-frame-options\\|content-security-policy"))])

    return _hdr_checks(ctx, cid, title, run)


def check_referrer(ctx):
    cid, title = "header_referrer", "Referrer-Policy"

    def run(hop, ctx):
        value = header(hop, "Referrer-Policy")
        if not value:
            return _result(cid, title, [_finding(
                cid, "Referrer-Policy header missing", LOW,
                "No policy controls how much URL information is sent in the Referer header.",
                "Full URLs (possibly containing tokens or identifiers) can leak to other sites.",
                "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
                "Header not present", _curl(hop.url, "referrer-policy"))])
        last = value.split(",")[-1].strip().lower()
        if last in ("unsafe-url", "no-referrer-when-downgrade"):
            return _result(cid, title, [_finding(
                cid, "Referrer-Policy leaks full URLs", LOW,
                f"The policy '{last}' sends the full URL to other origins.",
                "Sensitive URL parts can leak to third parties.",
                "Use strict-origin-when-cross-origin, same-origin or no-referrer.",
                f"Referrer-Policy: {value}", _curl(hop.url, "referrer-policy"))])
        return _result(cid, title, detail=f"Policy: {value}.")

    return _hdr_checks(ctx, cid, title, run)


def check_permissions(ctx):
    cid, title = "header_permissions", "Permissions-Policy"

    def run(hop, ctx):
        if header(hop, "Permissions-Policy"):
            return _result(cid, title, detail="Permissions-Policy present.")
        return _result(cid, title, [_finding(
            cid, "Permissions-Policy header missing", LOW,
            "The page does not restrict powerful browser features (camera, microphone, geolocation...).",
            "Embedded or injected content may request features the site never needs.",
            "Send e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            "Header not present", _curl(hop.url, "permissions-policy"))])

    return _hdr_checks(ctx, cid, title, run)


def check_disclosure(ctx):
    cid, title = "info_disclosure", "Server technology disclosure"

    def run(hop, ctx):
        findings = []
        server = header(hop, "Server")
        if server and re.search(r"\d+\.\d+|/\d", server):
            findings.append(_finding(
                cid, "Server header reveals version", LOW,
                "The Server header includes a software version.",
                "Version details help attackers pick known exploits.",
                "Remove version numbers (e.g. ServerTokens Prod / server_tokens off).",
                f"Server: {server}", _curl(hop.url, "^server:")))
        powered = header(hop, "X-Powered-By")
        if powered:
            findings.append(_finding(
                cid, "X-Powered-By header present", LOW,
                "The response advertises the application framework.", "Helps attackers fingerprint the stack.",
                "Disable the X-Powered-By header.", f"X-Powered-By: {powered}", _curl(hop.url, "x-powered-by")))
        return _result(cid, title, findings, detail="No version disclosure in Server/X-Powered-By." if not findings else "")

    return _hdr_checks(ctx, cid, title, run)


# ------------------------------------------------------------- cookies
_SENSITIVE = re.compile(r"sess|sid|auth|token|jwt|login", re.I)


def parse_cookies(hops):
    """Return [{name, flags..., https}] from every Set-Cookie header. Values are discarded."""
    cookies = []
    for hop in hops:
        for k, v in hop.headers:
            if k.lower() != "set-cookie":
                continue
            parts = [p.strip() for p in v.split(";")]
            name = parts[0].split("=", 1)[0].strip()
            attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "") for p in parts[1:]}
            cookies.append({
                "name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", "").lower(), "https": hop.url.startswith("https://"),
                "url": hop.url,
            })
    return cookies


def _cookie_check(ctx, cid, title, predicate, make):
    if not ctx.hops:
        return _result(cid, title, skip=True, detail="No response received.")
    cookies = parse_cookies(ctx.hops)
    if not cookies:
        return _result(cid, title, skip=True, detail="No cookies were set.")
    findings = [make(c) for c in cookies if predicate(c)]
    return _result(cid, title, findings, detail=f"{len(cookies)} cookie(s) inspected.")


def check_cookie_secure(ctx):
    cid = "cookie_secure"
    return _cookie_check(ctx, cid, "Cookies have the Secure attribute", lambda c: not c["secure"], lambda c: _finding(
        cid, f"Cookie '{c['name']}' lacks the Secure attribute", MEDIUM if c["https"] else LOW,
        "The cookie can be sent over unencrypted HTTP connections.",
        "It can be captured by a network attacker; for session cookies this means account takeover.",
        "Add the Secure attribute to every cookie.", f"Set-Cookie: {c['name']}=<redacted> (no Secure) at {c['url']}",
        _curl(c["url"], "set-cookie")))


def check_cookie_httponly(ctx):
    cid = "cookie_httponly"
    return _cookie_check(ctx, cid, "Cookies have the HttpOnly attribute", lambda c: not c["httponly"], lambda c: _finding(
        cid, f"Cookie '{c['name']}' lacks the HttpOnly attribute", MEDIUM if _SENSITIVE.search(c["name"]) else LOW,
        "JavaScript on the page can read this cookie.",
        "An XSS flaw could steal the cookie" + (" (its name suggests a session or auth value)." if _SENSITIVE.search(c["name"]) else "."),
        "Add HttpOnly unless scripts genuinely need the cookie.", f"Set-Cookie: {c['name']}=<redacted> (no HttpOnly)",
        _curl(c["url"], "set-cookie")))


def check_cookie_samesite(ctx):
    cid = "cookie_samesite"

    def bad(c):
        return c["samesite"] not in ("strict", "lax") if c["samesite"] != "none" else not c["secure"]

    def make(c):
        if c["samesite"] == "none":
            return _finding(cid, f"Cookie '{c['name']}' uses SameSite=None without Secure", MEDIUM,
                            "SameSite=None requires Secure; browsers reject or mishandle it otherwise.",
                            "The cookie is sent in all cross-site requests and may be dropped.",
                            "Add Secure or use SameSite=Lax/Strict.", f"Set-Cookie: {c['name']}=<redacted>; SameSite=None",
                            _curl(c["url"], "set-cookie"))
        return _finding(cid, f"Cookie '{c['name']}' has no SameSite attribute", LOW,
                        "Without an explicit SameSite value, behaviour depends on the browser default.",
                        "Cross-site request forgery protection is weaker and inconsistent.",
                        "Set SameSite=Lax (or Strict) explicitly.", f"Set-Cookie: {c['name']}=<redacted> (SameSite missing)",
                        _curl(c["url"], "set-cookie"))

    return _cookie_check(ctx, cid, "Cookies have a SameSite attribute", bad, make)


# ----------------------------------------------------------------- TLS
def check_tls_version(ctx):
    cid, title = "tls_version", "Negotiated TLS version is modern"
    tls = ctx.fetch.tls
    if tls is None:
        return _result(cid, title, skip=True, detail="No TLS connection was made.")
    if tls.version in ("SSLv3", "TLSv1", "TLSv1.1"):
        return _result(cid, title, [_finding(
            cid, f"Outdated TLS version negotiated ({tls.version})", HIGH,
            "The connection negotiated a deprecated protocol version.",
            "Deprecated versions have known weaknesses and are rejected by modern clients.",
            "Disable TLS 1.0/1.1; support TLS 1.2 and 1.3 only.", f"Negotiated: {tls.version}, cipher {tls.cipher}",
            f"openssl s_client -connect {urlsplit(ctx.start_url).hostname}:443 </dev/null 2>/dev/null | grep -i protocol")])
    return _result(cid, title, detail=f"Negotiated {tls.version} ({tls.cipher}). Only the negotiated version is tested; "
                                      "EagleEye does not probe whether older versions are also accepted.")


def check_certificate(ctx):
    cid, title = "tls_certificate", "Certificate is valid and not close to expiry"
    tls = ctx.fetch.tls
    host = urlsplit(ctx.start_url).hostname
    repro = f"openssl s_client -connect {host}:443 -servername {host} </dev/null 2>&1 | grep -i 'verify\\|notAfter'"
    if tls is None:
        return _result(cid, title, skip=True, detail="No TLS connection was made.")
    if not tls.verified:
        return _result(cid, title, [_finding(
            cid, "TLS certificate failed verification", HIGH,
            "The certificate chain or host name could not be validated against trusted authorities.",
            "Browsers will warn users, and clients cannot be sure they talk to the real server.",
            "Install a valid certificate from a trusted CA that covers this host name, with the full chain.",
            tls.error or "Verification failed", repro)])
    if tls.days_left is not None and tls.days_left <= 30:
        sev = HIGH if tls.days_left <= 14 else MEDIUM
        return _result(cid, title, [_finding(
            cid, f"Certificate expires in {tls.days_left} day(s)", sev,
            "The certificate is close to its expiry date.",
            "When it expires, browsers will block the site.", "Renew now and automate renewal (e.g. ACME).",
            f"notAfter: {tls.not_after}; issuer: {tls.issuer}", repro)])
    return _result(cid, title, detail=f"Valid; {tls.days_left} day(s) remaining." if tls.days_left is not None else "Valid.")


# ------------------------------------------------------------ response
def check_response(ctx):
    cid, title = "response_health", "Response status and timing"
    if not ctx.final:
        return _result(cid, title, skip=True, detail="No response received.")
    hop, findings = ctx.final, []
    if hop.status >= 500:
        findings.append(_finding(cid, f"Server error (HTTP {hop.status})", LOW,
                                 "The server returned an error status.", "Errors may reveal faults and affect availability.",
                                 "Investigate server logs.", f"HTTP {hop.status} {hop.reason}", _curl(hop.url)))
    elif hop.status in (401, 403):
        findings.append(_finding(cid, f"Access restricted (HTTP {hop.status})", INFO,
                                 "The page requires authentication or denies access.",
                                 "Header checks apply to this response only; protected pages were not assessed.",
                                 "No action needed.", f"HTTP {hop.status} {hop.reason}", _curl(hop.url)))
    elif hop.status >= 400:
        findings.append(_finding(cid, f"Client error (HTTP {hop.status})", INFO,
                                 "The URL returned an error status.", "The scan assessed the error page, not the application.",
                                 "Scan a URL that returns 200.", f"HTTP {hop.status} {hop.reason}", _curl(hop.url)))
    if hop.elapsed_ms > 3000:
        findings.append(_finding(cid, "Slow response", INFO, "The response took more than 3 seconds.",
                                 "Slow responses affect users and may signal load or misconfiguration.",
                                 "Review server performance.", f"{hop.elapsed_ms} ms", _curl(hop.url)))
    if hop.body_truncated:
        findings.append(_finding(cid, "Response body exceeded the read limit", INFO,
                                 "EagleEye reads only a limited amount of each response.", "Only headers were assessed in full.",
                                 "No action needed.", f"Read limit reached at {hop.body_bytes} bytes", _curl(hop.url)))
    return _result(cid, title, findings, detail=f"HTTP {hop.status} in {hop.elapsed_ms} ms.")


ALL_CHECKS = [
    check_https, check_downgrade, check_http_upgrade, check_redirects,
    check_tls_version, check_certificate,
    check_csp, check_hsts, check_xcto, check_xfo, check_referrer, check_permissions, check_disclosure,
    check_cookie_secure, check_cookie_httponly, check_cookie_samesite,
    check_response,
]
