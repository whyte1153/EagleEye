"""Scanner engine tests.  Pure Python: no Django, no public internet.

Unit tests use fake responses / injected DNS.  Integration tests start the
local lab server (apps/scanner/lab.py) on 127.0.0.1 and use *lab mode*.
Run just these with:  python -m unittest apps.scanner.tests.test_engine -v
"""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from apps.scanner.engine import checks as C
from apps.scanner.engine.datatypes import HIGH, INFO, LOW, MEDIUM, FetchResult, Hop, TlsInfo
from apps.scanner.engine.fetcher import fetch_chain
from apps.scanner.engine.scanner import run_scan
from apps.scanner.engine.ssrf import (InvalidTarget, ResolveError, ScanPolicy, TargetBlocked,
                                      normalize_url, resolve_and_validate)
from apps.scanner.lab import make_server


# ------------------------------------------------------------------ helpers
def policy(**kw) -> ScanPolicy:
    return ScanPolicy(**kw)


def hop(url="https://example.com/", status=200, headers=(), elapsed=50, location="") -> Hop:
    return Hop(url=url, status=status, reason="OK", headers=[list(h) for h in headers],
               elapsed_ms=elapsed, ip="93.184.216.34", location=location)


def ctx_for(hops, tls=None, probe=None, **fetch_kw) -> C.ScanContext:
    return C.ScanContext("https://example.com/", FetchResult(hops=hops, tls=tls, **fetch_kw), probe)


GOOD_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("Strict-Transport-Security", "max-age=31536000"), ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]


def fake_dns(mapping):
    return lambda host, port: mapping[host]


# ------------------------------------------------------- URL normalisation
class NormalizeTests(unittest.TestCase):
    def test_bare_host_defaults_to_https(self):
        t = normalize_url("Example.COM")
        self.assertEqual((t.scheme, t.host, t.port, t.path), ("https", "example.com", 443, "/"))

    def test_keeps_port_path_query_and_drops_fragment(self):
        self.assertEqual(normalize_url("http://example.com:8080/a?b=1#frag").url, "http://example.com:8080/a?b=1")

    def test_rejects_bad_input(self):
        for bad in ["", "   ", "ftp://example.com", "file:///etc/passwd", "gopher://x", "javascript:alert(1)",
                    "http://user:pw@example.com", "http://example.com\\@evil.com", "http://exa mple.com",
                    "http://", "http://example.com:99999", "http://[::1", "a" * 3000, "http://ex..ample.com"]:
            with self.subTest(bad=bad), self.assertRaises(InvalidTarget):
                normalize_url(bad)

    def test_ipv6_literal(self):
        self.assertEqual(normalize_url("http://[2001:db8::1]:8080/").url, "http://[2001:db8::1]:8080/")


# ------------------------------------------------ SSRF blocks (no host allowlist: any PUBLIC host is allowed)
class PolicyTests(unittest.TestCase):
    def check(self, url, pol=None, dns=None):
        pol = pol or policy(resolver=fake_dns(dns or {"example.com": ["93.184.216.34"]}))
        return resolve_and_validate(normalize_url(url), pol)

    def test_any_public_host_is_allowed_without_configuration(self):
        self.assertEqual(self.check("https://example.com/"), ["93.184.216.34"])
        dns = {"www.jexcelhub.com": ["93.184.216.34"], "a.example.org": ["93.184.216.34"]}
        self.assertTrue(self.check("https://www.jexcelhub.com/", dns=dns))
        self.assertTrue(self.check("https://a.example.org/", dns=dns))

    def test_policy_has_no_allowlist_setting(self):
        self.assertFalse(hasattr(ScanPolicy(), "allowlist"))

    def test_port_restriction(self):
        with self.assertRaisesRegex(TargetBlocked, "Port"):
            self.check("https://example.com:22/")

    def test_private_and_special_addresses_blocked(self):
        bad = ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.1.1", "0.0.0.0",
               "100.64.0.1", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.1.1.1"]
        for ip in bad:
            with self.subTest(ip=ip), self.assertRaises(TargetBlocked):
                self.check("https://example.com/", dns={"example.com": [ip]})

    def test_one_bad_address_among_good_ones_blocks(self):
        with self.assertRaises(TargetBlocked):
            self.check("https://example.com/", dns={"example.com": ["93.184.216.34", "127.0.0.1"]})

    def test_metadata_blocked_even_in_lab_mode(self):
        pol = policy(lab_mode=True, lab_targets=("169.254.169.254",))
        for url in ("http://169.254.169.254/", "http://metadata.google.internal/"):
            with self.subTest(url=url), self.assertRaises(TargetBlocked):
                resolve_and_validate(normalize_url(url), policy(
                                     lab_mode=True, lab_targets=("metadata.google.internal", "169.254.169.254")))
        with self.assertRaises(TargetBlocked):  # DNS pointing at metadata
            resolve_and_validate(normalize_url("https://example.com/"),
                                 policy(lab_mode=True, lab_targets=("example.com",), resolver=fake_dns({"example.com": ["169.254.169.254"]})))
        self.assertTrue(pol)

    def test_ip_literal_loopback_blocked_unless_lab(self):
        with self.assertRaises(TargetBlocked):
            resolve_and_validate(normalize_url("http://127.0.0.1:8080/"), policy())

    def test_lab_target_allows_only_listed_host_and_port(self):
        pol = policy(lab_mode=True, lab_targets=("127.0.0.1:8001",))
        self.assertEqual(resolve_and_validate(normalize_url("http://127.0.0.1:8001/"), pol), ["127.0.0.1"])
        with self.assertRaises(TargetBlocked):
            resolve_and_validate(normalize_url("http://127.0.0.1:8002/"), pol)
        with self.assertRaises(TargetBlocked):
            resolve_and_validate(normalize_url("http://localhost:8001/"), pol)

    def test_lab_targets_ignored_when_lab_mode_off(self):
        with self.assertRaises(TargetBlocked):
            resolve_and_validate(normalize_url("http://127.0.0.1:8001/"), policy(lab_mode=False, lab_targets=("127.0.0.1:8001",)))

    def test_obfuscated_ip_forms_do_not_bypass(self):
        # A resolver (like inet_aton) may turn these into 127.0.0.1; the *resolved* address is what we validate.
        for host in ("2130706433", "0x7f.1", "017700000001"):
            with self.subTest(host=host), self.assertRaises(TargetBlocked):
                resolve_and_validate(normalize_url(f"http://{host}/"),
                                     policy(resolver=fake_dns({host: ["127.0.0.1"]})))

    def test_dns_rebinding_second_lookup_never_used(self):
        """The validated IP is what gets used; a resolver that changes its answer cannot redirect us."""
        answers = iter([["93.184.216.34"], ["127.0.0.1"]])
        pol = policy(resolver=lambda h, p: next(answers))
        self.assertEqual(resolve_and_validate(normalize_url("https://example.com/"), pol), ["93.184.216.34"])
        # fetch_chain() calls the resolver once per hop and connects to that result (see fetcher tests).

    def test_dns_failure_is_not_a_policy_block(self):
        def boom(host, port):
            raise ResolveError("nope")
        with self.assertRaises(ResolveError):
            resolve_and_validate(normalize_url("https://example.com/"), policy(resolver=boom))


# ------------------------------------------------------------------ checks
def ids(result):
    return [f.check_id for f in result.findings]


class HeaderCheckTests(unittest.TestCase):
    def test_all_good_headers_pass(self):
        ctx = ctx_for([hop(headers=GOOD_HEADERS)])
        for fn in (C.check_csp, C.check_hsts, C.check_xcto, C.check_xfo, C.check_referrer, C.check_permissions):
            with self.subTest(fn=fn.__name__):
                self.assertEqual(fn(ctx).outcome, "pass")

    def test_missing_headers_flagged_with_severity(self):
        ctx = ctx_for([hop()])
        self.assertEqual(C.check_csp(ctx).findings[0].severity, MEDIUM)
        self.assertEqual(C.check_hsts(ctx).findings[0].severity, MEDIUM)
        self.assertEqual(C.check_xcto(ctx).findings[0].severity, LOW)
        self.assertEqual(C.check_xfo(ctx).findings[0].severity, MEDIUM)
        self.assertEqual(C.check_referrer(ctx).findings[0].severity, LOW)
        self.assertEqual(C.check_permissions(ctx).findings[0].severity, LOW)

    def test_every_finding_is_explained_and_reproducible(self):
        ctx = ctx_for([hop()])
        for fn in (C.check_csp, C.check_hsts, C.check_xcto, C.check_xfo, C.check_referrer, C.check_permissions):
            f = fn(ctx).findings[0]
            for attr in ("description", "impact", "remediation", "evidence", "reproduce"):
                self.assertTrue(getattr(f, attr), f"{f.check_id} missing {attr}")
            self.assertTrue(f.reproduce.startswith(("curl", "openssl")))

    def test_header_names_are_case_insensitive(self):
        ctx = ctx_for([hop(headers=[("x-content-type-options", "NOSNIFF")])])
        self.assertEqual(C.check_xcto(ctx).outcome, "pass")

    def test_weak_csp(self):
        for policy_text in ("script-src 'self' 'unsafe-inline'", "default-src *", "script-src 'self' 'unsafe-eval'", "img-src 'self'"):
            with self.subTest(policy=policy_text):
                r = C.check_csp(ctx_for([hop(headers=[("Content-Security-Policy", policy_text)])]))
                self.assertEqual(r.findings[0].severity, LOW)

    def test_csp_with_nonce_is_not_weak(self):
        r = C.check_csp(ctx_for([hop(headers=[("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'")])]))
        self.assertEqual(r.outcome, "pass")

    def test_report_only_csp_does_not_count(self):
        r = C.check_csp(ctx_for([hop(headers=[("Content-Security-Policy-Report-Only", "default-src 'self'")])]))
        self.assertIn("Report-Only", r.findings[0].description)

    def test_hsts_short_max_age_and_http_skip(self):
        r = C.check_hsts(ctx_for([hop(headers=[("Strict-Transport-Security", "max-age=300")])]))
        self.assertEqual(r.findings[0].severity, LOW)
        r = C.check_hsts(ctx_for([hop(url="http://example.com/")]))
        self.assertEqual(r.outcome, "skip")

    def test_xfo_satisfied_by_csp_frame_ancestors(self):
        r = C.check_xfo(ctx_for([hop(headers=[("Content-Security-Policy", "frame-ancestors 'self'")])]))
        self.assertEqual(r.outcome, "pass")

    def test_referrer_unsafe_url(self):
        r = C.check_referrer(ctx_for([hop(headers=[("Referrer-Policy", "unsafe-url")])]))
        self.assertEqual(r.findings[0].severity, LOW)

    def test_disclosure(self):
        r = C.check_disclosure(ctx_for([hop(headers=[("Server", "Apache/2.4.41"), ("X-Powered-By", "PHP/7.4")])]))
        self.assertEqual(len(r.findings), 2)
        self.assertEqual(C.check_disclosure(ctx_for([hop(headers=[("Server", "nginx")])])).outcome, "pass")


class CookieCheckTests(unittest.TestCase):
    def cookies(self, *values, url="https://example.com/"):
        return ctx_for([hop(url=url, headers=[("Set-Cookie", v) for v in values])])

    def test_no_cookies_is_skipped(self):
        self.assertEqual(C.check_cookie_secure(ctx_for([hop()])).outcome, "skip")

    def test_secure_flag(self):
        r = C.check_cookie_secure(self.cookies("a=1; Path=/", "b=2; Secure"))
        self.assertEqual([f.title for f in r.findings], ["Cookie 'a' lacks the Secure attribute"])
        self.assertEqual(r.findings[0].severity, MEDIUM)

    def test_secure_flag_on_http_is_lower_severity(self):
        r = C.check_cookie_secure(self.cookies("a=1", url="http://example.com/"))
        self.assertEqual(r.findings[0].severity, LOW)

    def test_httponly_sensitive_name_is_medium(self):
        r = C.check_cookie_httponly(self.cookies("sessionid=1; Secure", "theme=dark"))
        sev = {f.title.split("'")[1]: f.severity for f in r.findings}
        self.assertEqual(sev, {"sessionid": MEDIUM, "theme": LOW})

    def test_samesite(self):
        r = C.check_cookie_samesite(self.cookies("a=1", "b=2; SameSite=Lax", "c=3; SameSite=None", "d=4; SameSite=None; Secure"))
        self.assertEqual(sorted(f.title.split("'")[1] for f in r.findings), ["a", "c"])

    def test_cookie_values_are_never_stored(self):
        r = C.check_cookie_secure(self.cookies("sessionid=SUPERSECRETVALUE"))
        blob = repr(r.findings)
        self.assertNotIn("SUPERSECRETVALUE", blob)
        self.assertIn("<redacted>", blob)


class TransportCheckTests(unittest.TestCase):
    def test_http_final_response_is_high(self):
        r = C.check_https(ctx_for([hop(url="http://example.com/")]))
        self.assertEqual(r.findings[0].severity, HIGH)

    def test_https_to_http_downgrade(self):
        r = C.check_downgrade(ctx_for([hop(url="https://example.com/", status=302, location="http://example.com/"),
                                       hop(url="http://example.com/")]))
        self.assertEqual(r.findings[0].severity, HIGH)

    def test_http_upgrade_probe(self):
        good = C.check_http_upgrade(ctx_for([hop()], probe={"status": 301, "location": "https://example.com/"}))
        bad = C.check_http_upgrade(ctx_for([hop()], probe={"status": 200, "location": ""}))
        none = C.check_http_upgrade(ctx_for([hop()], probe=None))
        self.assertEqual((good.outcome, bad.outcome, none.outcome), ("pass", "fail", "skip"))
        self.assertEqual(bad.findings[0].severity, MEDIUM)

    def test_blocked_redirect_reported_as_info(self):
        r = C.check_redirects(ctx_for([hop(status=302, location="http://169.254.169.254/")],
                                      redirect_blocked={"location": "http://169.254.169.254/", "reason": "metadata"}))
        self.assertEqual(r.findings[0].severity, INFO)

    def test_too_many_redirects(self):
        r = C.check_redirects(ctx_for([hop(status=302, location="/")], error="Too many redirects (more than 5)."))
        self.assertEqual(r.findings[0].severity, LOW)

    def test_tls_checks(self):
        old = TlsInfo(version="TLSv1.1", cipher="X")
        self.assertEqual(C.check_tls_version(ctx_for([hop()], tls=old)).findings[0].severity, HIGH)
        self.assertEqual(C.check_tls_version(ctx_for([hop()], tls=TlsInfo(version="TLSv1.3"))).outcome, "pass")
        self.assertEqual(C.check_tls_version(ctx_for([hop()])).outcome, "skip")
        bad = TlsInfo(version="TLSv1.3", verified=False, error="certificate has expired (code 10)")
        self.assertEqual(C.check_certificate(ctx_for([hop()], tls=bad)).findings[0].severity, HIGH)
        soon = TlsInfo(version="TLSv1.3", days_left=10, not_after="x")
        self.assertEqual(C.check_certificate(ctx_for([hop()], tls=soon)).findings[0].severity, HIGH)
        self.assertEqual(C.check_certificate(ctx_for([hop()], tls=TlsInfo(version="TLSv1.3", days_left=25))).findings[0].severity, MEDIUM)
        self.assertEqual(C.check_certificate(ctx_for([hop()], tls=TlsInfo(version="TLSv1.3", days_left=200))).outcome, "pass")

    def test_response_health(self):
        self.assertEqual(C.check_response(ctx_for([hop(status=503)])).findings[0].severity, LOW)
        self.assertEqual(C.check_response(ctx_for([hop(elapsed=4000)])).findings[0].severity, INFO)
        self.assertEqual(C.check_response(ctx_for([hop()])).outcome, "pass")


# ------------------------------- integration: real sockets, local lab server
class LabServerCase(unittest.TestCase):
    PORT = 0

    @classmethod
    def setUpClass(cls):
        cls.server = make_server(0)  # port 0 = any free port
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.lab = policy(lab_mode=True, lab_targets=(f"127.0.0.1:{cls.port}",), timeout=2, deadline=6)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class LabScanTests(LabServerCase):
    def test_weak_page_produces_expected_findings(self):
        out = run_scan(self.base + "/weak", self.lab)
        self.assertEqual(out.status, "completed")
        found = {f.check_id for f in out.findings}
        self.assertTrue({"https_used", "header_csp", "header_xcto", "header_xfo", "header_referrer",
                         "header_permissions", "info_disclosure", "cookie_secure", "cookie_httponly",
                         "cookie_samesite"} <= found, found)
        self.assertEqual(out.final_status, 200)
        self.assertIsNotNone(out.response_time_ms)
        self.assertEqual(out.hops[0]["ip"], "127.0.0.1")
        # HSTS does not apply to HTTP responses -> skipped, not failed
        self.assertEqual(next(c for c in out.checks if c["check_id"] == "header_hsts")["outcome"], "skip")

    def test_cookie_values_never_reach_stored_output(self):
        out = run_scan(self.base + "/weak", self.lab)
        blob = repr(out.hops) + repr(out.findings)
        self.assertNotIn("abc123", blob)
        self.assertIn("sessionid=<redacted>", blob)
        # ...but flags are still assessed from the redacted header
        self.assertIn("cookie_httponly", {f.check_id for f in out.findings})

    def test_hardened_page_only_flags_transport(self):
        out = run_scan(self.base + "/hardened", self.lab)
        # Only transport (plain HTTP) and the lab server's versioned Server header remain.
        self.assertEqual({f.check_id for f in out.findings}, {"https_used", "info_disclosure"})

    def test_findings_sorted_most_severe_first(self):
        out = run_scan(self.base + "/weak", self.lab)
        sev = [f.severity for f in out.findings]
        self.assertEqual(sev, sorted(sev, reverse=True))

    def test_safe_redirect_is_followed_and_validated(self):
        out = run_scan(self.base + "/redirect-ok", self.lab)
        self.assertEqual(out.status, "completed")
        self.assertEqual([h["status"] for h in out.hops], [302, 200])
        self.assertTrue(out.final_url.endswith("/hardened"))

    def test_redirect_to_metadata_address_is_not_followed(self):
        out = run_scan(self.base + "/redirect-evil", self.lab)
        self.assertEqual(out.status, "completed")
        self.assertEqual(len(out.hops), 1)  # the evil destination was never contacted
        redirect = next(c for c in out.checks if c["check_id"] == "redirect_behaviour")
        self.assertEqual(redirect["outcome"], "fail")
        self.assertTrue(any("169.254.169.254" in f.evidence for f in out.findings))

    def test_redirect_loop_is_cut_off(self):
        out = run_scan(self.base + "/redirect-loop", self.lab)
        self.assertEqual(out.status, "completed")
        self.assertIn("Too many redirects", out.error)
        self.assertEqual(len(out.hops), self.lab.max_redirects + 1)

    def test_timeout(self):
        out = run_scan(self.base + "/slow", self.lab)
        self.assertEqual(out.status, "failed")
        self.assertIn("timed out", out.error)
        self.assertLess(out.duration_ms, 6000)

    def test_body_size_limit(self):
        small = ScanPolicy(lab_mode=True, lab_targets=self.lab.lab_targets, max_body_bytes=1000, timeout=2, deadline=6)
        out = run_scan(self.base + "/big", small)
        self.assertTrue(out.hops[0]["body_truncated"])
        self.assertLessEqual(out.hops[0]["body_bytes"], 1000)

    def test_unlisted_lab_port_is_blocked(self):
        out = run_scan(f"http://127.0.0.1:{self.port + 1}/weak", self.lab)
        self.assertEqual(out.status, "blocked")

    def test_loopback_blocked_without_lab_mode(self):
        out = run_scan(self.base + "/weak", policy(allowed_ports=frozenset({self.port})))
        self.assertEqual(out.status, "blocked")
        self.assertIn("non-public", out.error)

    def test_connection_refused_is_a_failure_not_a_crash(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        pol = ScanPolicy(lab_mode=True, lab_targets=(f"127.0.0.1:{port}",), timeout=2, deadline=5)
        out = run_scan(f"http://127.0.0.1:{port}/", pol)
        self.assertEqual(out.status, "failed")


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI needed to make a test certificate")
class TlsLabTests(unittest.TestCase):
    """HTTPS against a local server with a self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        from apps.scanner.lab import LabHandler
        cls.tmp = tempfile.TemporaryDirectory()
        key, crt = f"{cls.tmp.name}/k.pem", f"{cls.tmp.name}/c.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-subj", "/CN=localhost", "-days", "30"], check=True, capture_output=True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.tmp.cleanup()

    def test_self_signed_certificate_is_reported_and_headers_still_assessed(self):
        pol = ScanPolicy(lab_mode=True, lab_targets=(f"127.0.0.1:{self.port}",), timeout=3, deadline=8)
        out = run_scan(f"https://127.0.0.1:{self.port}/hardened", pol)
        self.assertEqual(out.status, "completed")
        self.assertFalse(out.tls["verified"])
        self.assertTrue(out.tls["version"].startswith("TLSv1."))
        cert = next(f for f in out.findings if f.check_id == "tls_certificate")
        self.assertEqual(cert.severity, HIGH)
        self.assertIn("self", cert.evidence.lower())
        # HTTPS final response, so HSTS applies and the hardened page satisfies it.
        self.assertEqual(next(c for c in out.checks if c["check_id"] == "header_hsts")["outcome"], "pass")
        self.assertNotIn("https_used", {f.check_id for f in out.findings})


class MalformedResponseTests(unittest.TestCase):
    """A hostile or broken server must not crash the scanner."""

    def serve_once(self, payload: bytes) -> int:
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]

        def run():
            conn, _ = srv.accept()
            conn.recv(4096)
            conn.sendall(payload)
            conn.close(); srv.close()
        threading.Thread(target=run, daemon=True).start()
        return port

    def scan(self, payload):
        port = self.serve_once(payload)
        pol = ScanPolicy(lab_mode=True, lab_targets=(f"127.0.0.1:{port}",), timeout=2, deadline=5)
        return run_scan(f"http://127.0.0.1:{port}/", pol)

    def test_garbage_response(self):
        out = self.scan(b"\x00\x01 this is not http \xff\xfe\r\n\r\n")
        self.assertEqual(out.status, "failed")

    def test_empty_response(self):
        self.assertEqual(self.scan(b"").status, "failed")

    def test_bad_status_line(self):
        self.assertEqual(self.scan(b"HTTP/1.1 abc nope\r\n\r\n").status, "failed")

    def test_oversized_header_line(self):
        self.assertEqual(self.scan(b"HTTP/1.1 200 OK\r\nX-Big: " + b"A" * 70000 + b"\r\n\r\n").status, "failed")

    def test_truncated_body_still_scans_headers(self):
        out = self.scan(b"HTTP/1.0 200 OK\r\nContent-Length: 500\r\nServer: x\r\n\r\nshort")
        self.assertIn(out.status, ("completed", "failed"))  # must not raise either way


if __name__ == "__main__":
    unittest.main()
