"""Scanner module: permissions, policy enforcement, persistence, history, compare, reports.

Integration tests: they start the local lab server (apps/scanner/lab.py) on a free
127.0.0.1 port and enable lab mode for that one target.  No public site is contacted.
"""
import json
import threading
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, ROLE_REVIEWER
from apps.accounts.tests.test_auth import make_user
from apps.audit.models import AuditEvent
from apps.scanner.lab import make_server
from apps.scanner.models import Finding, Scan


class LabTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = make_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.enterClassContext(override_settings(
            EAGLEEYE_LAB_MODE=True, EAGLEEYE_LAB_TARGETS=[f"127.0.0.1:{cls.port}"],
            SCAN_TIMEOUT_SECONDS=2, SCAN_DEADLINE_SECONDS=6))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def setUp(self):
        self.investigator = make_user("inv", ROLE_INVESTIGATOR)
        self.reviewer = make_user("rev", ROLE_REVIEWER)
        self.admin = make_user("boss", ROLE_ADMIN)
        self.client.force_login(self.investigator)

    def scan(self, url, confirm=True, **extra):
        data = {"url": url, **extra}
        if confirm:
            data["authorization_confirmed"] = "on"
        return self.client.post(reverse("scanner:home"), data)


class PermissionTests(LabTestCase):
    def test_anonymous_redirected(self):
        self.client.logout()
        for name in ("scanner:home", "scanner:history"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 302)

    def test_reviewer_can_view_but_not_scan(self):
        self.client.force_login(self.reviewer)
        self.assertEqual(self.client.get(reverse("scanner:home")).status_code, 200)
        self.assertEqual(self.scan(self.base + "/weak").status_code, 403)
        self.assertEqual(Scan.objects.count(), 0)

    def test_reviewer_can_view_history_and_reports(self):
        self.scan(self.base + "/weak")
        scan = Scan.objects.get()
        self.client.force_login(self.reviewer)
        self.assertEqual(self.client.get(reverse("scanner:history")).status_code, 200)
        self.assertEqual(self.client.get(scan.get_absolute_url()).status_code, 200)
        self.assertEqual(self.client.get(reverse("scanner:report", args=[scan.pk, "json"])).status_code, 200)

    def test_scanner_requires_csrf(self):
        from django.test import Client
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.investigator)
        self.assertEqual(c.post(reverse("scanner:home"), {"url": self.base, "authorization_confirmed": "on"}).status_code, 403)


class ScanRunTests(LabTestCase):
    def test_authorization_confirmation_required(self):
        response = self.scan(self.base + "/weak", confirm=False)
        self.assertContains(response, "must confirm", status_code=400)
        self.assertEqual(Scan.objects.count(), 0)

    def test_malformed_urls_rejected_without_saving(self):
        for bad in ("ftp://example.com", "http://user:pw@example.com", "javascript:alert(1)", "http://exa mple.com"):
            with self.subTest(url=bad):
                self.assertEqual(self.scan(bad).status_code, 400)
        self.assertEqual(Scan.objects.count(), 0)

    def test_successful_scan_is_saved_and_viewable(self):
        response = self.scan(self.base + "/weak", authorization_note="ticket 42")
        scan = Scan.objects.get()
        self.assertRedirects(response, scan.get_absolute_url())
        self.assertEqual(scan.status, Scan.COMPLETED)
        self.assertEqual(scan.final_status_code, 200)
        self.assertEqual(scan.created_by, self.investigator)
        self.assertEqual(scan.authorization_note, "ticket 42")
        self.assertGreater(scan.findings_count, 5)
        self.assertEqual(scan.findings.count(), scan.findings_count)
        self.assertEqual(scan.highest_severity, 3)  # plain HTTP
        self.assertEqual(sum(scan.severity_counts.values()), scan.findings_count)
        page = self.client.get(scan.get_absolute_url())
        self.assertContains(page, "Content-Security-Policy header missing")
        self.assertContains(page, "Checks performed")
        self.assertTrue(AuditEvent.objects.filter(action="scan.run", actor_name="inv").exists())

    def test_cookie_values_are_not_stored_anywhere(self):
        self.scan(self.base + "/weak")
        blob = json.dumps(list(Finding.objects.values())) + json.dumps(Scan.objects.values_list("hops", flat=True)[0])
        self.assertNotIn("abc123", blob)  # the sessionid value served by the lab page

    def test_private_target_is_blocked_and_recorded(self):
        self.scan("http://10.0.0.5/")  # private address, not a lab target: refused without any connection
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.BLOCKED)
        self.assertEqual(scan.hops, [])
        self.assertIn("non-public", scan.error_message)
        self.assertTrue(AuditEvent.objects.filter(action="scan.blocked").exists())
        self.assertContains(self.client.get(scan.get_absolute_url()), "Target refused by policy")

    def test_unlisted_lab_port_is_blocked(self):
        self.scan(f"http://127.0.0.1:{self.port + 1}/")
        self.assertEqual(Scan.objects.get().status, Scan.BLOCKED)

    def test_loopback_blocked_when_lab_mode_off(self):
        with override_settings(EAGLEEYE_LAB_MODE=False,
                               SCAN_ALLOWED_PORTS=[self.port]):
            self.scan(self.base + "/weak")
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.BLOCKED)
        self.assertIn("non-public", scan.error_message)

    def test_redirect_to_metadata_ip_is_not_followed(self):
        self.scan(self.base + "/redirect-evil")
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.COMPLETED)
        self.assertEqual(len(scan.hops), 1)
        self.assertTrue(scan.findings.filter(check_id="redirect_behaviour").exists())

    def test_timeout_is_recorded_as_failure(self):
        self.scan(self.base + "/slow")
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.FAILED)
        self.assertIn("timed out", scan.error_message)

    def test_unexpected_engine_error_does_not_leak_details(self):
        with mock.patch("apps.scanner.services.run_scan", side_effect=RuntimeError("secret /srv/path")):
            self.scan(self.base + "/weak")
        scan = Scan.objects.get()
        self.assertEqual(scan.status, Scan.FAILED)
        self.assertNotIn("secret", scan.error_message)

    def test_rate_limit(self):
        with override_settings(SCAN_RATE_LIMIT=2):
            self.assertEqual(self.scan("https://x.example/").status_code, 302)
            self.assertEqual(self.scan("https://x.example/").status_code, 302)
            response = self.scan("https://x.example/")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(Scan.objects.count(), 2)
        self.assertTrue(AuditEvent.objects.filter(action="scan.rate_limited").exists())

    def test_rate_limit_is_per_user(self):
        with override_settings(SCAN_RATE_LIMIT=1):
            self.scan("https://x.example/")
            self.client.force_login(self.admin)
            self.assertEqual(self.scan("https://x.example/").status_code, 302)

    def test_concurrency_limit(self):
        import threading as t
        busy = t.BoundedSemaphore(1)
        busy.acquire()
        with mock.patch("apps.scanner.services._get_slots", return_value=busy):
            response = self.scan(self.base + "/weak")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(Scan.objects.get().status, Scan.FAILED)

    def test_untrusted_text_is_escaped(self):
        self.scan(self.base + "/%3Cscript%3Ealert(1)%3C/script%3E", authorization_note="<img src=x onerror=alert(1)>")
        scan = Scan.objects.get()
        html = self.client.get(scan.get_absolute_url()).content.decode()
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<script>alert(1)", html)


class HistoryAndCompareTests(LabTestCase):
    def setUp(self):
        super().setUp()
        self.scan(self.base + "/weak")
        self.scan(self.base + "/hardened")
        self.weak, self.hard = Scan.objects.order_by("id")

    def test_history_lists_and_filters(self):
        html = self.client.get(reverse("scanner:history")).content.decode()
        self.assertIn(f"#{self.weak.pk}", html)
        self.assertIn(f"#{self.hard.pk}", html)
        html = self.client.get(reverse("scanner:history"), {"q": "hardened"}).content.decode()
        self.assertIn(f"#{self.hard.pk}", html)
        self.assertNotIn(f"#{self.weak.pk}<", html)
        self.assertEqual(self.client.get(reverse("scanner:history"), {"status": "blocked"}).context["page"].paginator.count, 0)
        self.assertEqual(self.client.get(reverse("scanner:history"), {"severity": "garbage"}).status_code, 200)

    def test_compare_shows_resolved_and_new(self):
        response = self.client.get(reverse("scanner:compare"), {"id": [self.weak.pk, self.hard.pk]})
        diff = response.context["diff"]
        titles_resolved = {f.title for f in diff["resolved"]}
        self.assertIn("Content-Security-Policy header missing", titles_resolved)
        self.assertEqual(response.context["older"], self.weak)
        self.assertTrue(len(diff["unchanged"]) >= 1)  # plain-HTTP finding persists

    def test_compare_requires_two_valid_distinct_ids(self):
        for params in ({}, {"id": [self.weak.pk]}, {"id": [self.weak.pk, self.weak.pk]}, {"id": ["x", "y"]}):
            with self.subTest(params=params):
                self.assertRedirects(self.client.get(reverse("scanner:compare"), params), reverse("scanner:history"))
        self.assertEqual(self.client.get(reverse("scanner:compare"), {"id": [self.weak.pk, 99999]}).status_code, 404)


class ReportTests(LabTestCase):
    def setUp(self):
        super().setUp()
        self.scan(self.base + "/weak", authorization_note="note <b>x</b>")
        self.scan_obj = Scan.objects.get()

    def get(self, fmt):
        return self.client.get(reverse("scanner:report", args=[self.scan_obj.pk, fmt]))

    def test_json(self):
        r = self.get("json")
        self.assertEqual(r["Content-Type"], "application/json")
        self.assertIn("attachment", r["Content-Disposition"])
        data = json.loads(r.content)
        self.assertEqual(data["id"], self.scan_obj.pk)
        self.assertEqual(len(data["findings"]), self.scan_obj.findings_count)

    def test_html_is_escaped_and_complete(self):
        r = self.get("html")
        body = r.content.decode()
        self.assertIn("EagleEye scan report", body)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", body)
        self.assertNotIn("<b>x</b>", body)
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")

    def test_pdf(self):
        r = self.get("pdf")
        self.assertEqual(r["Content-Type"], "application/pdf")
        self.assertTrue(r.content.startswith(b"%PDF-1.4"))
        self.assertTrue(r.content.rstrip().endswith(b"%%EOF"))

    def test_unknown_format_404_and_download_is_audited(self):
        self.assertEqual(self.get("exe").status_code, 404)
        self.get("json")
        self.assertTrue(AuditEvent.objects.filter(action="scan.report_downloaded").exists())

    def test_reports_require_login(self):
        self.client.logout()
        self.assertEqual(self.get("json").status_code, 302)
