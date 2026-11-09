"""Module catalogue, dashboard and settings page."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.core.models import Module
from apps.core.services import activity_last_days

User = get_user_model()
PASSWORD = "correct-horse-battery-9"


class ModuleCatalogueTests(TestCase):
    def test_seeded_by_migration(self):
        self.assertEqual(Module.objects.count(), 10)
        self.assertEqual(Module.objects.filter(status=Module.READY).count(), 10)

    def test_urls(self):
        self.assertTrue(Module.objects.get(slug="cases").is_ready)
        self.assertEqual(Module.objects.get(slug="cases").get_absolute_url(), reverse("cases:list"))
        self.assertEqual(Module.objects.get(slug="scanner").get_absolute_url(), reverse("scanner:home"))
        self.assertEqual(Module.objects.get(slug="users").get_absolute_url(), reverse("accounts:users"))


class DashboardTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("root", password=PASSWORD)
        self.client.force_login(self.admin)

    def test_dashboard_shows_modules_and_honest_empty_states(self):
        html = self.client.get(reverse("core:dashboard")).content.decode()
        for name in ("Vulnerability Scanner", "Digital Forensics", "Investigation Cases"):
            self.assertIn(name, html)
        self.assertIn("No scans yet", html)
        self.assertIn("Open cases", html)

    def test_dashboard_reflects_database(self):
        AuditEvent.objects.create(action="demo.event", actor_name="root", target="marker-xyz")
        html = self.client.get(reverse("core:dashboard")).content.decode()
        self.assertIn("demo.event", html)
        self.assertIn("marker-xyz", html)

    def test_activity_series_counts_today(self):
        baseline = activity_last_days(7)[-1]["count"]  # login in setUp already wrote an audit event
        AuditEvent.objects.create(action="a.b")
        AuditEvent.objects.create(action="a.b")
        series = activity_last_days(7)
        self.assertEqual(len(series), 7)
        self.assertEqual(series[-1]["day"], timezone.localdate())
        self.assertEqual(series[-1]["count"], baseline + 2)
        self.assertEqual(series[-1]["height"], 100)

    def test_planned_module_page(self):
        Module.objects.create(slug="future", name="Future module", summary="x", icon="cases", phase=6, order=99)
        response = self.client.get(reverse("core:module_detail", args=["future"]))
        self.assertContains(response, "Arrives in phase 6")

    def test_ready_module_redirects_to_its_page(self):
        response = self.client.get(reverse("core:module_detail", args=["users"]))
        self.assertRedirects(response, reverse("accounts:users"))

    def test_cases_and_reports_modules_are_online(self):
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["cases"])), reverse("cases:list"))
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["reports"])), reverse("reports:home"))

    def test_network_module_is_online(self):
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["network"])), reverse("network_analysis:home"))

    def test_scanner_module_is_online(self):
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["scanner"])), reverse("scanner:home"))

    def test_forensics_modules_are_online(self):
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["forensics"])), reverse("forensics:home"))
        self.assertRedirects(self.client.get(reverse("core:module_detail", args=["evidence-vault"])), reverse("forensics:vault"))

    def test_nav_highlights_only_the_most_specific_item(self):
        html = self.client.get(reverse("forensics:vault")).content.decode()
        import re
        active = re.findall(r'class="nav-link active"[^>]*>.*?<span>(.*?)</span>', html, re.S)
        self.assertEqual(active, ["Evidence Vault"])

    def test_dashboard_reflects_saved_scans(self):
        from apps.scanner.models import Finding, Scan
        scan = Scan.objects.create(target_url="https://a.example", normalized_url="https://a.example/", host="a.example",
                                   status=Scan.COMPLETED, findings_count=2, highest_severity=2)
        Finding.objects.create(scan=scan, check_id="x", title="Marker finding", severity=2, description="d", impact="i", remediation="r")
        Finding.objects.create(scan=scan, check_id="y", title="Other", severity=0, description="d", impact="i", remediation="r")
        ctx = self.client.get(reverse("core:dashboard")).context
        self.assertTrue(ctx["has_findings"])
        rows = {r["label"]: r["count"] for r in ctx["severity_rows"]}
        self.assertEqual((rows["Medium"], rows["Informational"], rows["High"]), (1, 1, 0))
        self.assertEqual(ctx["stat_cards"][0]["value"], 1)

    def test_rescans_are_not_double_counted(self):
        from apps.scanner.models import Finding, Scan
        for _ in range(2):
            s = Scan.objects.create(target_url="https://a.example", host="a.example", status=Scan.COMPLETED)
            Finding.objects.create(scan=s, check_id="x", title="t", severity=1, description="d", impact="i", remediation="r")
        ctx = self.client.get(reverse("core:dashboard")).context
        self.assertEqual({r["label"]: r["count"] for r in ctx["severity_rows"]}["Low"], 1)

    def test_unknown_module_is_404(self):
        self.assertEqual(self.client.get("/modules/nope/").status_code, 404)

    def test_all_eleven_nav_entries_for_admin(self):
        html = self.client.get(reverse("core:dashboard")).content.decode()
        for label in ("Dashboard", "Vulnerability Scanner", "Scan History", "Digital Forensics",
                      "Evidence Vault", "Network Analysis", "Investigation Cases", "Reports",
                      "Audit Logs", "User Management", "Settings"):
            self.assertIn(f"<span>{label}</span>", html)


class SettingsPageTests(TestCase):
    def test_secret_key_never_displayed(self):
        from django.conf import settings
        admin = User.objects.create_superuser("root", password=PASSWORD)
        self.client.force_login(admin)
        html = self.client.get(reverse("core:settings")).content.decode()
        self.assertNotIn(settings.SECRET_KEY, html)
        self.assertIn("Login throttle", html)

    def test_error_pages_do_not_leak(self):
        response = self.client.get("/definitely-missing/")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("Traceback", response.content.decode())
