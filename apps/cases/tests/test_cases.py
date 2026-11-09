"""Cases, reports and audit expansion (Django test client).  Run with `python manage.py test`."""
import csv
import io
import json

from django.test import TestCase
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, ROLE_REVIEWER
from apps.accounts.tests.test_auth import make_user
from apps.audit.models import AppendOnlyError, AuditEvent
from apps.cases import services
from apps.cases.models import Case, CaseEvent, CaseLink
from apps.forensics.models import EvidenceItem
from apps.network_analysis.models import NetworkImport
from apps.scanner.models import Finding, Scan


class CaseTestCase(TestCase):
    def setUp(self):
        self.inv = make_user("inv", ROLE_INVESTIGATOR)
        self.rev = make_user("rev", ROLE_REVIEWER)
        self.adm = make_user("adm", ROLE_ADMIN)
        self.client.force_login(self.inv)

    def new_case(self, title="Suspicious login", **extra):
        r = self.client.post(reverse("cases:new"), {"title": title, "description": "details", "priority": "high",
                                                    "assigned_to": self.inv.pk, **extra})
        self.assertEqual(r.status_code, 302, getattr(r, "content", b"")[:300])
        return Case.objects.get(title=title)

    def make_scan(self):
        s = Scan.objects.create(target_url="https://example.com/", normalized_url="https://example.com/", host="example.com",
                                status=Scan.COMPLETED, created_by=self.inv, findings_count=1, highest_severity=2,
                                severity_counts={"Medium": 1})
        Finding.objects.create(scan=s, check_id="hdr", title="Missing HSTS", severity=2, description="d", impact="i", remediation="Add HSTS")
        return s

    def make_evidence(self, case_reference=""):
        ev = EvidenceItem.objects.create(original_filename="a.bin", stored_name="x" * 32, size=3, sha256="a" * 64,
                                         case_reference=case_reference, uploaded_by=self.inv)
        ev.evidence_id = f"EV-2026-{ev.pk:06d}"
        ev.save(update_fields=["evidence_id"])
        return ev

    def make_import(self, case_reference=""):
        n = NetworkImport.objects.create(kind="nmap", original_filename="s.xml", size=1, sha256="b" * 64, max_severity=3,
                                         case_reference=case_reference)
        n.import_id = f"NI-2026-{n.pk:06d}"
        n.save(update_fields=["import_id"])
        return n

    def post(self, name, case, data, *a):
        return self.client.post(reverse(name, args=[case.case_id, *a]), data)


class AccessTests(CaseTestCase):
    def test_login_required(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse("cases:list")).status_code, 302)

    def test_reviewer_read_only(self):
        case = self.new_case()
        self.client.force_login(self.rev)
        self.assertEqual(self.client.get(reverse("cases:list")).status_code, 200)
        self.assertEqual(self.client.get(case.get_absolute_url()).status_code, 200)
        self.assertEqual(self.client.get(reverse("cases:new")).status_code, 403)
        self.assertEqual(self.post("cases:note", case, {"text": "x"}).status_code, 403)
        self.assertEqual(self.post("cases:status", case, {"status": "closed", "note": "x"}).status_code, 403)
        self.assertEqual(self.client.get(reverse("cases:report", args=[case.case_id, "html"])).status_code, 200)

    def test_bad_id_404(self):
        self.assertEqual(self.client.get(reverse("cases:detail", args=["../x"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("cases:detail", args=["CS-2026-999999"])).status_code, 404)

    def test_get_not_allowed_for_actions(self):
        case = self.new_case()
        self.assertEqual(self.client.get(reverse("cases:note", args=[case.case_id])).status_code, 405)


class LifecycleTests(CaseTestCase):
    def test_create_assigns_id_and_timeline(self):
        case = self.new_case()
        self.assertRegex(case.case_id, r"^CS-\d{4}-\d{6}$")
        self.assertEqual(case.events.first().kind, "created")
        self.assertTrue(AuditEvent.objects.filter(action="case.created", target=case.case_id).exists())

    def test_title_required(self):
        r = self.client.post(reverse("cases:new"), {"title": "", "priority": "low"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(Case.objects.count(), 0)

    def test_close_requires_note_and_reopen_requires_note(self):
        case = self.new_case()
        self.post("cases:status", case, {"status": "closed", "note": ""})
        case.refresh_from_db()
        self.assertEqual(case.status, "open")
        self.post("cases:status", case, {"status": "closed", "note": "Resolved: password reset"})
        case.refresh_from_db()
        self.assertEqual(case.status, "closed")
        self.assertIsNotNone(case.closed_at)
        self.assertEqual(case.closure_note, "Resolved: password reset")
        self.post("cases:status", case, {"status": "open", "note": ""})
        case.refresh_from_db()
        self.assertEqual(case.status, "closed")
        self.post("cases:status", case, {"status": "open", "note": "New evidence"})
        case.refresh_from_db()
        self.assertEqual(case.status, "open")
        self.assertIsNone(case.closed_at)

    def test_closed_case_cannot_be_edited_or_linked_or_progressed(self):
        case = self.new_case()
        self.post("cases:status", case, {"status": "closed", "note": "done"})
        r = self.client.post(reverse("cases:edit", args=[case.case_id]), {"title": "new", "priority": "low"})
        self.assertEqual(r.status_code, 400)
        case.refresh_from_db()
        self.assertEqual(case.title, "Suspicious login")
        scan = self.make_scan()
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        self.assertEqual(case.links.count(), 0)
        self.post("cases:status", case, {"status": "in_progress", "note": "x"})
        case.refresh_from_db()
        self.assertEqual(case.status, "closed")

    def test_edit_records_changes(self):
        case = self.new_case()
        self.client.post(reverse("cases:edit", args=[case.case_id]),
                         {"title": "Renamed", "description": "d2", "priority": "critical", "assigned_to": self.adm.pk})
        case.refresh_from_db()
        self.assertEqual((case.title, case.priority, case.assigned_to), ("Renamed", "critical", self.adm))
        self.assertIn("priority", case.events.last().detail)

    def test_notes_and_timeline_order(self):
        case = self.new_case()
        self.post("cases:note", case, {"text": "Called the user"})
        self.post("cases:note", case, {"text": "Reset password"})
        kinds = [e.kind for e in case.events.all()]
        self.assertEqual(kinds, ["created", "note", "note"])
        html = self.client.get(case.get_absolute_url()).content.decode()
        self.assertLess(html.index("Called the user"), html.index("Reset password"))

    def test_xss_escaped(self):
        case = self.new_case(title="<script>alert(1)</script>")
        self.post("cases:note", case, {"text": "<img src=x onerror=alert(1)>"})
        html = self.client.get(case.get_absolute_url()).content.decode()
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<img src=x", html)

    def test_cases_and_events_are_append_only(self):
        case = self.new_case()
        with self.assertRaises(AppendOnlyError):
            case.delete()
        with self.assertRaises(AppendOnlyError):
            Case.objects.all().delete()
        ev = case.events.first()
        ev.detail = "tampered"
        with self.assertRaises(AppendOnlyError):
            ev.save()
        with self.assertRaises(AppendOnlyError):
            ev.delete()
        with self.assertRaises(AppendOnlyError):
            CaseEvent.objects.all().update(detail="x")

    def test_list_filters(self):
        a = self.new_case("Alpha")
        self.new_case("Beta")
        self.post("cases:status", a, {"status": "closed", "note": "done"})
        html = self.client.get(reverse("cases:list"), {"status": "active"}).content.decode()
        self.assertIn("Beta", html)
        self.assertNotIn("Alpha", html)
        self.assertIn("Alpha", self.client.get(reverse("cases:list"), {"q": "alph"}).content.decode())
        self.assertIn("Beta", self.client.get(reverse("cases:list"), {"mine": "1"}).content.decode())


class LinkTests(CaseTestCase):
    def test_link_all_kinds_and_unlink_keeps_record(self):
        case = self.new_case()
        scan, ev, ni = self.make_scan(), self.make_evidence(), self.make_import()
        for kind, ref in (("scan", scan.pk), ("evidence", ev.evidence_id), ("network", ni.import_id)):
            self.post("cases:link", case, {"kind": kind, "ref": ref})
        self.assertEqual(case.links.filter(removed_at__isnull=True).count(), 3)
        html = self.client.get(case.get_absolute_url()).content.decode()
        for needle in (ev.evidence_id, ni.import_id, f"Scan #{scan.pk}"):
            self.assertIn(needle, html)
        link = case.links.get(kind="scan")
        self.post("cases:unlink", case, {}, link.pk)
        link.refresh_from_db()
        self.assertIsNotNone(link.removed_at)
        self.assertEqual(CaseLink.objects.count(), 3)  # not deleted
        self.assertIn("unlinked", [e.kind for e in case.events.all()])

    def test_duplicate_and_missing_links_rejected(self):
        case = self.new_case()
        scan = self.make_scan()
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        self.post("cases:link", case, {"kind": "scan", "ref": 99999})
        self.post("cases:link", case, {"kind": "evidence", "ref": "EV-1999-000001"})
        self.assertEqual(case.links.count(), 1)

    def test_relink_after_unlink_allowed(self):
        case = self.new_case()
        scan = self.make_scan()
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        self.post("cases:unlink", case, {}, case.links.get().pk)
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        self.assertEqual(case.links.filter(removed_at__isnull=True).count(), 1)

    def test_cannot_unlink_via_other_case(self):
        a, b = self.new_case("A"), self.new_case("B")
        scan = self.make_scan()
        self.post("cases:link", a, {"kind": "scan", "ref": scan.pk})
        r = self.client.post(reverse("cases:unlink", args=[b.case_id, a.links.get().pk]))
        self.assertEqual(r.status_code, 404)

    def test_suggestions_from_case_reference(self):
        case = self.new_case()
        ev = self.make_evidence(case_reference=case.case_id)
        html = self.client.get(case.get_absolute_url()).content.decode()
        self.assertIn("Suggested links", html)
        self.assertIn(ev.evidence_id, html)

    def test_missing_object_is_reported_not_hidden(self):
        case = self.new_case()
        scan = self.make_scan()
        self.post("cases:link", case, {"kind": "scan", "ref": scan.pk})
        scan.delete()
        self.assertIn("record missing", self.client.get(case.get_absolute_url()).content.decode())
        report = json.loads(self.client.get(reverse("cases:report", args=[case.case_id, "json"])).content)
        self.assertTrue(any("record missing" in str(sec) for sec in report["sections"]))


class ReportTests(CaseTestCase):
    def setUp(self):
        super().setUp()
        self.case = self.new_case()
        self.post("cases:link", self.case, {"kind": "scan", "ref": self.make_scan().pk})
        self.post("cases:link", self.case, {"kind": "evidence", "ref": self.make_evidence().evidence_id})
        self.post("cases:note", self.case, {"text": "marker-note-123"})

    def get(self, fmt):
        return self.client.get(reverse("cases:report", args=[self.case.case_id, fmt]))

    def test_formats(self):
        html = self.get("html")
        self.assertEqual(html["X-Content-Type-Options"], "nosniff")
        self.assertIn("marker-note-123", html.content.decode())
        self.assertIn("Missing HSTS", html.content.decode())
        pdf = self.get("pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF"))
        data = json.loads(self.get("json").content)
        self.assertEqual(data["title"], f"Case report {self.case.case_id}")
        self.assertEqual(self.get("exe").status_code, 404)
        self.assertTrue(AuditEvent.objects.filter(action="case.report_exported").exists())

    def test_report_escapes_html(self):
        self.post("cases:note", self.case, {"text": "<script>alert(1)</script>"})
        self.assertNotIn("<script>alert(1)", self.get("html").content.decode())


class OverviewAndAuditTests(CaseTestCase):
    def test_overview_formats_for_any_role(self):
        self.make_scan()
        self.new_case()
        self.client.force_login(self.rev)
        for fmt in ("html", "pdf", "json"):
            self.assertEqual(self.client.get(reverse("reports:overview", args=[fmt])).status_code, 200)
        data = json.loads(self.client.get(reverse("reports:overview", args=["json"])).content)
        self.assertEqual(data["sections"][0]["kv"][0][1], 1)  # one target scanned

    def test_reports_home(self):
        self.new_case()
        html = self.client.get(reverse("reports:home")).content.decode()
        self.assertIn("Security overview", html)
        self.assertNotIn("Audit report (administrators)", html)
        self.client.force_login(self.adm)
        self.assertIn("Audit report (administrators)", self.client.get(reverse("reports:home")).content.decode())

    def test_audit_report_admin_only(self):
        self.assertEqual(self.client.get(reverse("reports:audit", args=["html"])).status_code, 403)
        self.client.force_login(self.adm)
        self.assertEqual(self.client.get(reverse("reports:audit", args=["html"]), {"from": "2000-01-01", "to": "bad"}).status_code, 200)
        self.assertEqual(self.client.get(reverse("reports:audit", args=["csv"])).status_code, 404)

    def test_audit_filters_and_export(self):
        self.new_case("Findme")
        self.client.force_login(self.adm)
        html = self.client.get(reverse("audit:list"), {"action": "case.created", "actor": "inv"}).content.decode()
        self.assertIn("case.created", html)
        self.assertNotIn("auth.login", html.split("<tbody>")[1])
        self.assertIn(" 0 of ", self.client.get(reverse("audit:list"), {"from": "2999-01-01"}).content.decode())
        r = self.client.get(reverse("audit:export", args=["csv"]), {"action": "case.created"})
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
        self.assertEqual(rows[0][2], "action")
        self.assertTrue(all(row[2] == "case.created" for row in rows[1:]))
        self.assertEqual(len(r["X-Content-SHA256"]), 64)
        j = json.loads(self.client.get(reverse("audit:export", args=["json"])).content)
        self.assertIn("events", j)
        self.assertTrue(AuditEvent.objects.filter(action="audit.exported").exists())

    def test_audit_export_requires_admin(self):
        self.assertEqual(self.client.get(reverse("audit:export", args=["csv"])).status_code, 403)
        self.client.force_login(self.adm)
        self.assertEqual(self.client.get(reverse("audit:export", args=["xml"])).status_code, 404)

    def test_audit_csv_formula_neutralised(self):
        AuditEvent.objects.create(action="x.y", actor_name="adm", target="=cmd()")
        self.client.force_login(self.adm)
        body = self.client.get(reverse("audit:export", args=["csv"])).content.decode("utf-8-sig")
        self.assertIn("'=cmd()", body)

    def test_dashboard_open_cases(self):
        self.new_case()
        html = self.client.get(reverse("core:dashboard")).content.decode()
        self.assertIn("Open cases", html)
