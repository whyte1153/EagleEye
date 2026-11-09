"""Evidence module: permissions, upload safety, hashing, integrity, custody chain, downloads, exports.

Integration tests using Django's test client and a throw-away evidence store in a temp directory.
"""
import csv
import io
import json
import os
import re
import shutil
import struct
import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, ROLE_REVIEWER
from apps.accounts.tests.test_auth import make_user
from apps.audit.models import AppendOnlyError, AuditEvent
from apps.forensics.engine.hashing import hash_path
from apps.forensics.engine.storage import UnsafeStorage
from apps.forensics.models import CustodyEvent, EvidenceItem, EvidenceNote
from apps.forensics.services import get_store

PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 30


def _rmtree_writable(path):
    for p in Path(path).rglob("*"):
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


class EvidenceTestCase(TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ee-evidence-")
        self.addCleanup(_rmtree_writable, self.root)
        self.enterContext(override_settings(EVIDENCE_ROOT=self.root, EVIDENCE_MAX_BYTES=5 * 1024 * 1024))
        self.investigator = make_user("inv", ROLE_INVESTIGATOR)
        self.reviewer = make_user("rev", ROLE_REVIEWER)
        self.admin = make_user("boss", ROLE_ADMIN)
        self.client.force_login(self.investigator)

    def upload(self, name="note.txt", data=b"hello evidence\n", confirm=True, **extra):
        payload = {"file": SimpleUploadedFile(name, data), **extra}
        if confirm:
            payload["authorization_confirmed"] = "on"
        return self.client.post(reverse("forensics:home"), payload)

    def make(self, name="note.txt", data=b"hello evidence\n", **extra) -> EvidenceItem:
        self.upload(name, data, **extra)
        return EvidenceItem.objects.latest("id")

    def tamper(self, ev, data=b"changed!"):
        p = get_store().path(ev.stored_name)
        os.chmod(p, 0o600)
        p.write_bytes(data)


class PermissionTests(EvidenceTestCase):
    def test_anonymous_redirected(self):
        self.client.logout()
        for url in (reverse("forensics:home"), reverse("forensics:vault"), "/forensics/vault/EV-2026-000001/"):
            self.assertEqual(self.client.get(url).status_code, 302)

    def test_reviewer_can_view_and_export_but_not_modify_or_download(self):
        ev = self.make()
        self.client.force_login(self.reviewer)
        for url in (reverse("forensics:home"), reverse("forensics:vault"), ev.get_absolute_url(),
                    reverse("forensics:item_report", args=[ev.evidence_id, "html"]),
                    reverse("forensics:integrity_report", args=["pdf"]), reverse("forensics:export_inventory", args=["csv"])):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(self.upload("x.txt", b"abc").status_code, 403)
        for name in ("verify", "reanalyze", "note"):
            self.assertEqual(self.client.post(reverse(f"forensics:{name}", args=[ev.evidence_id]), {"text": "x"}).status_code, 403)
        self.assertEqual(self.client.post(reverse("forensics:verify_all")).status_code, 403)
        self.assertEqual(self.client.get(reverse("forensics:download", args=[ev.evidence_id])).status_code, 403)
        self.assertEqual(EvidenceItem.objects.count(), 1)

    def test_state_changing_actions_are_post_only(self):
        ev = self.make()
        for name in ("verify", "reanalyze", "note"):
            self.assertEqual(self.client.get(reverse(f"forensics:{name}", args=[ev.evidence_id])).status_code, 405)

    def test_csrf_enforced_on_upload(self):
        from django.test import Client
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.investigator)
        r = c.post(reverse("forensics:home"), {"file": SimpleUploadedFile("a.txt", b"x"), "authorization_confirmed": "on"})
        self.assertEqual(r.status_code, 403)


class UploadTests(EvidenceTestCase):
    def test_upload_hashes_stores_and_audits(self):
        data = b"The quick brown fox\n" * 50
        response = self.upload("report.txt", data, description="seized laptop log", case_reference="CASE-2026/14")
        ev = EvidenceItem.objects.get()
        self.assertRedirects(response, ev.get_absolute_url())
        import hashlib
        self.assertEqual(ev.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(ev.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(ev.size, len(data))
        self.assertRegex(ev.evidence_id, r"^EV-\d{4}-\d{6}$")
        self.assertEqual(ev.uploaded_by, self.investigator)
        self.assertEqual(ev.integrity_status, EvidenceItem.VERIFIED)
        self.assertEqual(ev.detected_kind, "text")
        self.assertEqual(ev.case_reference, "CASE-2026/14")
        # original preserved byte-for-byte, read-only, outside static/web directories
        path = get_store().path(ev.stored_name)
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o440")
        self.assertNotIn("static", str(path))
        self.assertEqual(list((Path(self.root) / "working").iterdir()), [])  # working copy removed
        self.assertEqual([e.action for e in ev.events.all()], ["uploaded", "analyzed"])
        self.assertTrue(AuditEvent.objects.filter(action="evidence.uploaded", target=ev.evidence_id).exists())

    def test_evidence_ids_are_unique_and_sequential(self):
        a, b = self.make("a.txt", b"one"), self.make("b.txt", b"two")
        self.assertNotEqual(a.evidence_id, b.evidence_id)
        self.assertLess(a.evidence_id, b.evidence_id)

    def test_authorization_checkbox_required(self):
        r = self.upload(confirm=False)
        self.assertContains(r, "must confirm", status_code=400)
        self.assertEqual(EvidenceItem.objects.count(), 0)

    def test_empty_file_rejected(self):
        r = self.upload("empty.txt", b"")
        self.assertEqual(EvidenceItem.objects.count(), 0)
        self.assertGreaterEqual(r.status_code, 400)

    def test_oversize_rejected_and_nothing_left_on_disk(self):
        with override_settings(EVIDENCE_MAX_BYTES=100):
            r = self.upload("big.bin", b"A" * 5000)
        self.assertEqual(r.status_code, 413)
        self.assertEqual(EvidenceItem.objects.count(), 0)
        self.assertEqual(list((Path(self.root) / "incoming").iterdir()), [])
        self.assertEqual(list((Path(self.root) / "originals").rglob("*")), [])

    def test_bad_case_reference_rejected(self):
        self.assertEqual(self.upload(case_reference="<script>").status_code, 400)
        self.assertEqual(EvidenceItem.objects.count(), 0)

    def test_hostile_filename_is_sanitised_and_never_used_as_a_path(self):
        ev = self.make("../../../etc/passwd.txt", b"x")
        self.assertEqual(ev.original_filename, "passwd.txt")
        self.assertRegex(ev.stored_name, r"^[0-9a-f]{32}$")
        self.assertFalse(Path("/etc/passwd.txt").exists())
        spoof = self.make("invoice‮gpj.exe", PE)
        self.assertNotIn("‮", spoof.original_filename)

    def test_disguised_executable_is_flagged_high(self):
        ev = self.make("holiday.jpg", PE)
        self.assertEqual((ev.detected_kind, ev.extension_severity, ev.mismatch), ("pe", "high", True))
        self.assertContains(self.client.get(ev.get_absolute_url()), "Possible disguised executable")

    def test_uploaded_scripts_are_never_executed(self):
        marker = Path(self.root) / "pwned"
        self.make("run.sh", b"#!/bin/sh\ntouch " + str(marker).encode() + b"\n")
        self.assertFalse(marker.exists())

    def test_user_text_is_escaped(self):
        ev = self.make("<img src=x onerror=alert(1)>.txt", b"x", description="<script>alert(1)</script>")
        html = self.client.get(ev.get_absolute_url()).content.decode()
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<img src=x", html)

    def test_evidence_root_inside_static_is_refused(self):
        from django.conf import settings
        with override_settings(EVIDENCE_ROOT=Path(settings.BASE_DIR) / "static" / "evidence"):
            with self.assertRaises(UnsafeStorage):
                get_store()

    def test_failed_database_write_leaves_no_orphan_file(self):
        from unittest import mock
        with mock.patch("apps.forensics.services.add_event", side_effect=RuntimeError("db down")):
            with self.assertRaises(RuntimeError):
                self.upload("a.txt", b"data")
        self.assertEqual([p for p in (Path(self.root) / "originals").rglob("*") if p.is_file()], [])
        self.assertEqual(EvidenceItem.objects.count(), 0)


class IntegrityTests(EvidenceTestCase):
    def test_verify_passes_for_untouched_file(self):
        ev = self.make()
        self.client.post(reverse("forensics:verify", args=[ev.evidence_id]))
        ev.refresh_from_db()
        self.assertEqual(ev.integrity_status, "verified")
        self.assertEqual(ev.last_verified_by, self.investigator)
        self.assertTrue(ev.events.filter(action="integrity_verified").exists())

    def test_tampering_is_detected_recorded_and_blocks_download_and_analysis(self):
        ev = self.make()
        self.tamper(ev)
        self.client.post(reverse("forensics:verify", args=[ev.evidence_id]))
        ev.refresh_from_db()
        self.assertEqual(ev.integrity_status, "failed")
        event = ev.events.get(action="integrity_failed")
        self.assertIn(ev.sha256, event.detail)
        self.assertContains(self.client.get(ev.get_absolute_url()), "INTEGRITY FAILED")
        r = self.client.get(reverse("forensics:download", args=[ev.evidence_id]))
        self.assertRedirects(r, ev.get_absolute_url())
        self.assertFalse(ev.events.filter(action="downloaded").exists())
        self.client.post(reverse("forensics:reanalyze", args=[ev.evidence_id]))
        self.assertFalse(ev.events.filter(action="reanalyzed").exists())
        self.assertEqual(list((Path(self.root) / "working").iterdir()), [])

    def test_missing_original_detected(self):
        ev = self.make()
        p = get_store().path(ev.stored_name)
        os.chmod(p, 0o600)
        p.unlink()
        self.client.post(reverse("forensics:verify", args=[ev.evidence_id]))
        ev.refresh_from_db()
        self.assertEqual(ev.integrity_status, "missing")

    def test_verify_all_reports_counts(self):
        good, bad = self.make("a.txt", b"aaa"), self.make("b.txt", b"bbb")
        self.tamper(bad)
        r = self.client.post(reverse("forensics:verify_all"), follow=True)
        self.assertContains(r, "FAILED 1")
        good.refresh_from_db(); bad.refresh_from_db()
        self.assertEqual((good.integrity_status, bad.integrity_status), ("verified", "failed"))

    def test_reanalyze_uses_a_working_copy_and_logs(self):
        ev = self.make()
        original_hash = hash_path(get_store().path(ev.stored_name)).sha256
        self.client.post(reverse("forensics:reanalyze", args=[ev.evidence_id]))
        self.assertTrue(ev.events.filter(action="reanalyzed").exists())
        self.assertEqual(hash_path(get_store().path(ev.stored_name)).sha256, original_hash)

    def test_evidence_cannot_be_deleted(self):
        ev = self.make()
        with self.assertRaises(AppendOnlyError):
            ev.delete()
        with self.assertRaises(AppendOnlyError):
            EvidenceItem.objects.all().delete()
        self.assertEqual(EvidenceItem.objects.count(), 1)


class CustodyTests(EvidenceTestCase):
    def test_chain_valid_and_links_events(self):
        ev = self.make()
        self.client.post(reverse("forensics:verify", args=[ev.evidence_id]))
        events = list(ev.events.all())
        self.assertEqual(events[0].prev_hash, "0" * 64)
        for a, b in zip(events, events[1:]):
            self.assertEqual(b.prev_hash, a.entry_hash)
        self.assertContains(self.client.get(ev.get_absolute_url()), "HASH CHAIN VALID")

    def test_events_are_append_only(self):
        ev = self.make()
        event = ev.events.first()
        event.detail = "edited"
        with self.assertRaises(AppendOnlyError):
            event.save()
        with self.assertRaises(AppendOnlyError):
            event.delete()
        with self.assertRaises(AppendOnlyError):
            CustodyEvent.objects.all().update(detail="x")
        with self.assertRaises(AppendOnlyError):
            CustodyEvent.objects.all().delete()

    def test_direct_database_tampering_breaks_the_chain(self):
        ev = self.make()
        with connection.cursor() as cur:  # bypasses the application: simulates a DB-level edit
            cur.execute("UPDATE forensics_custodyevent SET detail = %s WHERE id = %s", ["forged", ev.events.first().pk])
        self.assertContains(self.client.get(ev.get_absolute_url()), "HASH CHAIN BROKEN")
        self.assertContains(self.client.get(reverse("forensics:item_report", args=[ev.evidence_id, "html"])), "BROKEN")

    def test_deleting_a_row_at_database_level_is_detected(self):
        ev = self.make()
        self.client.post(reverse("forensics:verify", args=[ev.evidence_id]))
        victim = ev.events.all()[1]
        with connection.cursor() as cur:
            cur.execute("DELETE FROM forensics_custodyevent WHERE id = %s", [victim.pk])
        self.assertContains(self.client.get(ev.get_absolute_url()), "HASH CHAIN BROKEN")

    def test_notes_are_recorded_immutable_and_validated(self):
        ev = self.make()
        self.client.post(reverse("forensics:note", args=[ev.evidence_id]), {"text": "Seen on desktop <b>1</b>"})
        note = EvidenceNote.objects.get()
        self.assertEqual((note.author_name, note.evidence), ("inv", ev))
        self.assertTrue(ev.events.filter(action="note_added").exists())
        note.text = "edited"
        with self.assertRaises(AppendOnlyError):
            note.save()
        with self.assertRaises(AppendOnlyError):
            note.delete()
        self.client.post(reverse("forensics:note", args=[ev.evidence_id]), {"text": "  "})
        self.assertEqual(EvidenceNote.objects.count(), 1)
        html = self.client.get(ev.get_absolute_url()).content.decode()
        self.assertIn("&lt;b&gt;1&lt;/b&gt;", html)


class DownloadTests(EvidenceTestCase):
    def test_download_returns_exact_bytes_as_attachment(self):
        data = os.urandom(5000)
        ev = self.make("blob.bin", data)
        r = self.client.get(reverse("forensics:download", args=[ev.evidence_id]))
        self.assertEqual(b"".join(r.streaming_content), data)
        self.assertEqual(r["Content-Type"], "application/octet-stream")
        self.assertIn("attachment", r["Content-Disposition"])
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertTrue(ev.events.filter(action="downloaded").exists())
        self.assertTrue(AuditEvent.objects.filter(action="evidence.downloaded").exists())

    def test_invalid_ids_404(self):
        for eid in ("EV-bad", "../../etc/passwd", "EV-2026-1", "ev-2026-000001"):
            with self.subTest(eid=eid):
                self.assertEqual(self.client.get(f"/forensics/vault/{eid}/").status_code, 404)
        self.assertEqual(self.client.get("/forensics/vault/EV-2026-999999/").status_code, 404)

    def test_no_public_media_url_exposes_evidence(self):
        ev = self.make()
        for url in (f"/media/{ev.stored_name}", f"/static/{ev.stored_name}", f"/evidence/{ev.stored_name}"):
            self.assertEqual(self.client.get(url).status_code, 404)


class ExportTests(EvidenceTestCase):
    def setUp(self):
        super().setUp()
        self.a = self.make("=HYPERLINK(1).txt", b"formula name")
        self.b = self.make("photo.png", b"not really a png")

    def test_inventory_csv_is_complete_and_formula_safe(self):
        r = self.client.get(reverse("forensics:export_inventory", args=["csv"]))
        self.assertEqual(r["Content-Type"], "text/csv; charset=utf-8")
        rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
        self.assertEqual(len(rows), 2)
        by_id = {x["evidence_id"]: x for x in rows}
        self.assertEqual(by_id[self.a.evidence_id]["sha256"], self.a.sha256)
        self.assertTrue(by_id[self.a.evidence_id]["original_filename"].startswith("'="))
        self.assertEqual(by_id[self.b.evidence_id]["extension_check"], "warn")

    def test_inventory_json_and_filters(self):
        r = self.client.get(reverse("forensics:export_inventory", args=["json"]), {"flag": "mismatch"})
        data = json.loads(r.content)
        self.assertEqual([i["evidence_id"] for i in data["items"]], [self.b.evidence_id])

    def test_integrity_report_formats(self):
        for fmt, ctype in (("html", "text/html"), ("json", "application/json"), ("pdf", "application/pdf")):
            with self.subTest(fmt=fmt):
                r = self.client.get(reverse("forensics:integrity_report", args=[fmt]))
                self.assertTrue(r["Content-Type"].startswith(ctype))
                self.assertIn("attachment", r["Content-Disposition"])
        self.assertTrue(self.client.get(reverse("forensics:integrity_report", args=["pdf"])).content.startswith(b"%PDF-1.4"))
        self.assertEqual(self.client.get(reverse("forensics:integrity_report", args=["exe"])).status_code, 404)

    def test_item_report_contains_custody_chain_and_is_escaped(self):
        self.client.post(reverse("forensics:note", args=[self.a.evidence_id]), {"text": "<script>x</script>"})
        r = self.client.get(reverse("forensics:item_report", args=[self.a.evidence_id, "html"]))
        body = r.content.decode()
        self.assertIn("VALID", body)
        self.assertIn(self.a.sha256, body)
        self.assertNotIn("<script>x</script>", body)
        data = json.loads(self.client.get(reverse("forensics:item_report", args=[self.a.evidence_id, "json"])).content)
        self.assertEqual(len(data["items"][0]["events"]), 3)  # uploaded, analyzed, note_added
        self.assertTrue(data["items"][0]["chain"]["ok"])

    def test_exports_are_audited(self):
        self.client.get(reverse("forensics:export_inventory", args=["csv"]))
        self.client.get(reverse("forensics:item_report", args=[self.a.evidence_id, "pdf"]))
        self.assertTrue(AuditEvent.objects.filter(action="evidence.inventory_exported").exists())
        self.assertTrue(AuditEvent.objects.filter(action="evidence.record_exported").exists())


class VaultAndDashboardTests(EvidenceTestCase):
    def test_vault_search_and_filters(self):
        a, b = self.make("alpha.txt", b"aaa", case_reference="CASE-A"), self.make("beta.txt", b"bbb", case_reference="CASE-B")
        self.tamper(b)
        self.client.post(reverse("forensics:verify", args=[b.evidence_id]))
        ids = lambda **q: {e.evidence_id for e in self.client.get(reverse("forensics:vault"), q).context["page"]}
        self.assertEqual(ids(q="CASE-A"), {a.evidence_id})
        self.assertEqual(ids(q=a.sha256[:12]), {a.evidence_id})
        self.assertEqual(ids(status="failed"), {b.evidence_id})
        self.assertEqual(ids(), {a.evidence_id, b.evidence_id})

    def test_dashboard_reflects_evidence(self):
        self.make("alpha.txt", b"aaa")
        bad = self.make("beta.txt", b"bbb")
        self.tamper(bad)
        self.client.post(reverse("forensics:verify", args=[bad.evidence_id]))
        ctx = self.client.get(reverse("core:dashboard")).context
        self.assertEqual(ctx["evidence"]["total"], 2)
        self.assertEqual(ctx["evidence"]["problems"], 1)
        rows = {r["label"]: r["count"] for r in ctx["evidence"]["rows"]}
        self.assertEqual((rows["Verified"], rows["Failed"]), (1, 1))

    def test_oversized_request_body_rejected_before_reading(self):
        r = self.client.post(reverse("accounts:login"), {"username": "x"}, CONTENT_LENGTH=str(10 * 1024 * 1024))
        self.assertEqual(r.status_code, 413)
        r = self.client.post(reverse("forensics:home"), {}, CONTENT_LENGTH=str(50 * 1024 * 1024))
        self.assertEqual(r.status_code, 413)
