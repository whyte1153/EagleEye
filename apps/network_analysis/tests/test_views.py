"""Network analysis views: permissions, safe imports, filtering, exports, audit.  (Run with `python manage.py test`.)"""
import csv
import io
import json
import socket
import struct

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, ROLE_REVIEWER
from apps.accounts.tests.test_auth import make_user
from apps.audit.models import AuditEvent
from apps.network_analysis.models import NetworkHost, NetworkImport
from apps.network_analysis.tests.test_engine import NMAP, _eth, _ip, _pcap, _pcapng, _tcp

FORM = {"authorization_confirmed": "on", "case_reference": "CASE-1", "description": "lab"}


def _upload(name, data):
    return SimpleUploadedFile(name, data, content_type="application/octet-stream")


class NetworkTestCase(TestCase):
    def setUp(self):
        self.inv = make_user("inv", ROLE_INVESTIGATOR)
        self.rev = make_user("rev", ROLE_REVIEWER)
        self.adm = make_user("adm", ROLE_ADMIN)
        self.client.force_login(self.inv)

    def post(self, name, data, **extra):
        return self.client.post(reverse("network_analysis:home"), {**FORM, "file": _upload(name, data), **extra})

    def nmap_import(self):
        r = self.post("scan.xml", NMAP)
        self.assertEqual(r.status_code, 302, getattr(r, "content", b"")[:500])
        return NetworkImport.objects.get()


class AccessTests(NetworkTestCase):
    def test_login_required(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse("network_analysis:home")).status_code, 302)

    def test_reviewer_can_view_but_not_import(self):
        self.client.force_login(self.rev)
        self.assertEqual(self.client.get(reverse("network_analysis:home")).status_code, 200)
        self.assertEqual(self.post("scan.xml", NMAP).status_code, 403)
        self.assertEqual(NetworkImport.objects.count(), 0)

    def test_bad_id_404(self):
        self.assertEqual(self.client.get(reverse("network_analysis:detail", args=["../etc"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("network_analysis:detail", args=["NI-2026-999999"])).status_code, 404)


class NmapImportTests(NetworkTestCase):
    def test_import_stores_hosts_and_flags(self):
        ni = self.nmap_import()
        self.assertEqual(ni.kind, "nmap")
        self.assertRegex(ni.import_id, r"^NI-\d{4}-\d{6}$")
        self.assertEqual(NetworkHost.objects.filter(network_import=ni).count(), 1)
        self.assertEqual(ni.max_severity, 3)
        self.assertEqual(len(ni.sha256), 64)
        self.assertTrue(AuditEvent.objects.filter(action="network.imported", target=ni.import_id).exists())

    def test_requires_authorization_checkbox(self):
        r = self.client.post(reverse("network_analysis:home"), {"file": _upload("scan.xml", NMAP)})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(NetworkImport.objects.count(), 0)

    def test_entity_attack_rejected_and_audited(self):
        r = self.post("evil.xml", b'<!DOCTYPE nmaprun [<!ENTITY a "x">]><nmaprun>&a;</nmaprun>')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(NetworkImport.objects.count(), 0)
        self.assertTrue(AuditEvent.objects.filter(action="network.import_rejected").exists())

    def test_type_by_content_not_extension(self):
        self.assertEqual(self.post("holiday.jpg", NMAP).status_code, 302)
        self.assertEqual(NetworkImport.objects.get().kind, "nmap")

    def test_unknown_content_rejected(self):
        self.assertEqual(self.post("x.xml", b"MZ" + b"\0" * 200).status_code, 400)

    @override_settings(NETWORK_MAX_BYTES=50)
    def test_size_limit(self):
        self.assertEqual(self.post("scan.xml", NMAP).status_code, 400)

    def test_detail_filter_and_html_escaped(self):
        evil = NMAP.replace(b'name="telnet"', b'name="telnet" product="&lt;script&gt;alert(1)&lt;/script&gt;"')
        self.post("scan.xml", evil)
        ni = NetworkImport.objects.get()
        url = reverse("network_analysis:detail", args=[ni.import_id])
        html = self.client.get(url).content.decode()
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("telnet", html)
        filtered = self.client.get(url, {"min_sev": "3"}).content.decode()
        self.assertIn("Telnet", filtered)
        self.assertNotIn(">ssh<", filtered)
        self.assertIn("No matching ports", self.client.get(url, {"port": "9"}).content.decode())

    def test_exports(self):
        ni = self.nmap_import()
        r = self.client.get(reverse("network_analysis:export", args=[ni.import_id, "csv"]))
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
        self.assertGreater(len(rows), 1)
        j = json.loads(self.client.get(reverse("network_analysis:export", args=[ni.import_id, "json"])).content)
        self.assertIn("note", j)
        self.assertEqual(self.client.get(reverse("network_analysis:export", args=[ni.import_id, "exe"])).status_code, 404)
        self.assertTrue(AuditEvent.objects.filter(action="network.exported").exists())

    def test_csv_formula_neutralised(self):
        x = NMAP.replace(b'name="telnet"', b'name="telnet" product="=HYPERLINK(1)"')
        self.post("s.xml", x)
        ni = NetworkImport.objects.get()
        body = self.client.get(reverse("network_analysis:export", args=[ni.import_id, "csv"])).content.decode("utf-8-sig")
        self.assertIn("'=HYPERLINK", body)
        self.assertNotIn(",=HYPERLINK", body)


class PcapImportTests(NetworkTestCase):
    def setUp(self):
        super().setUp()
        pk = [_eth(_ip("10.0.0.5", "10.0.0.9", 6, _tcp(40000, p, 2))) for p in range(1, 31)]
        pk.append(_eth(_ip("10.0.0.5", "10.0.0.9", 6, _tcp(40001, 23, 0x18, b"login:"))))
        self.pk = pk

    def test_pcap_and_pcapng(self):
        for name, data in (("a.pcap", _pcap(self.pk)), ("b.pcapng", _pcapng(self.pk))):
            self.assertEqual(self.post(name, data).status_code, 302)
        self.assertEqual(NetworkImport.objects.filter(kind="pcap").count(), 2)
        ni = NetworkImport.objects.first()
        html = self.client.get(ni.get_absolute_url()).content.decode()
        self.assertIn("Possible port scan", html)
        self.assertNotIn("login:", html)  # payload never stored or shown

    def test_flow_filter_and_export(self):
        self.post("a.pcap", _pcap(self.pk))
        ni = NetworkImport.objects.get()
        html = self.client.get(ni.get_absolute_url(), {"port": "23", "ip": "10.0.0.5"}).content.decode()
        self.assertIn("Flows (2)", html)
        csvr = self.client.get(reverse("network_analysis:export", args=[ni.import_id, "csv"]), {"proto": "tcp", "port": "40001"})
        self.assertEqual(len(list(csv.reader(io.StringIO(csvr.content.decode("utf-8-sig"))))), 2)

    def test_truncated_pcap_rejected(self):
        self.assertEqual(self.post("a.pcap", _pcap(self.pk)[:-4]).status_code, 400)
        self.assertEqual(NetworkImport.objects.count(), 0)


class AppendOnlyTests(NetworkTestCase):
    def test_cannot_delete(self):
        from apps.audit.models import AppendOnlyError
        ni = self.nmap_import()
        with self.assertRaises(AppendOnlyError):
            ni.delete()
        with self.assertRaises(AppendOnlyError):
            NetworkImport.objects.all().delete()


class DashboardTests(NetworkTestCase):
    def test_dashboard_shows_network_imports(self):
        self.nmap_import()
        html = self.client.get(reverse("core:dashboard")).content.decode()
        self.assertIn("Network imports", html)
