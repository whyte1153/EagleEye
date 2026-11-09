"""Audit log: append-only behaviour, helper safety and viewer."""
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN
from apps.audit.models import AppendOnlyError, AuditEvent
from apps.audit.services import log_event

User = get_user_model()


class AppendOnlyTests(TestCase):
    def setUp(self):
        self.event = AuditEvent.objects.create(action="test.event", target="x")

    def test_cannot_modify_existing_event(self):
        self.event.target = "changed"
        with self.assertRaises(AppendOnlyError):
            self.event.save()

    def test_cannot_delete_event(self):
        with self.assertRaises(AppendOnlyError):
            self.event.delete()

    def test_queryset_update_and_delete_blocked(self):
        with self.assertRaises(AppendOnlyError):
            AuditEvent.objects.all().update(target="changed")
        with self.assertRaises(AppendOnlyError):
            AuditEvent.objects.all().delete()
        self.assertEqual(AuditEvent.objects.get(pk=self.event.pk).target, "x")

    def test_events_survive_user_deletion(self):
        user = User.objects.create_user("gone", password="correct-horse-battery-9")
        log_event(None, "x.y", actor=user)
        user.delete()
        event = AuditEvent.objects.get(action="x.y")
        self.assertIsNone(event.actor)
        self.assertEqual(event.actor_name, "gone")


class LogEventTests(TestCase):
    def test_records_ip_and_truncates(self):
        request = RequestFactory().get("/", REMOTE_ADDR="10.1.2.3")
        request.user = type("Anon", (), {"is_authenticated": False})()
        event = log_event(request, "a" * 200, target="t" * 500, detail="d" * 5000)
        self.assertEqual(event.ip_address, "10.1.2.3")
        self.assertEqual(len(event.action), 64)
        self.assertEqual(len(event.target), 255)
        self.assertEqual(len(event.detail), 2000)

    def test_never_raises(self):
        self.assertIsNone(log_event(object(), "bad"))  # object() has no META


class AuditViewTests(TestCase):
    def setUp(self):
        admin = User.objects.create_superuser("root", password="correct-horse-battery-9")
        self.assertEqual(admin.profile.role, ROLE_ADMIN)
        self.client.force_login(admin)
        AuditEvent.objects.create(action="alpha.one", actor_name="zed", target="needle")
        AuditEvent.objects.create(action="beta.two", actor_name="amy", target="hay")

    def test_filter_by_action(self):
        html = self.client.get(reverse("audit:list"), {"action": "alpha.one"}).content.decode()
        self.assertIn("needle", html)
        self.assertNotIn("hay<", html)

    def test_search(self):
        html = self.client.get(reverse("audit:list"), {"q": "amy"}).content.decode()
        self.assertIn("beta.two", html)

    def test_output_is_escaped(self):
        AuditEvent.objects.create(action="xss.test", target="<script>alert(1)</script>")
        html = self.client.get(reverse("audit:list")).content.decode()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
