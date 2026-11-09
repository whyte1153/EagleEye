"""Authentication, throttling, roles and user management (integration tests)."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.accounts.roles import ROLE_ADMIN, ROLE_INVESTIGATOR, ROLE_REVIEWER, get_role
from apps.audit.models import AuditEvent

User = get_user_model()
PASSWORD = "correct-horse-battery-9"


def make_user(username: str, role: str = ROLE_REVIEWER, **extra) -> "User":
    user = User.objects.create_user(username, password=PASSWORD, **extra)
    user.profile.role = role
    user.profile.save()
    return user


class ProfileTests(TestCase):
    def test_regular_user_defaults_to_reviewer(self):
        self.assertEqual(User.objects.create_user("a", password=PASSWORD).profile.role, ROLE_REVIEWER)

    def test_superuser_is_admin(self):
        user = User.objects.create_superuser("root", password=PASSWORD)
        self.assertEqual(user.profile.role, ROLE_ADMIN)
        self.assertEqual(get_role(user), ROLE_ADMIN)


class LoginTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user("alice", ROLE_INVESTIGATOR)

    def test_anonymous_is_redirected_to_login(self):
        response = self.client.get(reverse("core:dashboard"))
        self.assertRedirects(response, f"{reverse('accounts:login')}?next=/")

    def test_login_page_renders(self):
        self.assertContains(self.client.get(reverse("accounts:login")), "Authenticate")

    def test_successful_login_redirects_and_is_audited(self):
        response = self.client.post(reverse("accounts:login"), {"username": "alice", "password": PASSWORD})
        self.assertRedirects(response, reverse("core:dashboard"))
        self.assertTrue(AuditEvent.objects.filter(action="auth.login", actor_name="alice").exists())

    def test_failed_login_is_audited_without_password(self):
        self.client.post(reverse("accounts:login"), {"username": "alice", "password": "wrong-pass-123"})
        event = AuditEvent.objects.get(action="auth.login_failed")
        self.assertEqual(event.target, "alice")
        self.assertNotIn("wrong-pass-123", f"{event.detail}{event.target}")

    @override_settings(LOGIN_MAX_ATTEMPTS=3)
    def test_lockout_after_repeated_failures(self):
        for _ in range(3):
            self.client.post(reverse("accounts:login"), {"username": "alice", "password": "nope-nope-nope"})
        # Even the correct password is refused while locked.
        response = self.client.post(reverse("accounts:login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertTrue(AuditEvent.objects.filter(action="auth.login_blocked").exists())

    def test_logout_requires_post(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("accounts:logout")).status_code, 405)
        self.client.post(reverse("accounts:logout"))
        self.assertTrue(AuditEvent.objects.filter(action="auth.logout").exists())
        self.assertEqual(self.client.get(reverse("core:dashboard")).status_code, 302)

    def test_login_enforces_csrf(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(reverse("accounts:login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 403)


class RolePermissionTests(TestCase):
    ADMIN_URLS = ["accounts:users", "audit:list", "core:settings"]

    def setUp(self):
        self.admin = make_user("boss", ROLE_ADMIN)
        self.investigator = make_user("inv", ROLE_INVESTIGATOR)
        self.reviewer = make_user("rev", ROLE_REVIEWER)

    def test_admin_only_pages(self):
        for user, expected in [(self.admin, 200), (self.investigator, 403), (self.reviewer, 403)]:
            self.client.force_login(user)
            for name in self.ADMIN_URLS:
                with self.subTest(user=user.username, url=name):
                    self.assertEqual(self.client.get(reverse(name)).status_code, expected)

    def test_everyone_can_open_dashboard(self):
        for user in (self.admin, self.investigator, self.reviewer):
            self.client.force_login(user)
            self.assertEqual(self.client.get(reverse("core:dashboard")).status_code, 200)

    def test_sidebar_hides_admin_items_from_non_admins(self):
        self.client.force_login(self.reviewer)
        html = self.client.get(reverse("core:dashboard")).content.decode()
        self.assertNotIn(reverse("accounts:users"), html)
        self.client.force_login(self.admin)
        html = self.client.get(reverse("core:dashboard")).content.decode()
        self.assertIn(reverse("accounts:users"), html)


class UserManagementTests(TestCase):
    def setUp(self):
        self.admin = make_user("boss", ROLE_ADMIN)
        self.client.force_login(self.admin)

    def test_create_user_with_role(self):
        response = self.client.post(reverse("accounts:users"), {
            "username": "newbie", "email": "n@example.org", "role": ROLE_INVESTIGATOR,
            "password1": PASSWORD, "password2": PASSWORD,
        })
        self.assertRedirects(response, reverse("accounts:users"))
        self.assertEqual(User.objects.get(username="newbie").profile.role, ROLE_INVESTIGATOR)
        self.assertTrue(AuditEvent.objects.filter(action="user.created", target="newbie").exists())

    def test_weak_password_rejected(self):
        response = self.client.post(reverse("accounts:users"), {
            "username": "weak", "role": ROLE_REVIEWER, "password1": "short1", "password2": "short1",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="weak").exists())

    def test_change_role_is_audited(self):
        target = make_user("target", ROLE_REVIEWER)
        self.client.post(reverse("accounts:change_role", args=[target.pk]), {"role": ROLE_INVESTIGATOR})
        target.profile.refresh_from_db()
        self.assertEqual(target.profile.role, ROLE_INVESTIGATOR)
        self.assertTrue(AuditEvent.objects.filter(action="user.role_changed", target="target").exists())

    def test_invalid_role_rejected(self):
        target = make_user("target", ROLE_REVIEWER)
        self.client.post(reverse("accounts:change_role", args=[target.pk]), {"role": "root"})
        target.profile.refresh_from_db()
        self.assertEqual(target.profile.role, ROLE_REVIEWER)

    def test_cannot_change_own_role(self):
        self.client.post(reverse("accounts:change_role", args=[self.admin.pk]), {"role": ROLE_REVIEWER})
        self.admin.profile.refresh_from_db()
        self.assertEqual(self.admin.profile.role, ROLE_ADMIN)

    def test_non_admin_cannot_change_roles(self):
        reviewer = make_user("rev", ROLE_REVIEWER)
        self.client.force_login(reviewer)
        response = self.client.post(reverse("accounts:change_role", args=[reviewer.pk]), {"role": ROLE_ADMIN})
        self.assertEqual(response.status_code, 403)
        reviewer.profile.refresh_from_db()
        self.assertEqual(reviewer.profile.role, ROLE_REVIEWER)

    def test_change_role_is_post_only(self):
        target = make_user("target", ROLE_REVIEWER)
        self.assertEqual(self.client.get(reverse("accounts:change_role", args=[target.pk])).status_code, 405)
