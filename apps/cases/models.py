from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AppendOnlyError, AppendOnlyQuerySet


class NoDeleteQuerySet(models.QuerySet):
    def delete(self):
        raise AppendOnlyError("Cases cannot be deleted through EagleEye.")


class Case(models.Model):
    OPEN, IN_PROGRESS, ON_HOLD, CLOSED = "open", "in_progress", "on_hold", "closed"
    STATUS_CHOICES = [(OPEN, "Open"), (IN_PROGRESS, "In progress"), (ON_HOLD, "On hold"), (CLOSED, "Closed")]
    LOW, MEDIUM, HIGH, CRITICAL = "low", "medium", "high", "critical"
    PRIORITY_CHOICES = [(LOW, "Low"), (MEDIUM, "Medium"), (HIGH, "High"), (CRITICAL, "Critical")]
    PRIORITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

    case_id = models.CharField(max_length=20, unique=True, null=True, blank=True)  # CS-2026-000001
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=OPEN)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default=MEDIUM)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="assigned_cases")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="cases_created")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    closed_at = models.DateTimeField(null=True, blank=True)
    closure_note = models.TextField(blank=True)

    objects = NoDeleteQuerySet.as_manager()

    class Meta:
        ordering = ["-updated_at", "-id"]
        indexes = [models.Index(fields=["status"], name="case_status_idx"),
                   models.Index(fields=["-updated_at"], name="case_updated_idx")]

    def __str__(self):
        return f"{self.case_id} {self.title}"

    def get_absolute_url(self):
        return reverse("cases:detail", args=[self.case_id])

    def delete(self, *a, **k):
        raise AppendOnlyError("Cases cannot be deleted through EagleEye.")

    @property
    def is_closed(self):
        return self.status == self.CLOSED


class CaseLink(models.Model):
    """A reference from a case to a scan, evidence item or network import.  Unlinking is recorded, never erased."""

    SCAN, EVIDENCE, NETWORK = "scan", "evidence", "network"
    KIND_CHOICES = [(SCAN, "Scan"), (EVIDENCE, "Evidence"), (NETWORK, "Network import")]

    case = models.ForeignKey(Case, on_delete=models.PROTECT, related_name="links")
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    object_ref = models.CharField(max_length=40)  # scan pk, EV-..., or NI-...
    label = models.CharField(max_length=300)      # snapshot so the case reads well even if the object changes
    linked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    linked_at = models.DateTimeField(default=timezone.now)
    removed_at = models.DateTimeField(null=True, blank=True)
    removed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["linked_at", "id"]
        indexes = [models.Index(fields=["case", "kind"], name="caselink_case_kind_idx"),
                   models.Index(fields=["kind", "object_ref"], name="caselink_obj_idx")]

    def __str__(self):
        return f"{self.case_id}: {self.kind} {self.object_ref}"

    @property
    def active(self):
        return self.removed_at is None


class CaseEvent(models.Model):
    """Append-only timeline entry (including investigator notes)."""

    case = models.ForeignKey(Case, on_delete=models.PROTECT, related_name="events")
    kind = models.CharField(max_length=20)  # created, note, status, priority, assigned, linked, unlinked, edited
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    actor_name = models.CharField(max_length=150, blank=True)
    detail = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["created_at", "id"]

    def save(self, *a, **k):
        if not self._state.adding:
            raise AppendOnlyError("Case timeline entries cannot be modified.")
        super().save(*a, **k)

    def delete(self, *a, **k):
        raise AppendOnlyError("Case timeline entries cannot be deleted.")
