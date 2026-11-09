from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AppendOnlyError, AppendOnlyQuerySet


class NoDeleteQuerySet(models.QuerySet):
    def delete(self):
        raise AppendOnlyError("Evidence records cannot be deleted through EagleEye.")


class EvidenceItem(models.Model):
    """One preserved evidence file.  The original bytes live in the evidence store and are never modified."""

    UNVERIFIED, VERIFIED, FAILED, MISSING = "unverified", "verified", "failed", "missing"
    INTEGRITY_CHOICES = [(UNVERIFIED, "Unverified"), (VERIFIED, "Verified"), (FAILED, "FAILED"), (MISSING, "Missing")]

    evidence_id = models.CharField(max_length=20, unique=True, null=True, blank=True)  # EV-2026-000001
    original_filename = models.CharField(max_length=255)  # sanitised, display only
    stored_name = models.CharField(max_length=32, unique=True)  # random name in the store
    size = models.BigIntegerField()
    sha256 = models.CharField(max_length=64)
    md5 = models.CharField(max_length=32, blank=True)  # legacy identification only

    declared_extension = models.CharField(max_length=20, blank=True)
    detected_kind = models.CharField(max_length=40, blank=True)
    detected_mime = models.CharField(max_length=120, blank=True)
    detected_category = models.CharField(max_length=20, blank=True)
    extension_severity = models.CharField(max_length=8, default="match")
    extension_note = models.TextField(blank=True)
    mismatch = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)

    case_reference = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="evidence_uploaded")
    uploaded_at = models.DateTimeField(default=timezone.now)

    integrity_status = models.CharField(max_length=10, choices=INTEGRITY_CHOICES, default=UNVERIFIED)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    last_verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                         on_delete=models.SET_NULL, related_name="+")

    objects = NoDeleteQuerySet.as_manager()

    class Meta:
        ordering = ["-uploaded_at", "-id"]
        indexes = [
            models.Index(fields=["-uploaded_at"], name="ev_uploaded_idx"),
            models.Index(fields=["sha256"], name="ev_sha256_idx"),
            models.Index(fields=["integrity_status"], name="ev_integrity_idx"),
            models.Index(fields=["case_reference"], name="ev_case_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.evidence_id} {self.original_filename}"

    def delete(self, *args, **kwargs):
        raise AppendOnlyError("Evidence records cannot be deleted through EagleEye.")

    def get_absolute_url(self) -> str:
        return reverse("forensics:detail", kwargs={"eid": self.evidence_id})


class EvidenceNote(models.Model):
    """Investigator note.  Notes are immutable: correct a mistake by adding a new note."""

    evidence = models.ForeignKey(EvidenceItem, on_delete=models.PROTECT, related_name="notes")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    author_name = models.CharField(max_length=150, blank=True)
    text = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["created_at", "id"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AppendOnlyError("Notes cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AppendOnlyError("Notes cannot be deleted.")


class CustodyEvent(models.Model):
    """Append-only, hash-chained chain-of-custody entry for one evidence item."""

    evidence = models.ForeignKey(EvidenceItem, on_delete=models.PROTECT, related_name="events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    actor_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=40)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["id"]  # insertion order IS chain order

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AppendOnlyError("Custody events cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AppendOnlyError("Custody events cannot be deleted.")
