from django.conf import settings
from django.db import models
from django.utils import timezone


class AppendOnlyError(Exception):
    """Raised when code tries to change or delete an audit record."""


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise AppendOnlyError("Audit events cannot be modified.")

    def delete(self):
        raise AppendOnlyError("Audit events cannot be deleted.")

    def bulk_update(self, *args, **kwargs):
        raise AppendOnlyError("Audit events cannot be modified.")


class AuditEvent(models.Model):
    """One immutable record of something that happened in EagleEye.

    The application only ever *adds* rows.  ``save()`` refuses to update an
    existing row and ``delete()`` is blocked, so the history is append-only at
    the application level.  (A database administrator can still alter the
    database directly; for stronger guarantees ship logs to external storage.)
    """

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    # Kept separately so the record stays readable if the user is deleted.
    actor_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=64)
    target = models.CharField(max_length=255, blank=True)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["-created_at"], name="audit_created_idx"),
            models.Index(fields=["action"], name="audit_action_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} by {self.actor_name or 'system'}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AppendOnlyError("Audit events cannot be modified.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AppendOnlyError("Audit events cannot be deleted.")
