from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from .engine.datatypes import SEVERITY_LABELS

SEVERITY_CHOICES = sorted(SEVERITY_LABELS.items())
SEVERITY_SLUGS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


class Scan(models.Model):
    """One saved assessment of one target URL."""

    QUEUED, RUNNING, COMPLETED, FAILED, BLOCKED = "queued", "running", "completed", "failed", "blocked"
    STATUS_CHOICES = [
        (QUEUED, "Queued"), (RUNNING, "Running"), (COMPLETED, "Completed"),
        (FAILED, "Failed"), (BLOCKED, "Blocked"),
    ]

    target_url = models.CharField(max_length=2048)
    normalized_url = models.CharField(max_length=2048, blank=True)
    host = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=QUEUED)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="scans"
    )
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    final_url = models.CharField(max_length=2048, blank=True)
    final_status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    authorization_confirmed = models.BooleanField(default=False)
    authorization_note = models.CharField(max_length=300, blank=True)

    hops = models.JSONField(default=list, blank=True)
    tls = models.JSONField(null=True, blank=True)
    checks = models.JSONField(default=list, blank=True)
    severity_counts = models.JSONField(default=dict, blank=True)
    findings_count = models.PositiveIntegerField(default=0)
    highest_severity = models.SmallIntegerField(default=-1)  # -1 = no findings

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["-created_at"], name="scan_created_idx"),
            models.Index(fields=["host"], name="scan_host_idx"),
            models.Index(fields=["status"], name="scan_status_idx"),
        ]

    def __str__(self) -> str:
        return f"Scan #{self.pk} {self.normalized_url or self.target_url} [{self.status}]"

    def get_absolute_url(self) -> str:
        return reverse("scanner:detail", kwargs={"pk": self.pk})

    @property
    def highest_severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.highest_severity, "None")

    @property
    def highest_severity_slug(self) -> str:
        return SEVERITY_SLUGS.get(self.highest_severity, "none")


class Finding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    check_id = models.CharField(max_length=60)
    title = models.CharField(max_length=200)
    severity = models.PositiveSmallIntegerField(choices=SEVERITY_CHOICES)
    description = models.TextField()
    impact = models.TextField()
    remediation = models.TextField()
    evidence = models.TextField(blank=True)
    reproduce = models.TextField(blank=True)

    class Meta:
        ordering = ["-severity", "check_id", "id"]
        indexes = [models.Index(fields=["scan", "-severity"], name="finding_scan_sev_idx")]

    def __str__(self) -> str:
        return f"[{self.get_severity_display()}] {self.title}"

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "")

    @property
    def severity_slug(self) -> str:
        return SEVERITY_SLUGS.get(self.severity, "info")
