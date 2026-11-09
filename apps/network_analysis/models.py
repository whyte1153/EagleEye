from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AppendOnlyError


class NoDeleteQuerySet(models.QuerySet):
    def delete(self):
        raise AppendOnlyError("Network imports cannot be deleted through EagleEye.")


class NetworkImport(models.Model):
    """One imported Nmap XML or PCAP file.  Only parsed results are kept; the uploaded file is not retained or executed.

    Keep the original in the Evidence Vault if you need to preserve it (chain of custody).
    """

    NMAP, PCAP = "nmap", "pcap"
    KIND_CHOICES = [(NMAP, "Nmap XML"), (PCAP, "PCAP / PCAPNG")]

    import_id = models.CharField(max_length=20, unique=True, null=True, blank=True)  # NI-2026-000001
    kind = models.CharField(max_length=8, choices=KIND_CHOICES)
    original_filename = models.CharField(max_length=255)
    size = models.BigIntegerField()
    sha256 = models.CharField(max_length=64)
    case_reference = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    imported_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="network_imports")
    imported_at = models.DateTimeField(default=timezone.now)

    summary = models.JSONField(default=dict, blank=True)    # counts and headline numbers
    warnings = models.JSONField(default=list, blank=True)   # limits reached, skipped items
    findings = models.JSONField(default=list, blank=True)   # PCAP heuristic findings
    data = models.JSONField(default=dict, blank=True)       # PCAP: protocols, talkers, flows, dns; Nmap: scanner info
    max_severity = models.SmallIntegerField(default=-1)     # -1 = nothing flagged

    objects = NoDeleteQuerySet.as_manager()

    class Meta:
        ordering = ["-imported_at", "-id"]
        indexes = [models.Index(fields=["-imported_at"], name="ni_imported_idx"),
                   models.Index(fields=["kind"], name="ni_kind_idx"),
                   models.Index(fields=["sha256"], name="ni_sha_idx")]

    def __str__(self):
        return f"{self.import_id} {self.original_filename}"

    def get_absolute_url(self):
        return reverse("network_analysis:detail", args=[self.import_id])

    def delete(self, *a, **k):
        raise AppendOnlyError("Network imports cannot be deleted through EagleEye.")


class NetworkHost(models.Model):
    """A host from an Nmap import, with its ports stored as JSON (bounded by the parser limits)."""

    network_import = models.ForeignKey(NetworkImport, on_delete=models.PROTECT, related_name="hosts")
    address = models.CharField(max_length=45)
    hostnames = models.CharField(max_length=600, blank=True)
    state = models.CharField(max_length=20, blank=True)
    os_guess = models.CharField(max_length=140, blank=True)
    mac = models.CharField(max_length=64, blank=True)
    vendor = models.CharField(max_length=80, blank=True)
    open_ports = models.IntegerField(default=0)
    max_severity = models.SmallIntegerField(default=-1)
    ports = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-max_severity", "address"]
        indexes = [models.Index(fields=["network_import", "address"], name="nh_import_addr_idx")]

    def __str__(self):
        return self.address
