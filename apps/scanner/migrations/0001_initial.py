import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Scan",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("target_url", models.CharField(max_length=2048)),
                ("normalized_url", models.CharField(blank=True, max_length=2048)),
                ("host", models.CharField(blank=True, max_length=255)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed"), ("blocked", "Blocked")], default="queued", max_length=12)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("final_url", models.CharField(blank=True, max_length=2048)),
                ("final_status_code", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("response_time_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("duration_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("error_message", models.TextField(blank=True)),
                ("authorization_confirmed", models.BooleanField(default=False)),
                ("authorization_note", models.CharField(blank=True, max_length=300)),
                ("hops", models.JSONField(blank=True, default=list)),
                ("tls", models.JSONField(blank=True, null=True)),
                ("checks", models.JSONField(blank=True, default=list)),
                ("severity_counts", models.JSONField(blank=True, default=dict)),
                ("findings_count", models.PositiveIntegerField(default=0)),
                ("highest_severity", models.SmallIntegerField(default=-1)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="scans", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at", "-id"]},
        ),
        migrations.CreateModel(
            name="Finding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("check_id", models.CharField(max_length=60)),
                ("title", models.CharField(max_length=200)),
                ("severity", models.PositiveSmallIntegerField(choices=[(0, "Informational"), (1, "Low"), (2, "Medium"), (3, "High"), (4, "Critical")])),
                ("description", models.TextField()),
                ("impact", models.TextField()),
                ("remediation", models.TextField()),
                ("evidence", models.TextField(blank=True)),
                ("reproduce", models.TextField(blank=True)),
                ("scan", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="scanner.scan")),
            ],
            options={"ordering": ["-severity", "check_id", "id"]},
        ),
        migrations.AddIndex(model_name="scan", index=models.Index(fields=["-created_at"], name="scan_created_idx")),
        migrations.AddIndex(model_name="scan", index=models.Index(fields=["host"], name="scan_host_idx")),
        migrations.AddIndex(model_name="scan", index=models.Index(fields=["status"], name="scan_status_idx")),
        migrations.AddIndex(model_name="finding", index=models.Index(fields=["scan", "-severity"], name="finding_scan_sev_idx")),
    ]
