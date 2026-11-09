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
            name="EvidenceItem",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("evidence_id", models.CharField(blank=True, max_length=20, null=True, unique=True)),
                ("original_filename", models.CharField(max_length=255)),
                ("stored_name", models.CharField(max_length=32, unique=True)),
                ("size", models.BigIntegerField()),
                ("sha256", models.CharField(max_length=64)),
                ("md5", models.CharField(blank=True, max_length=32)),
                ("declared_extension", models.CharField(blank=True, max_length=20)),
                ("detected_kind", models.CharField(blank=True, max_length=40)),
                ("detected_mime", models.CharField(blank=True, max_length=120)),
                ("detected_category", models.CharField(blank=True, max_length=20)),
                ("extension_severity", models.CharField(default="match", max_length=8)),
                ("extension_note", models.TextField(blank=True)),
                ("mismatch", models.BooleanField(default=False)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("case_reference", models.CharField(blank=True, max_length=100)),
                ("description", models.TextField(blank=True)),
                ("uploaded_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("integrity_status", models.CharField(choices=[("unverified", "Unverified"), ("verified", "Verified"), ("failed", "FAILED"), ("missing", "Missing")], default="unverified", max_length=10)),
                ("last_verified_at", models.DateTimeField(blank=True, null=True)),
                ("last_verified_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("uploaded_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="evidence_uploaded", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-uploaded_at", "-id"]},
        ),
        migrations.CreateModel(
            name="EvidenceNote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("author_name", models.CharField(blank=True, max_length=150)),
                ("text", models.TextField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("author", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("evidence", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="notes", to="forensics.evidenceitem")),
            ],
            options={"ordering": ["created_at", "id"]},
        ),
        migrations.CreateModel(
            name="CustodyEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("actor_name", models.CharField(blank=True, max_length=150)),
                ("action", models.CharField(max_length=40)),
                ("detail", models.TextField(blank=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("prev_hash", models.CharField(max_length=64)),
                ("entry_hash", models.CharField(max_length=64)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("evidence", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="events", to="forensics.evidenceitem")),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.AddIndex(model_name="evidenceitem", index=models.Index(fields=["-uploaded_at"], name="ev_uploaded_idx")),
        migrations.AddIndex(model_name="evidenceitem", index=models.Index(fields=["sha256"], name="ev_sha256_idx")),
        migrations.AddIndex(model_name="evidenceitem", index=models.Index(fields=["integrity_status"], name="ev_integrity_idx")),
        migrations.AddIndex(model_name="evidenceitem", index=models.Index(fields=["case_reference"], name="ev_case_idx")),
    ]
