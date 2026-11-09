import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="Case",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("case_id", models.CharField(blank=True, max_length=20, null=True, unique=True)),
                ("title", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("status", models.CharField(choices=[("open", "Open"), ("in_progress", "In progress"), ("on_hold", "On hold"), ("closed", "Closed")], default="open", max_length=12)),
                ("priority", models.CharField(choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")], default="medium", max_length=10)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("closed_at", models.DateTimeField(blank=True, null=True)),
                ("closure_note", models.TextField(blank=True)),
                ("assigned_to", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="assigned_cases", to=settings.AUTH_USER_MODEL)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="cases_created", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-updated_at", "-id"]},
        ),
        migrations.CreateModel(
            name="CaseLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("scan", "Scan"), ("evidence", "Evidence"), ("network", "Network import")], max_length=10)),
                ("object_ref", models.CharField(max_length=40)),
                ("label", models.CharField(max_length=300)),
                ("linked_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("removed_at", models.DateTimeField(blank=True, null=True)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="links", to="cases.case")),
                ("linked_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("removed_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["linked_at", "id"]},
        ),
        migrations.CreateModel(
            name="CaseEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(max_length=20)),
                ("actor_name", models.CharField(blank=True, max_length=150)),
                ("detail", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="events", to="cases.case")),
            ],
            options={"ordering": ["created_at", "id"]},
        ),
        migrations.AddIndex(model_name="case", index=models.Index(fields=["status"], name="case_status_idx")),
        migrations.AddIndex(model_name="case", index=models.Index(fields=["-updated_at"], name="case_updated_idx")),
        migrations.AddIndex(model_name="caselink", index=models.Index(fields=["case", "kind"], name="caselink_case_kind_idx")),
        migrations.AddIndex(model_name="caselink", index=models.Index(fields=["kind", "object_ref"], name="caselink_obj_idx")),
    ]
