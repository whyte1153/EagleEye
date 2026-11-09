import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="NetworkImport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("import_id", models.CharField(blank=True, max_length=20, null=True, unique=True)),
                ("kind", models.CharField(choices=[("nmap", "Nmap XML"), ("pcap", "PCAP / PCAPNG")], max_length=8)),
                ("original_filename", models.CharField(max_length=255)),
                ("size", models.BigIntegerField()),
                ("sha256", models.CharField(max_length=64)),
                ("case_reference", models.CharField(blank=True, max_length=100)),
                ("description", models.TextField(blank=True)),
                ("imported_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("warnings", models.JSONField(blank=True, default=list)),
                ("findings", models.JSONField(blank=True, default=list)),
                ("data", models.JSONField(blank=True, default=dict)),
                ("max_severity", models.SmallIntegerField(default=-1)),
                ("imported_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="network_imports", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-imported_at", "-id"]},
        ),
        migrations.CreateModel(
            name="NetworkHost",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("address", models.CharField(max_length=45)),
                ("hostnames", models.CharField(blank=True, max_length=600)),
                ("state", models.CharField(blank=True, max_length=20)),
                ("os_guess", models.CharField(blank=True, max_length=140)),
                ("mac", models.CharField(blank=True, max_length=64)),
                ("vendor", models.CharField(blank=True, max_length=80)),
                ("open_ports", models.IntegerField(default=0)),
                ("max_severity", models.SmallIntegerField(default=-1)),
                ("ports", models.JSONField(blank=True, default=list)),
                ("network_import", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="hosts", to="network_analysis.networkimport")),
            ],
            options={"ordering": ["-max_severity", "address"]},
        ),
        migrations.AddIndex(model_name="networkimport", index=models.Index(fields=["-imported_at"], name="ni_imported_idx")),
        migrations.AddIndex(model_name="networkimport", index=models.Index(fields=["kind"], name="ni_kind_idx")),
        migrations.AddIndex(model_name="networkimport", index=models.Index(fields=["sha256"], name="ni_sha_idx")),
        migrations.AddIndex(model_name="networkhost", index=models.Index(fields=["network_import", "address"], name="nh_import_addr_idx")),
    ]
