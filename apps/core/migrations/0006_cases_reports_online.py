"""Phase 5: cases and reports are now online."""
from django.db import migrations

ONLINE = {"cases": "cases:list", "reports": "reports:home"}


def go_online(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    for slug, url_name in ONLINE.items():
        Module.objects.filter(slug=slug).update(status="ready", url_name=url_name)
    Module.objects.filter(slug="audit-logs").update(
        summary="Append-only history of sign-ins, scans, evidence, imports, cases and reports, with filters and export.",
        features="Filter by action, actor and date\nSearch actor, target and detail\nCSV and JSON export with SHA-256")


def go_offline(apps, schema_editor):
    apps.get_model("core", "Module").objects.filter(slug__in=ONLINE).update(status="planned", url_name="")


class Migration(migrations.Migration):

    dependencies = [("core", "0005_network_online")]

    operations = [migrations.RunPython(go_online, go_offline)]
