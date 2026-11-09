"""Phase 2: the scanner and scan-history modules are now online."""
from django.db import migrations

ONLINE = {"scanner": "scanner:home", "scan-history": "scanner:history"}


def go_online(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    for slug, url_name in ONLINE.items():
        Module.objects.filter(slug=slug).update(status="ready", url_name=url_name)


def go_offline(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    Module.objects.filter(slug__in=ONLINE).update(status="planned", url_name="")


class Migration(migrations.Migration):

    dependencies = [("core", "0002_seed_modules")]

    operations = [migrations.RunPython(go_online, go_offline)]
