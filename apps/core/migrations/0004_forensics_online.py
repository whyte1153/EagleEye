"""Phase 3: digital forensics and the evidence vault are now online."""
from django.db import migrations

ONLINE = {"forensics": "forensics:home", "evidence-vault": "forensics:vault"}


def go_online(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    for slug, url_name in ONLINE.items():
        Module.objects.filter(slug=slug).update(status="ready", url_name=url_name)


def go_offline(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    Module.objects.filter(slug__in=ONLINE).update(status="planned", url_name="")


class Migration(migrations.Migration):

    dependencies = [("core", "0003_scanner_online")]

    operations = [migrations.RunPython(go_online, go_offline)]
