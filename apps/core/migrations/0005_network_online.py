"""Phase 4: network analysis is now online."""
from django.db import migrations


def go_online(apps, schema_editor):
    apps.get_model("core", "Module").objects.filter(slug="network").update(status="ready", url_name="network_analysis:home")


def go_offline(apps, schema_editor):
    apps.get_model("core", "Module").objects.filter(slug="network").update(status="planned", url_name="")


class Migration(migrations.Migration):

    dependencies = [("core", "0004_forensics_online")]

    operations = [migrations.RunPython(go_online, go_offline)]
