from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Module",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slug", models.SlugField(unique=True)),
                ("name", models.CharField(max_length=80)),
                ("summary", models.CharField(max_length=240)),
                ("features", models.TextField(blank=True, help_text="One planned feature per line.")),
                ("icon", models.SlugField(default="shield", max_length=30)),
                ("phase", models.PositiveSmallIntegerField(help_text="Development phase that delivers it.")),
                ("status", models.CharField(choices=[("planned", "Planned"), ("ready", "Online")], default="planned", max_length=10)),
                ("url_name", models.CharField(blank=True, help_text="URL name once the module is online.", max_length=60)),
                ("order", models.PositiveSmallIntegerField(default=0)),
            ],
            options={"ordering": ["order", "name"]},
        ),
    ]
