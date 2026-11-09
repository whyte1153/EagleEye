from django.db import models
from django.urls import reverse


class Module(models.Model):
    """One EagleEye module (scanner, forensics, ...) and how far along it is.

    The dashboard's "Module Overview" is built from these rows, so the status
    shown to users always comes from the database.  When a later phase ships a
    module, its row is switched to ``ready`` and given a ``url_name``.
    """

    PLANNED = "planned"
    READY = "ready"
    STATUS_CHOICES = [(PLANNED, "Planned"), (READY, "Online")]

    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=80)
    summary = models.CharField(max_length=240)
    features = models.TextField(blank=True, help_text="One planned feature per line.")
    icon = models.SlugField(max_length=30, default="shield")
    phase = models.PositiveSmallIntegerField(help_text="Development phase that delivers it.")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PLANNED)
    url_name = models.CharField(max_length=60, blank=True, help_text="URL name once the module is online.")
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["order", "name"]

    def __str__(self) -> str:
        return self.name

    @property
    def is_ready(self) -> bool:
        return self.status == self.READY and bool(self.url_name)

    @property
    def feature_list(self) -> list[str]:
        return [line.strip() for line in self.features.splitlines() if line.strip()]

    def get_absolute_url(self) -> str:
        if self.is_ready:
            return reverse(self.url_name)
        return reverse("core:module_detail", kwargs={"slug": self.slug})
