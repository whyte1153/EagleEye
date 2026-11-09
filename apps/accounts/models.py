from django.conf import settings
from django.db import models

from .roles import ROLE_CHOICES, ROLE_REVIEWER


class Profile(models.Model):
    """Extra data attached to Django's built-in User: currently just the role."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_REVIEWER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["user__username"]

    def __str__(self) -> str:
        return f"{self.user.get_username()} ({self.get_role_display()})"
