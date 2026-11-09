from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Profile
from .roles import ROLE_ADMIN, ROLE_REVIEWER


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_profile(sender, instance, created, **kwargs):
    """Every new user automatically gets a Profile.

    Superusers become administrators; everyone else starts as a read-only
    reviewer until an administrator changes it.
    """
    if created:
        Profile.objects.get_or_create(
            user=instance,
            defaults={"role": ROLE_ADMIN if instance.is_superuser else ROLE_REVIEWER},
        )
