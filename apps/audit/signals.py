from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .services import log_event


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    log_event(request, "auth.login", target=user.get_username(), actor=user)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user is not None:
        log_event(request, "auth.logout", target=user.get_username(), actor=user)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    # Only the attempted username is stored - never the password.
    attempted = str((credentials or {}).get("username", ""))[:150]
    log_event(request, "auth.login_failed", target=attempted)
