"""Role names and helpers used for role-based access control (RBAC)."""
from __future__ import annotations

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

ROLE_ADMIN = "admin"
ROLE_INVESTIGATOR = "investigator"
ROLE_REVIEWER = "reviewer"

ROLE_CHOICES = [
    (ROLE_ADMIN, "Administrator"),
    (ROLE_INVESTIGATOR, "Investigator"),
    (ROLE_REVIEWER, "Read-only reviewer"),
]

ROLE_DESCRIPTIONS = {
    ROLE_ADMIN: "Full access: manages users, settings, audit logs and all modules.",
    ROLE_INVESTIGATOR: "Runs assessments, handles evidence and manages cases.",
    ROLE_REVIEWER: "Read-only access to results and reports.",
}


def get_role(user) -> str | None:
    """Return the user's role name, or None for anonymous users.

    Superusers are always administrators.  Anyone without a profile is treated
    as a read-only reviewer (least privilege).
    """
    if not user.is_authenticated:
        return None
    if user.is_superuser:
        return ROLE_ADMIN
    profile = getattr(user, "profile", None)
    return profile.role if profile else ROLE_REVIEWER


def has_role(user, *roles: str) -> bool:
    return get_role(user) in roles


def role_required(*roles: str):
    """View decorator: user must be logged in AND hold one of ``roles``.

    Logged-out users are sent to the login page; logged-in users without the
    right role receive a 403 page.
    """

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(request, *args, **kwargs):
            if not has_role(request.user, *roles):
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
