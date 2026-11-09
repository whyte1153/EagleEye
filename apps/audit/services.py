"""The one function the rest of EagleEye uses to write audit events."""
from __future__ import annotations

import logging

from .models import AuditEvent

logger = logging.getLogger(__name__)


def log_event(request, action: str, *, target: str = "", detail: str = "", actor=None) -> AuditEvent | None:
    """Record an audit event.  Never raises: auditing must not break a request."""
    try:
        user = actor
        if user is None and request is not None:
            candidate = getattr(request, "user", None)
            if candidate is not None and candidate.is_authenticated:
                user = candidate
        ip = request.META.get("REMOTE_ADDR") if request is not None else None
        return AuditEvent.objects.create(
            actor=user,
            actor_name=(user.get_username() if user else "")[:150],
            action=action[:64],
            target=target[:255],
            detail=detail[:2000],
            ip_address=ip or None,
        )
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to write audit event %s", action)
        return None
