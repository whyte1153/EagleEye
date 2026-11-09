"""Simple failed-login throttle using Django's cache.

Counts failures per client IP and per username.  When either reaches
``LOGIN_MAX_ATTEMPTS`` within ``LOGIN_LOCKOUT_SECONDS`` the login form refuses
further attempts until the window expires.  The default cache is per-process
memory, which is fine for development; use a shared cache (Redis, etc.) in
production with several workers.
"""
from __future__ import annotations

import hashlib

from django.conf import settings
from django.core.cache import cache


def client_ip(request) -> str:
    # REMOTE_ADDR only: X-Forwarded-For can be forged unless a trusted proxy sets it.
    return request.META.get("REMOTE_ADDR", "unknown")


def _keys(request, username: str) -> list[str]:
    digest = hashlib.sha256(username.strip().lower().encode()).hexdigest()[:32]
    return [f"eagleeye:login:ip:{client_ip(request)}", f"eagleeye:login:user:{digest}"]


def is_locked(request, username: str) -> bool:
    return any(cache.get(key, 0) >= settings.LOGIN_MAX_ATTEMPTS for key in _keys(request, username))


def register_failure(request, username: str) -> None:
    for key in _keys(request, username):
        cache.add(key, 0, timeout=settings.LOGIN_LOCKOUT_SECONDS)
        try:
            cache.incr(key)
        except ValueError:  # key expired between add() and incr()
            cache.set(key, 1, timeout=settings.LOGIN_LOCKOUT_SECONDS)


def reset(request, username: str) -> None:
    for key in _keys(request, username):
        cache.delete(key)
