import platform

import django
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseServerError
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string

from apps.accounts.roles import ROLE_ADMIN, has_role, role_required

from .models import Module
from .navigation import ADMIN_ONLY
from .services import dashboard_context


@login_required
def dashboard(request):
    ctx = dashboard_context()
    if not has_role(request.user, ROLE_ADMIN):
        ctx["modules"] = [m for m in ctx["modules"] if m.slug not in ADMIN_ONLY]
    return render(request, "core/dashboard.html", ctx)


@login_required
def module_detail(request, slug: str):
    module = get_object_or_404(Module, slug=slug)
    if module.is_ready:
        return redirect(module.get_absolute_url())
    return render(request, "core/module_detail.html", {"module": module})


@role_required(ROLE_ADMIN)
def settings_view(request):
    db_engine = settings.DATABASES["default"]["ENGINE"].rsplit(".", 1)[-1]
    rows = [
        ("Debug mode", "ON (development only)" if settings.DEBUG else "OFF", settings.DEBUG),
        ("Database", db_engine, False),
        ("Allowed hosts", ", ".join(settings.ALLOWED_HOSTS) or "none", False),
        ("Secure session cookie", "Yes" if settings.SESSION_COOKIE_SECURE else "No (HTTP dev)", not settings.SESSION_COOKIE_SECURE),
        ("Session lifetime", f"{settings.SESSION_COOKIE_AGE // 3600} hours", False),
        ("Login throttle", f"{settings.LOGIN_MAX_ATTEMPTS} failures / {settings.LOGIN_LOCKOUT_SECONDS}s lockout", False),
        ("Minimum password length", "12 characters", False),
        ("Scan targets", "Entered on the Scanner page (authorization confirmed per scan); private/metadata addresses always refused", False),
        ("Local lab mode", "Enabled" if settings.EAGLEEYE_LAB_MODE else "Disabled", settings.EAGLEEYE_LAB_MODE),
        ("Lab targets", ", ".join(settings.EAGLEEYE_LAB_TARGETS) or "none", False),
        ("Scan rate limit", f"{settings.SCAN_RATE_LIMIT} per user per 10 min", False),
        ("Scan concurrency", f"{settings.SCAN_MAX_CONCURRENT} at once", False),
        ("Scan timeouts", f"{settings.SCAN_TIMEOUT_SECONDS}s per request / {settings.SCAN_DEADLINE_SECONDS}s total", False),
    ]
    return render(request, "core/settings.html", {
        "rows": rows,
        "versions": [("Python", platform.python_version()), ("Django", django.get_version())],
    })


# --- Error pages: friendly text, no internals --------------------------------
def permission_denied(request, exception=None):
    return render(request, "errors/error.html", {
        "code": 403, "title": "Access denied",
        "message": "Your role does not allow access to this area.",
    }, status=403)


def not_found(request, exception=None):
    return render(request, "errors/error.html", {
        "code": 404, "title": "Signal lost",
        "message": "That page does not exist.",
    }, status=404)


def server_error(request):
    # Rendered without the request so a failing context processor cannot cause a second error.
    html = render_to_string("errors/error.html", {
        "code": 500, "title": "System fault",
        "message": "Something went wrong. The incident was logged.",
    })
    return HttpResponseServerError(html)
