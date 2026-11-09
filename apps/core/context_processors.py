"""Adds the sidebar navigation and current role to every template."""
from django.db.utils import OperationalError, ProgrammingError
from django.urls import reverse

from apps.accounts.roles import ROLE_CHOICES, get_role

from .models import Module
from .navigation import ADMIN_ONLY, ADMIN_ROLE, SECTIONS


def navigation(request):
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {}

    role = get_role(user)
    try:
        modules = {m.slug: m for m in Module.objects.all()}
    except (OperationalError, ProgrammingError):  # tables missing before `migrate`
        modules = {}

    path = request.path
    dashboard_url = reverse("core:dashboard")
    sections = [{
        "title": "Command",
        "items": [{
            "slug": "dashboard", "label": "Dashboard", "icon": "dashboard",
            "url": dashboard_url, "active": path == dashboard_url, "planned": False,
        }],
    }]
    for title, slugs in SECTIONS:
        items = []
        for slug in slugs:
            module = modules.get(slug)
            if module is None or (slug in ADMIN_ONLY and role != ADMIN_ROLE):
                continue
            url = module.get_absolute_url()
            items.append({
                "slug": slug, "label": module.name, "icon": module.icon, "url": url,
                "active": path.startswith(url), "planned": not module.is_ready,
                "phase": module.phase,
            })
        if items:
            sections.append({"title": title, "items": items})

    # Several items can share a URL prefix (/scanner/ and /scanner/history/): highlight only the longest match.
    candidates = [i for sec in sections for i in sec["items"] if i["slug"] != "dashboard" and path.startswith(i["url"])]
    best = max(candidates, key=lambda i: len(i["url"]), default=None)
    for sec in sections:
        for item in sec["items"]:
            if item["slug"] != "dashboard":
                item["active"] = item is best

    return {
        "nav_sections": sections,
        "current_role": role,
        "current_role_label": dict(ROLE_CHOICES).get(role, ""),
    }
