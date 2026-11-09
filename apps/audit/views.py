from urllib.parse import urlencode

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render

from apps.accounts.roles import ROLE_ADMIN, role_required

from .models import AuditEvent


@role_required(ROLE_ADMIN)
def audit_list(request):
    events = AuditEvent.objects.select_related("actor")
    action = request.GET.get("action", "").strip()
    query = request.GET.get("q", "").strip()
    if action:
        events = events.filter(action=action)
    if query:
        events = events.filter(
            Q(actor_name__icontains=query) | Q(target__icontains=query) | Q(detail__icontains=query)
        )
    page = Paginator(events, 25).get_page(request.GET.get("page"))
    actions = AuditEvent.objects.order_by().values_list("action", flat=True).distinct()
    return render(request, "audit/audit_list.html", {
        "page": page,
        "actions": sorted(actions),
        "selected_action": action,
        "query": query,
        "pager_query": urlencode({k: v for k, v in {"action": action, "q": query}.items() if v}),
    })
