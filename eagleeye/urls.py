"""Root URL configuration."""
from django.contrib import admin
from django.urls import include, path

handler403 = "apps.core.views.permission_denied"
handler404 = "apps.core.views.not_found"
handler500 = "apps.core.views.server_error"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("apps.accounts.urls")),
    path("audit/", include("apps.audit.urls")),
    path("scanner/", include("apps.scanner.urls")),
    path("forensics/", include("apps.forensics.urls")),
    path("network/", include("apps.network_analysis.urls")),
    path("", include("apps.core.urls")),
]
