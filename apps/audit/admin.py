from django.contrib import admin

from .models import AuditEvent


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    """Read-only in the Django admin: audit history must not be edited."""

    list_display = ("created_at", "action", "actor_name", "target", "ip_address")
    list_filter = ("action",)
    search_fields = ("actor_name", "target", "detail")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
