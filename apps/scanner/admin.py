from django.contrib import admin

from .models import Finding, Scan


class ReadOnlyAdmin(admin.ModelAdmin):
    """Saved assessments are records; they are not edited through the admin."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Scan)
class ScanAdmin(ReadOnlyAdmin):
    list_display = ("id", "normalized_url", "status", "highest_severity", "created_by", "created_at")
    list_filter = ("status",)
    search_fields = ("normalized_url", "host")


@admin.register(Finding)
class FindingAdmin(ReadOnlyAdmin):
    list_display = ("title", "severity", "scan")
    list_filter = ("severity",)
