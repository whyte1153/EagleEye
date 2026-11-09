from django.contrib import admin

from .models import NetworkHost, NetworkImport


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(NetworkImport)
class NetworkImportAdmin(ReadOnlyAdmin):
    list_display = ("import_id", "kind", "original_filename", "size", "imported_by", "imported_at")
    list_filter = ("kind",)
    search_fields = ("import_id", "original_filename", "sha256")
    exclude = ("data", "findings")


@admin.register(NetworkHost)
class NetworkHostAdmin(ReadOnlyAdmin):
    list_display = ("address", "network_import", "state", "open_ports")
    exclude = ("ports",)
