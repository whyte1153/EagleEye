from django.contrib import admin

from .models import CustodyEvent, EvidenceItem, EvidenceNote


class ReadOnlyAdmin(admin.ModelAdmin):
    """Evidence records are never edited or deleted through the admin site."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(EvidenceItem)
class EvidenceItemAdmin(ReadOnlyAdmin):
    list_display = ("evidence_id", "original_filename", "size", "integrity_status", "mismatch", "uploaded_at")
    list_filter = ("integrity_status", "mismatch")
    search_fields = ("evidence_id", "original_filename", "sha256")
    exclude = ("stored_name",)


@admin.register(EvidenceNote)
class EvidenceNoteAdmin(ReadOnlyAdmin):
    list_display = ("evidence", "author_name", "created_at")


@admin.register(CustodyEvent)
class CustodyEventAdmin(ReadOnlyAdmin):
    list_display = ("evidence", "action", "actor_name", "created_at")
    list_filter = ("action",)
