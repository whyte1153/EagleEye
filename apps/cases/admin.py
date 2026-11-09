from django.contrib import admin

from .models import Case, CaseEvent, CaseLink


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Case)
class CaseAdmin(ReadOnlyAdmin):
    list_display = ("case_id", "title", "status", "priority", "assigned_to", "updated_at")
    list_filter = ("status", "priority")
    search_fields = ("case_id", "title")


@admin.register(CaseLink)
class CaseLinkAdmin(ReadOnlyAdmin):
    list_display = ("case", "kind", "object_ref", "linked_at", "removed_at")


@admin.register(CaseEvent)
class CaseEventAdmin(ReadOnlyAdmin):
    list_display = ("case", "kind", "actor_name", "created_at")
