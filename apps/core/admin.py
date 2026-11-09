from django.contrib import admin

from .models import Module


@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ("name", "phase", "status", "order")
    list_filter = ("status", "phase")
