from django.urls import path

from . import views

app_name = "forensics"

urlpatterns = [
    path("", views.home, name="home"),
    path("vault/", views.vault, name="vault"),
    path("vault/verify-all/", views.verify_all, name="verify_all"),
    path("vault/export/inventory.<str:fmt>", views.export_inventory, name="export_inventory"),
    path("vault/export/integrity.<str:fmt>", views.integrity_report, name="integrity_report"),
    path("vault/<str:eid>/", views.detail, name="detail"),
    path("vault/<str:eid>/verify/", views.verify, name="verify"),
    path("vault/<str:eid>/reanalyze/", views.reanalyze_view, name="reanalyze"),
    path("vault/<str:eid>/note/", views.add_note_view, name="note"),
    path("vault/<str:eid>/download/", views.download, name="download"),
    path("vault/<str:eid>/report.<str:fmt>", views.item_report, name="item_report"),
]
