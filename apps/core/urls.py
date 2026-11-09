from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("modules/<slug:slug>/", views.module_detail, name="module_detail"),
    path("settings/", views.settings_view, name="settings"),
]
