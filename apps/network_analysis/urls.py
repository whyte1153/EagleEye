from django.urls import path

from . import views

app_name = "network_analysis"

urlpatterns = [
    path("", views.home, name="home"),
    path("imports/", views.imports, name="imports"),
    path("imports/<str:iid>/", views.detail, name="detail"),
    path("imports/<str:iid>/export.<str:fmt>", views.export, name="export"),
]
