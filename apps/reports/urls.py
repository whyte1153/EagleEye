from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("", views.home, name="home"),
    path("overview.<str:fmt>", views.overview, name="overview"),
    path("audit.<str:fmt>", views.audit_report, name="audit"),
]
