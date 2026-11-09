from django.urls import path

from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.home, name="home"),
    path("history/", views.history, name="history"),
    path("history/compare/", views.compare, name="compare"),
    path("history/<int:pk>/", views.detail, name="detail"),
    path("history/<int:pk>/report/<str:fmt>/", views.download_report, name="report"),
]
