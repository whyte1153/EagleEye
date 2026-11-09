from django.contrib.auth.views import LogoutView
from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.EagleEyeLoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),  # POST only (Django 5+)
    path("users/", views.user_list, name="users"),
    path("users/<int:user_id>/role/", views.change_role, name="change_role"),
]
