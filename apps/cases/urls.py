from django.urls import path

from . import views

app_name = "cases"

urlpatterns = [
    path("", views.case_list, name="list"),
    path("new/", views.case_new, name="new"),
    path("<str:cid>/", views.detail, name="detail"),
    path("<str:cid>/edit/", views.edit, name="edit"),
    path("<str:cid>/status/", views.change_status, name="status"),
    path("<str:cid>/note/", views.add_note_view, name="note"),
    path("<str:cid>/link/", views.link_item, name="link"),
    path("<str:cid>/unlink/<int:link_id>/", views.unlink_item, name="unlink"),
    path("<str:cid>/report.<str:fmt>", views.case_report, name="report"),
]
