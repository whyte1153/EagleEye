from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.core.paginator import Paginator
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.audit.services import log_event

from . import throttle
from .forms import EagleEyeAuthenticationForm, RoleChangeForm, UserCreateForm
from .models import Profile
from .roles import ROLE_ADMIN, ROLE_CHOICES, ROLE_DESCRIPTIONS, role_required

User = get_user_model()


class EagleEyeLoginView(LoginView):
    template_name = "registration/login.html"
    authentication_form = EagleEyeAuthenticationForm
    redirect_authenticated_user = True

    def post(self, request, *args, **kwargs):
        username = request.POST.get("username", "")
        if throttle.is_locked(request, username):
            log_event(request, "auth.login_blocked", target=username[:150],
                      detail="Too many failed attempts; login temporarily blocked.")
            form = self.get_form()
            form.add_error(
                None, "Too many failed attempts. Please wait a few minutes and try again."
            )
            return self.render_to_response(self.get_context_data(form=form), status=429)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        throttle.register_failure(self.request, self.request.POST.get("username", ""))
        return super().form_invalid(form)

    def form_valid(self, form):
        throttle.reset(self.request, self.request.POST.get("username", ""))
        return super().form_valid(form)


@role_required(ROLE_ADMIN)
def user_list(request):
    """Administrator-only: list users, create users, and see role descriptions."""
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        if form.is_valid():
            user = form.save()
            log_event(request, "user.created", target=user.get_username(),
                      detail=f"role={form.cleaned_data['role']}")
            messages.success(request, f"User '{user.get_username()}' created.")
            return redirect("accounts:users")
    else:
        form = UserCreateForm()

    users = User.objects.select_related("profile").order_by("username")
    page = Paginator(users, 15).get_page(request.GET.get("page"))
    return render(request, "accounts/user_list.html", {
        "page": page,
        "form": form,
        "role_choices": ROLE_CHOICES,
        "role_descriptions": [(label, ROLE_DESCRIPTIONS[key]) for key, label in ROLE_CHOICES],
    })


@role_required(ROLE_ADMIN)
@require_POST
def change_role(request, user_id: int):
    target = get_object_or_404(User, pk=user_id)
    form = RoleChangeForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid role selected.")
        return redirect("accounts:users")
    if target.pk == request.user.pk:
        messages.error(request, "You cannot change your own role.")
        return redirect("accounts:users")
    if target.is_superuser:
        messages.error(request, "Superuser roles are managed from the command line.")
        return redirect("accounts:users")

    new_role = form.cleaned_data["role"]
    with transaction.atomic():
        profile, _ = Profile.objects.get_or_create(user=target)
        old_role = profile.role
        profile.role = new_role
        profile.save(update_fields=["role"])
        log_event(request, "user.role_changed", target=target.get_username(),
                  detail=f"{old_role} -> {new_role}")
    messages.success(request, f"Role for '{target.get_username()}' updated.")
    return redirect("accounts:users")
