from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db import transaction

from .models import Profile
from .roles import ROLE_CHOICES, ROLE_REVIEWER

User = get_user_model()


class EagleEyeAuthenticationForm(AuthenticationForm):
    """Login form with accessible, styled widgets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update(
            {"class": "ee-input", "autocomplete": "username", "autofocus": True,
             "placeholder": "operator id"}
        )
        self.fields["password"].widget.attrs.update(
            {"class": "ee-input", "autocomplete": "current-password",
             "placeholder": "passphrase"}
        )
        self.fields["username"].label = "Operator ID"
        self.fields["password"].label = "Passphrase"


class UserCreateForm(UserCreationForm):
    """Lets an administrator create a user and assign a role in one step."""

    role = forms.ChoiceField(choices=ROLE_CHOICES, initial=ROLE_REVIEWER)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css = "ee-select" if isinstance(field, forms.ChoiceField) else "ee-input"
            field.widget.attrs["class"] = css

    @transaction.atomic
    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit:
            Profile.objects.update_or_create(
                user=user, defaults={"role": self.cleaned_data["role"]}
            )
        return user


class RoleChangeForm(forms.Form):
    role = forms.ChoiceField(choices=ROLE_CHOICES)
