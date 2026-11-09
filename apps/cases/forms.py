from django import forms
from django.contrib.auth import get_user_model

from .models import Case

User = get_user_model()
_input = {"class": "ee-input"}
_select = {"class": "ee-select"}


class CaseForm(forms.Form):
    title = forms.CharField(label="Title", max_length=200, widget=forms.TextInput(attrs={**_input, "placeholder": "Short, specific summary"}))
    description = forms.CharField(label="Description", max_length=5000, required=False,
                                 widget=forms.Textarea(attrs={**_input, "rows": 4, "placeholder": "What happened or what is being assessed?"}))
    priority = forms.ChoiceField(label="Priority", choices=Case.PRIORITY_CHOICES, initial=Case.MEDIUM, widget=forms.Select(attrs=_select))
    assigned_to = forms.ModelChoiceField(label="Assigned to", queryset=User.objects.none(), required=False, empty_label="Unassigned",
                                         widget=forms.Select(attrs=_select))

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.fields["assigned_to"].queryset = User.objects.filter(is_active=True).order_by("username")


class StatusForm(forms.Form):
    status = forms.ChoiceField(label="Status", choices=Case.STATUS_CHOICES, widget=forms.Select(attrs=_select))
    note = forms.CharField(label="Note (required to close or reopen)", max_length=2000, required=False,
                           widget=forms.Textarea(attrs={**_input, "rows": 2}))


class NoteForm(forms.Form):
    text = forms.CharField(label="Add a note", max_length=3000,
                           widget=forms.Textarea(attrs={**_input, "rows": 3, "placeholder": "Observation, decision, action taken..."}))


class LinkForm(forms.Form):
    kind = forms.ChoiceField(choices=[("scan", "Scan"), ("evidence", "Evidence"), ("network", "Network import")], widget=forms.HiddenInput)
    ref = forms.CharField(max_length=40)
