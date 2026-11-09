from django import forms


class EvidenceUploadForm(forms.Form):
    file = forms.FileField(label="Evidence file", widget=forms.ClearableFileInput(attrs={"class": "ee-input"}))
    case_reference = forms.RegexField(
        label="Case reference (optional)", max_length=100, required=False, regex=r"^[\w .\-/#]+$",
        error_messages={"invalid": "Use letters, numbers, spaces and . - / # only."},
        widget=forms.TextInput(attrs={"class": "ee-input", "placeholder": "e.g. CASE-2026-014"}))
    description = forms.CharField(
        label="Description (optional)", max_length=1000, required=False,
        widget=forms.Textarea(attrs={"class": "ee-input", "rows": 3, "placeholder": "Where did this come from? What is it?"}))
    authorization_confirmed = forms.BooleanField(
        label="I am authorized to examine this file and to store it in this system.",
        error_messages={"required": "You must confirm you are authorized to examine this file."})


class NoteForm(forms.Form):
    text = forms.CharField(
        label="Add a note", max_length=2000,
        widget=forms.Textarea(attrs={"class": "ee-input", "rows": 3, "placeholder": "Observation, action taken, reference..."}))
