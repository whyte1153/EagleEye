from django import forms


class ImportForm(forms.Form):
    file = forms.FileField(label="Nmap XML or PCAP file", widget=forms.ClearableFileInput(attrs={"class": "ee-input"}))
    case_reference = forms.RegexField(
        label="Case reference (optional)", max_length=100, required=False, regex=r"^[\w .\-/#]+$",
        error_messages={"invalid": "Use letters, numbers, spaces and . - / # only."},
        widget=forms.TextInput(attrs={"class": "ee-input", "placeholder": "e.g. CASE-2026-014"}))
    description = forms.CharField(
        label="Description (optional)", max_length=1000, required=False,
        widget=forms.Textarea(attrs={"class": "ee-input", "rows": 3, "placeholder": "Which lab network? When was it captured?"}))
    authorization_confirmed = forms.BooleanField(
        label="This data comes from a network I am authorized to assess or monitor.",
        error_messages={"required": "You must confirm you are authorized to analyse this data."})
