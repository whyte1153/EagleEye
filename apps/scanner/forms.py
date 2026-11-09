from django import forms

from .engine.ssrf import InvalidTarget, normalize_url


class ScanForm(forms.Form):
    url = forms.CharField(
        label="Target URL", max_length=2048,
        widget=forms.TextInput(attrs={"class": "ee-input", "placeholder": "https://www.example.com/", "autofocus": True,
                                      "autocomplete": "off", "spellcheck": "false"}),
        help_text="Bare host names default to https://.",
    )
    authorization_note = forms.CharField(
        label="Authorization reference (optional)", max_length=300, required=False,
        widget=forms.TextInput(attrs={"class": "ee-input", "placeholder": "ticket / engagement / owner name"}),
    )
    authorization_confirmed = forms.BooleanField(
        label="I own this target or have written permission to assess it.",
        error_messages={"required": "You must confirm you are authorized to scan this target."},
    )

    def clean_url(self):
        raw = self.cleaned_data["url"]
        try:
            normalize_url(raw)  # format / scheme checks only; policy + DNS checks happen when the scan runs
        except InvalidTarget as exc:
            raise forms.ValidationError(str(exc)) from None
        return raw.strip()
