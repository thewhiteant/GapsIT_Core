from django import forms
from django.contrib.auth.models import User

AUDIENCE_CHOICES = [
    ("all", "Everyone (all accounts)"),
    ("role_admin", "Admins only"),
    ("role_employee", "Employees only"),
    ("role_user", "Regular users only"),
    ("specific", "Specific people"),
]


class BroadcastForm(forms.Form):
    """Used on /accounts/notifications/send/ -- the admin 'send a notice' page."""

    audience = forms.ChoiceField(
        choices=AUDIENCE_CHOICES,
        widget=forms.Select(attrs={"class": "form-input"}),
    )
    specific_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True).order_by("username"),
        required=False,
        widget=forms.SelectMultiple(attrs={"class": "form-input", "size": 8}),
        label="Specific people (only used when 'Specific people' is selected above)",
    )
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={"class": "form-input", "placeholder": "Subject"}),
    )
    message = forms.CharField(
        widget=forms.Textarea(
            attrs={"class": "form-input", "rows": 8, "placeholder": "Write your notice or update here..."}
        )
    )
    force_send = forms.BooleanField(
        required=False,
        label="Send even to people who turned admin notices off (mark as urgent)",
    )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("audience") == "specific" and not cleaned.get("specific_users"):
            raise forms.ValidationError("Choose at least one person for a specific-audience notice.")
        return cleaned
