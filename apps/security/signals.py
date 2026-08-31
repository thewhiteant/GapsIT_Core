from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

from .utils import record_failed_login


@receiver(user_login_failed)
def on_user_login_failed(sender, credentials, request=None, **kwargs):
    """
    django.contrib.auth.authenticate() sends this signal whenever no
    backend accepts the given credentials -- which covers the HTML login
    page at /accounts/login/ (apps.employees.views.EmployeeLoginView,
    via AuthenticationForm) *and* the JWT login at /api/auth/login/
    (CustomTokenObtainPairView, which calls authenticate() directly).
    One receiver here is enough for both entry points.
    """
    username = credentials.get("username", "") if credentials else ""
    record_failed_login(request=request, username=username)
