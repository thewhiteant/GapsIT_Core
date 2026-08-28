from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from .views import (
    broadcast_view,
    notification_preferences_view,
    resend_verification_view,
    verify_email_view,
)

# Included under "accounts/" in core/urls.py, same as login/register/dashboard.
notifications_page_urlpatterns = [
    path("verify-email/<str:token>/", verify_email_view, name="verify_email"),
    path("verify-email/resend/", resend_verification_view, name="resend_verification"),
    path("notifications/", notification_preferences_view, name="notification_preferences"),
    path("notifications/send/", broadcast_view, name="admin_broadcast"),
]

# Django's built-in "forgot password" email flow. Views/templates are
# customised only for styling; the security logic (signed, time-limited,
# single-use tokens) is Django's own, unmodified.
#
# NOTE: these deliberately do NOT live under templates/registration/ --
# django.contrib.admin ships its own registration/password_reset_*
# templates, and since "django.contrib.admin" is listed before
# "apps.notifications" in INSTALLED_APPS, Django's template loader would
# silently use admin's plain-text versions instead of ours. Using our
# own "notifications/password_reset/" path sidesteps that collision
# entirely, regardless of app ordering.
password_reset_page_urlpatterns = [
    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="notifications/password_reset/form.html",
            email_template_name="notifications/password_reset/email.txt",
            html_email_template_name="notifications/password_reset/email.html",
            subject_template_name="notifications/password_reset/subject.txt",
            success_url=reverse_lazy("password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="notifications/password_reset/done.html"
        ),
        name="password_reset_done",
    ),
    path(
        "password-reset/confirm/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="notifications/password_reset/confirm.html",
            success_url=reverse_lazy("password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="notifications/password_reset/complete.html"
        ),
        name="password_reset_complete",
    ),
]
