from django.conf import settings
from django.db import models


class NotificationType(models.Model):
    """
    A category of email an account can receive, e.g. "Account & Security"
    or "Admin Notices". Admins manage these from /admin/ -- add a new one
    any time you want a new, independently-toggleable kind of email.

    - is_mandatory=True  -> users can't opt out (used for security emails
      like "your password changed" / email verification).
    - default_enabled    -> whether a user who hasn't visited the
      notification-settings page yet is opted in or out by default.
    """

    CATEGORY_CHOICES = [
        ("security", "Account & Security"),
        ("account", "Account Updates"),
        ("admin", "Admin Notices"),
        ("system", "System"),
    ]

    code = models.SlugField(
        max_length=50,
        unique=True,
        help_text="Stable identifier used in code, e.g. 'account_security'.",
    )
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True, default="")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default="system")
    is_mandatory = models.BooleanField(
        default=False,
        help_text="If checked, users cannot opt out of this notification (e.g. security alerts).",
    )
    default_enabled = models.BooleanField(
        default=True,
        help_text="Whether new accounts receive this by default until they change it.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Uncheck to stop sending this notification entirely without deleting it.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["category", "name"]

    def __str__(self):
        return self.name


class NotificationPreference(models.Model):
    """A single user's on/off choice for a single NotificationType."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_preferences"
    )
    notification_type = models.ForeignKey(
        NotificationType, on_delete=models.CASCADE, related_name="preferences"
    )
    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "notification_type")

    def __str__(self):
        return f"{self.user} -> {self.notification_type} ({'on' if self.enabled else 'off'})"


class EmailVerification(models.Model):
    """Tracks whether a user has clicked their email-verification link."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_verification"
    )
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    last_sent_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user} (verified={self.is_verified})"


class NotificationLog(models.Model):
    """
    Audit trail of every email the app has tried to send -- automatic
    ones (verification, welcome, password-changed, role-changed) and
    admin broadcasts alike. Visible read-only from /admin/.
    """

    STATUS_CHOICES = [
        ("sent", "Sent"),
        ("failed", "Failed"),
        ("skipped", "Skipped (recipient opted out)"),
    ]

    notification_type = models.ForeignKey(
        NotificationType, on_delete=models.SET_NULL, null=True, blank=True, related_name="logs"
    )
    recipient_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="notification_logs",
    )
    recipient_email = models.EmailField(blank=True, default="")
    subject = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="sent")
    error_message = models.TextField(blank=True, default="")
    sent_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="broadcasts_sent",
        help_text="Set only for admin-initiated broadcast notices.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.subject} -> {self.recipient_email} ({self.status})"
