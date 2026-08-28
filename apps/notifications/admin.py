from django.contrib import admin

from .models import EmailVerification, NotificationLog, NotificationPreference, NotificationType


@admin.register(NotificationType)
class NotificationTypeAdmin(admin.ModelAdmin):
    """
    Add a new row here to create a brand-new, independently toggleable
    kind of notification -- give it a unique `code` and reference that
    code from send_notification() wherever you want to trigger it.
    """

    list_display = ["name", "code", "category", "is_mandatory", "default_enabled", "is_active"]
    list_filter = ["category", "is_mandatory", "default_enabled", "is_active"]
    search_fields = ["name", "code"]


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ["user", "notification_type", "enabled", "updated_at"]
    list_filter = ["notification_type", "enabled"]
    search_fields = ["user__username", "user__email"]


@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ["user", "is_verified", "verified_at", "last_sent_at"]
    list_filter = ["is_verified"]
    search_fields = ["user__username", "user__email"]


@admin.register(NotificationLog)
class NotificationLogAdmin(admin.ModelAdmin):
    """Read-only audit trail -- every email attempt, automatic or broadcast."""

    list_display = ["created_at", "subject", "recipient_email", "notification_type", "status", "sent_by"]
    list_filter = ["status", "notification_type"]
    search_fields = ["subject", "recipient_email"]
    readonly_fields = [f.name for f in NotificationLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
