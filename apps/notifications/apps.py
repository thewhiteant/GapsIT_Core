from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.notifications"
    verbose_name = "Notifications"

    def ready(self):
        # Registers the signal handlers that send automatic emails
        # (welcome + verify on signup, password-changed, role-changed).
        from . import signals  # noqa: F401
