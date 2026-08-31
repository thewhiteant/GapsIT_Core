from django.apps import AppConfig


class SecurityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.security"
    verbose_name = "🛡️ Cyber Security"

    def ready(self):
        # Hooks the failed-login / brute-force detector onto Django's auth
        # signal. Importing here (not at module load time) avoids the
        # classic "models aren't ready yet" AppRegistryNotReady error.
        from . import signals  # noqa: F401
