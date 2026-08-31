from pathlib import Path
from datetime import timedelta
from decouple import config, Csv

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config("SECRET_KEY", default="django-insecure-change-this-in-production")
DEBUG = False

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="gapsit.bd,www.gapsit.bd", cast=Csv())

#security

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True


# cPanel/Apache terminates HTTPS and forwards plain HTTP to the Passenger
# app behind it. Without this, Django thinks every request is plain HTTP,
# so anything that treats http vs https as meaningful (redirects, secure
# cookies, CSRF origin checks) gets it wrong -- which is what produces an
# ERR_TOO_MANY_REDIRECTS loop against Apache's own force-HTTPS rule.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

CSRF_TRUSTED_ORIGINS = config(
    "CSRF_TRUSTED_ORIGINS",
    default="https://gapsit.bd,https://www.gapsit.bd",
    cast=Csv(),
)

FORCE_SCRIPT_NAME = "/core"
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "apps.employees",
    "apps.allowlist",
    "apps.activity",
    "apps.releases",
    "apps.notifications",
    "apps.security",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.security.middleware.SecurityMonitoringMiddleware",
]

STATICFILES_DIRS = [
    BASE_DIR / "static",
]

ROOT_URLCONF = "core.urls"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # Feeds the "beautiful" stats/chart cards on the admin
                # homepage only -- see apps/employees/context_processors.py.
                "apps.employees.context_processors.gapsit_admin_dashboard",
                "apps.notifications.context_processors.email_verification_status",
                "apps.security.context_processors.security_alerts_banner",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": config("DB_ENGINE", default="django.db.backends.sqlite3"),
        "NAME": config("DB_NAME", default=BASE_DIR / "db.sqlite3"),
        "USER": config("DB_USER", default=""),
        "PASSWORD": config("DB_PASSWORD", default=""),
        "HOST": config("DB_HOST", default=""),
        "PORT": config("DB_PORT", default=""),
        "OPTIONS": (
            {
                "charset": "utf8mb4",
                "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
            }
            if config("DB_ENGINE", default="django.db.backends.sqlite3") == "django.db.backends.mysql"
            else {}
        ),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/core/static/"
WHITENOISE_STATIC_PREFIX = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# REST Framework settings
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
}

# JWT settings
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
}

# CORS settings (adjust for production)
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = config(
    "CORS_ALLOWED_ORIGINS",
    default="https://gapsit.bd,https://www.gapsit.bd",
    cast=Csv(),
)

# Admin API Key for external services
ADMIN_API_KEY = config("ADMIN_API_KEY", default="change-this-secure-key")

# Browser-facing session auth pages (see apps/employees/urls.py)
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

# ----------------------------------------------------------------------
# GapsSight client downloads (see apps/releases/) -- one-time-use download
# links offered on the dashboard right after a normal user logs in.
# ----------------------------------------------------------------------

# Folder on the server holding the actual installer files. Not part of the
# git repo (they're large binaries) -- upload/rsync them here separately,
# using exactly the filenames below. Override with the env var if you'd
# rather keep them somewhere else on disk.
GAPSIGHT_RELEASES_DIR = config(
    "GAPSIGHT_RELEASES_DIR", default=str(BASE_DIR / "releases_files")
)

GAPSIGHT_RELEASES = {
    "windows": {"filename": "GapsSight_Windows_0.1.2.rar", "label": "Windows"},
    "linux": {"filename": "GapsSight_Linux_0.1.rar", "label": "Linux"},
}

# How long a generated download link stays valid before it expires (it's
# also invalidated immediately after its one use, whichever comes first).
GAPSIGHT_DOWNLOAD_TOKEN_MINUTES = config(
    "GAPSIGHT_DOWNLOAD_TOKEN_MINUTES", default=10, cast=int
)

# ----------------------------------------------------------------------
# Email (see apps/notifications/) -- powers email verification, password
# reset emails, automatic account notifications, and the admin broadcast
# page. Point these at your hosting's webmail/SMTP details via .env --
# see the "connecting webmail" notes left in .env.
# ----------------------------------------------------------------------
EMAIL_BACKEND = config(
    "EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_HOST = config("EMAIL_HOST", default="mail.gapsit.bd")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_USE_SSL = config("EMAIL_USE_SSL", default=False, cast=bool)
# Fail fast instead of hanging a request if the mail server is unreachable.
EMAIL_TIMEOUT = config("EMAIL_TIMEOUT", default=10, cast=int)
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default=EMAIL_HOST_USER or "no-reply@gapsit.bd")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# Used to build absolute links inside emails (verify-email, notices).
# Django's own password-reset email builds its link from the request
# instead, so this only matters for apps/notifications' own emails.

# Scheme + host ONLY -- do NOT include the "/core" FORCE_SCRIPT_NAME prefix
# here. reverse() (used when building the email-verification link) already
# adds that prefix automatically, so including it in SITE_BASE_URL too would
# produce a broken "/core/core/..." link.
SITE_BASE_URL = config("SITE_BASE_URL", default="https://gapsit.bd")

# How long a "forgot password" link stays valid, in seconds. Default: 3 days.
PASSWORD_RESET_TIMEOUT = config("PASSWORD_RESET_TIMEOUT", default=60 * 60 * 24 * 3, cast=int)