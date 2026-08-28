from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from apps.employees.views import CustomTokenObtainPairView
from apps.employees.urls import auth_page_urlpatterns
from apps.allowlist.urls import allowlist_page_urlpatterns
from apps.releases.urls import release_page_urlpatterns
from apps.notifications.urls import (
    notifications_page_urlpatterns,
    password_reset_page_urlpatterns,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    # JWT API endpoints (used by the GapsSight desktop app, Postman, etc.)
    path(
        "api/auth/login/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"
    ),
    path("api/auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Employee CRUD API endpoints
    path("api/", include("apps.employees.urls")),
    # Allowed-apps (GapsSight on-task allow-list) CRUD + sync API endpoints
    path("api/", include("apps.allowlist.urls")),
    # Session/gate-check/status-change backup sync API endpoints
    path("api/", include("apps.activity.urls")),
    # Browser-facing login / register / dashboard pages
    path("accounts/", include(auth_page_urlpatterns)),
    # Browser-facing admin page for managing the allow-list
    path("accounts/", include(allowlist_page_urlpatterns)),
    # GapsSight client download links -- only reachable once logged in,
    # right after /accounts/login/ (see apps/releases/).
    path("accounts/", include(release_page_urlpatterns)),
    # Email verification, per-user notification settings, and the admin
    # "send a notice" broadcast page (see apps/notifications/).
    path("accounts/", include(notifications_page_urlpatterns)),
    # Django's built-in "forgot password" email flow (see apps/notifications/).
    path("accounts/", include(password_reset_page_urlpatterns)),
]
