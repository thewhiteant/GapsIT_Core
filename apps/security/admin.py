from django.contrib import admin
from django.urls import path
from django.utils import timezone
from django.utils.html import format_html

from .models import SecurityEvent

SEVERITY_COLORS = {
    SecurityEvent.SEVERITY_LOW: ("#14432e", "#7fe3ab"),
    SecurityEvent.SEVERITY_MEDIUM: ("#4a3c12", "#f5d97a"),
    SecurityEvent.SEVERITY_HIGH: ("#4a2f12", "#ffb26b"),
    SecurityEvent.SEVERITY_CRITICAL: ("#4a1616", "#ff9b9b"),
}


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = [
        "severity_badge",
        "event_type",
        "summary",
        "source_ip",
        "occurrence_count",
        "status",
        "last_seen_at",
    ]
    list_filter = ["severity", "event_type", "status", "created_at"]
    search_fields = ["summary", "source_ip", "username_attempted", "path", "details"]
    readonly_fields = [
        "event_type",
        "severity",
        "source_ip",
        "ip_location",
        "user",
        "username_attempted",
        "path",
        "method",
        "user_agent",
        "summary",
        "details",
        "occurrence_count",
        "created_at",
        "last_seen_at",
    ]
    date_hierarchy = "created_at"
    actions = ["mark_acknowledged", "mark_resolved", "mark_false_positive"]

    fieldsets = (
        ("What happened", {"fields": ("event_type", "severity", "summary", "details")}),
        (
            "Who / where",
            {"fields": ("source_ip", "ip_location", "user", "username_attempted", "path", "method", "user_agent")},
        ),
        ("Review", {"fields": ("status", "acknowledged_by", "acknowledged_at")}),
        ("Timing", {"fields": ("occurrence_count", "created_at", "last_seen_at")}),
    )

    def ip_location(self, obj):
        # Kept off list_display deliberately -- geolocation is cached per
        # IP (see utils.get_ip_location) but a changelist page can show
        # dozens of distinct IPs at once, and a cold cache would mean
        # dozens of live lookups on one page load. The detail page only
        # ever looks up one IP, so it's cheap here.
        from .utils import get_ip_location

        if not obj.source_ip:
            return "—"
        location = get_ip_location(obj.source_ip)
        return f"{location['flag']} {location['label']}".strip()

    ip_location.short_description = "Attack location"

    def has_add_permission(self, request):
        # Rows are only ever created automatically by the middleware/signal.
        return False

    def severity_badge(self, obj):
        bg, fg = SEVERITY_COLORS.get(obj.severity, ("#333", "#ccc"))
        return format_html(
            '<span style="background:{}; color:{}; padding:2px 9px; border-radius:999px; '
            'font-size:11px; font-weight:700;">{}</span>',
            bg, fg, obj.get_severity_display(),
        )

    severity_badge.short_description = "Severity"
    severity_badge.admin_order_field = "severity"

    def _bulk_update_status(self, request, queryset, new_status, message):
        updated = queryset.update(
            status=new_status,
            acknowledged_by=request.user,
            acknowledged_at=timezone.now(),
        )
        self.message_user(request, f"{updated} event(s) marked {message}.")

    def mark_acknowledged(self, request, queryset):
        self._bulk_update_status(request, queryset, SecurityEvent.STATUS_ACKNOWLEDGED, "acknowledged")

    mark_acknowledged.short_description = "Acknowledge selected events"

    def mark_resolved(self, request, queryset):
        self._bulk_update_status(request, queryset, SecurityEvent.STATUS_RESOLVED, "resolved")

    mark_resolved.short_description = "Resolve selected events"

    def mark_false_positive(self, request, queryset):
        self._bulk_update_status(request, queryset, SecurityEvent.STATUS_FALSE_POSITIVE, "as false positives")

    mark_false_positive.short_description = "Mark selected events as false positives"


# ----------------------------------------------------------------------
# Cyber Security Report Card -- a full report page, not backed by its own
# ModelAdmin changelist, wired in as an extra admin URL. Mirrors the
# pattern already used by apps/employees/admin.py for the CEO Work Table,
# so if apps.employees is loaded first, this chains on top of it rather
# than clobbering it (each app's monkeypatch calls the previous one).
# ----------------------------------------------------------------------
_original_get_urls = admin.site.get_urls


def _get_urls_with_security_report_card():
    from apps.security.report_card import report_card_view

    custom = [
        path(
            "security-report-card/",
            admin.site.admin_view(report_card_view),
            name="security-report-card",
        ),
    ]
    return custom + _original_get_urls()


admin.site.get_urls = _get_urls_with_security_report_card