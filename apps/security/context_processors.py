"""
Feeds the red "🚨 unresolved security alerts" banner on the admin
homepage. Mirrors apps.employees.context_processors.gapsit_admin_dashboard:
only does anything on /admin/ itself, so it can't affect any other page.
"""


def security_alerts_banner(request):
    match = getattr(request, "resolver_match", None)
    if not match or match.view_name != "admin:index":
        return {}

    try:
        from .models import SecurityEvent

        unresolved = SecurityEvent.objects.filter(
            status__in=[SecurityEvent.STATUS_NEW, SecurityEvent.STATUS_ACKNOWLEDGED],
            severity__in=[SecurityEvent.SEVERITY_HIGH, SecurityEvent.SEVERITY_CRITICAL],
        )
        critical_count = unresolved.filter(severity=SecurityEvent.SEVERITY_CRITICAL).count()
        high_count = unresolved.filter(severity=SecurityEvent.SEVERITY_HIGH).count()
        total = critical_count + high_count
        if total == 0:
            return {}

        return {
            "security_alert_banner": {
                "total": total,
                "critical_count": critical_count,
                "high_count": high_count,
                "latest": unresolved.order_by("-last_seen_at")[:5],
            }
        }
    except Exception:
        # Never let a broken alert query take down the whole admin homepage.
        return {}
