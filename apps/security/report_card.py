"""
The Cyber Security Report Card -- a full report page, not backed by its
own ModelAdmin changelist, wired in as an extra admin URL exactly the
way apps/employees/ceo_dashboard.py does for the CEO Work Table.
"""
import json
from datetime import timedelta

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from django.shortcuts import render
from django.utils import timezone

from .models import SecurityEvent
from .utils import get_ip_location

TREND_DAYS = 14


def _trend_data():
    """Attacks-per-day for the last TREND_DAYS days, for the line chart."""
    today = timezone.localdate()
    days = [today - timedelta(days=offset) for offset in range(TREND_DAYS - 1, -1, -1)]
    since = timezone.now() - timedelta(days=TREND_DAYS)

    counts_by_day = {day: 0 for day in days}
    for event in SecurityEvent.objects.filter(created_at__gte=since).only("created_at", "occurrence_count"):
        day = timezone.localtime(event.created_at).date()
        if day in counts_by_day:
            counts_by_day[day] += event.occurrence_count

    labels = [day.strftime("%b %d") for day in days]
    values = [counts_by_day[day] for day in days]
    return labels, values


@staff_member_required
def report_card_view(request):
    """/admin/security-report-card/ -- see apps/employees/ceo_dashboard.py for the identical wiring pattern."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    all_events = SecurityEvent.objects.all()

    summary = {
        "total_all_time": all_events.count(),
        "total_24h": all_events.filter(created_at__gte=last_24h).count(),
        "total_7d": all_events.filter(created_at__gte=last_7d).count(),
        "total_30d": all_events.filter(created_at__gte=last_30d).count(),
        "unresolved": all_events.filter(
            status__in=[SecurityEvent.STATUS_NEW, SecurityEvent.STATUS_ACKNOWLEDGED]
        ).count(),
        "critical_unresolved": all_events.filter(
            severity=SecurityEvent.SEVERITY_CRITICAL,
            status__in=[SecurityEvent.STATUS_NEW, SecurityEvent.STATUS_ACKNOWLEDGED],
        ).count(),
    }

    severity_breakdown = list(
        all_events.filter(created_at__gte=last_30d)
        .values("severity")
        .annotate(count=Count("id"))
        .order_by("severity")
    )
    severity_map = {row["severity"]: row["count"] for row in severity_breakdown}
    severity_display = [
        {"key": key, "label": label, "count": severity_map.get(key, 0)}
        for key, label in SecurityEvent.SEVERITY_CHOICES
    ]

    type_breakdown = list(
        all_events.filter(created_at__gte=last_30d)
        .values("event_type")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    type_labels_map = dict(SecurityEvent.TYPE_CHOICES)
    for row in type_breakdown:
        row["label"] = type_labels_map.get(row["event_type"], row["event_type"])

    top_ips = list(
        all_events.filter(created_at__gte=last_30d, source_ip__isnull=False)
        .values("source_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    # Cached per-IP (see utils.get_ip_location), so this stays cheap even
    # though it's a lookup per row -- repeat attacking IPs are the norm.
    for row in top_ips:
        row["location"] = get_ip_location(row["source_ip"])

    # SecurityEvent.severity is a plain CharField, so ordering by it
    # directly would sort alphabetically (critical, high, low, medium --
    # not what anyone wants). Pull the most recent unresolved rows and
    # re-sort them in Python by actual severity rank instead.
    recent_unresolved = sorted(
        all_events.filter(status__in=[SecurityEvent.STATUS_NEW, SecurityEvent.STATUS_ACKNOWLEDGED]).order_by(
            "-last_seen_at"
        )[:100],
        key=lambda e: (SecurityEvent.SEVERITY_ORDER.get(e.severity, 0), e.last_seen_at),
        reverse=True,
    )[:25]

    for event in recent_unresolved:
        event.location = get_ip_location(event.source_ip)

    trend_labels, trend_values = _trend_data()

    context = {
        "title": "Cyber Security Report Card",
        "site_title": "GapsIT Core Admin",
        "summary": summary,
        "severity_display": severity_display,
        "type_breakdown": type_breakdown,
        "top_ips": top_ips,
        "recent_unresolved": recent_unresolved,
        "trend_labels": json.dumps(trend_labels),
        "trend_values": json.dumps(trend_values),
        "severity_labels": json.dumps([row["label"] for row in severity_display]),
        "severity_values": json.dumps([row["count"] for row in severity_display]),
        "opts": SecurityEvent._meta,
    }
    return render(request, "admin/security/report_card.html", context)