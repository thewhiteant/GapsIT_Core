from django import forms
from django.contrib import admin
from django.db.models import Sum, Count
from django.utils import timezone
from django.utils.html import format_html

from .models import ActivityGateCheck, ActivitySession, ActivityStatusChange


class ActivityGateCheckInline(admin.TabularInline):
    model = ActivityGateCheck
    extra = 0
    can_delete = False
    readonly_fields = [
        "timestamp",
        "mouse_x",
        "mouse_y",
        "mouse_moved",
        "key_pressed",
        "process_name",
        "window_title",
        "is_allowed_app",
        "is_present",
        "timer_running",
    ]
    max_num = 0  # backup data, view-only from admin -- never hand-add rows here


class ActivityStatusChangeInline(admin.TabularInline):
    model = ActivityStatusChange
    extra = 0
    can_delete = False
    readonly_fields = ["timestamp", "status", "reason"]
    max_num = 0


class ActivitySessionManualAddForm(forms.ModelForm):
    """
    Form used only when an admin hand-adds a session from the admin panel
    (see ActivitySessionAdmin.get_form). Deliberately excludes the
    machine-only fields (client_session_id, synced_at, is_manual_entry,
    entered_by) -- those are filled in automatically in save_model so an
    admin can't accidentally spoof a real machine-synced row or collide
    with a real client_session_id.
    """

    class Meta:
        model = ActivitySession
        fields = [
            "owner",
            "username",
            "start_time",
            "end_time",
            "total_active_seconds",
            "total_afk_seconds",
            "total_blocked_seconds",
        ]
        help_texts = {
            "end_time": "Required -- manual entries are logged as already-finished sessions, same as synced ones.",
        }

    def clean_end_time(self):
        end_time = self.cleaned_data.get("end_time")
        if not end_time:
            raise forms.ValidationError("End time is required for a manually logged session.")
        return end_time


@admin.register(ActivitySession)
class ActivitySessionAdmin(admin.ModelAdmin):
    change_list_template = "admin/activity/activitysession/change_list.html"

    list_display = [
        "username",
        "owner",
        "client_session_id",
        "start_time",
        "end_time",
        "active_fmt",
        "afk_fmt",
        "blocked_fmt",
        "productivity_badge",
        "source_badge",
        "synced_at",
    ]
    list_filter = ["is_manual_entry", "username", "owner"]
    search_fields = ["username", "owner__username", "client_session_id"]
    date_hierarchy = "start_time"
    readonly_fields = [
        "owner",
        "client_session_id",
        "username",
        "start_time",
        "end_time",
        "total_active_seconds",
        "total_afk_seconds",
        "total_blocked_seconds",
        "synced_at",
        "is_manual_entry",
        "entered_by",
    ]
    inlines = [ActivityStatusChangeInline, ActivityGateCheckInline]

    def has_add_permission(self, request):
        # Machine-synced sessions still only ever arrive via the sync API
        # (see ActivitySyncView) -- this just lets an admin ALSO hand-add a
        # session here (e.g. to backfill a day the desktop app was offline
        # for, or log time for someone without GapsSight installed). Every
        # such row is flagged is_manual_entry=True and attributed to the
        # admin who added it, so it's never confused with real agent data.
        return True

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            kwargs["form"] = ActivitySessionManualAddForm
        return super().get_form(request, obj, **kwargs)

    def get_fields(self, request, obj=None):
        if obj is None:
            return [
                "owner",
                "username",
                "start_time",
                "end_time",
                "total_active_seconds",
                "total_afk_seconds",
                "total_blocked_seconds",
            ]
        return super().get_fields(request, obj)

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            # Everything is editable on the add form -- see get_fields/
            # ActivitySessionManualAddForm for the actual field set.
            return []
        return self.readonly_fields

    def has_change_permission(self, request, obj=None):
        # Existing (synced or manual) sessions stay locked for editing --
        # every field is already listed in readonly_fields above, so the
        # change view is effectively view-only, same as before this change.
        return True

    def save_model(self, request, obj, form, change):
        if not change:
            obj.is_manual_entry = True
            obj.entered_by = request.user
            if not obj.username and obj.owner_id:
                obj.username = obj.owner.get_username()
            # client_session_id only has to be unique per (owner,
            # client_session_id) -- real GapsSight ids are always positive
            # local SQLite autoincrement values, so a descending run of
            # negative ids can never collide with a real synced session.
            lowest = (
                ActivitySession.objects.filter(owner=obj.owner, client_session_id__lt=0)
                .order_by("client_session_id")
                .first()
            )
            obj.client_session_id = (lowest.client_session_id - 1) if lowest else -1
        super().save_model(request, obj, form, change)

    @staticmethod
    def _fmt(total_seconds):
        total_seconds = int(total_seconds or 0)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes:02d}m"
        return f"{minutes}m"

    def active_fmt(self, obj):
        return self._fmt(obj.total_active_seconds)

    active_fmt.short_description = "Active"
    active_fmt.admin_order_field = "total_active_seconds"

    def afk_fmt(self, obj):
        return self._fmt(obj.total_afk_seconds)

    afk_fmt.short_description = "AFK"
    afk_fmt.admin_order_field = "total_afk_seconds"

    def blocked_fmt(self, obj):
        return self._fmt(obj.total_blocked_seconds)

    blocked_fmt.short_description = "Blocked"
    blocked_fmt.admin_order_field = "total_blocked_seconds"

    def productivity_badge(self, obj):
        total = obj.total_active_seconds + obj.total_afk_seconds + obj.total_blocked_seconds
        if not total:
            return format_html('<span style="color:#888;">no data</span>')
        pct = round(100 * obj.total_active_seconds / total, 1)
        color = "#2fae6b" if pct >= 70 else ("#c9a227" if pct >= 40 else "#c0392b")
        return format_html(
            '<span style="background:{}22;color:{};padding:2px 8px;border-radius:999px;'
            'font-size:11px;font-weight:700;">{}%</span>',
            color, color, pct,
        )

    productivity_badge.short_description = "Productivity"

    def source_badge(self, obj):
        if obj.is_manual_entry:
            who = obj.entered_by.get_username() if obj.entered_by_id else "admin"
            return format_html(
                '<span style="background:#7c5cff22;color:#7c5cff;padding:2px 8px;border-radius:999px;'
                'font-size:11px;font-weight:700;" title="Manually added by {}">MANUAL</span>',
                who,
            )
        return format_html('<span style="color:#888;">synced</span>')

    source_badge.short_description = "Source"
    source_badge.admin_order_field = "is_manual_entry"

    def changelist_view(self, request, extra_context=None):
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        agg = ActivitySession.objects.filter(start_time__gte=today_start).aggregate(
            active=Sum("total_active_seconds"),
            afk=Sum("total_afk_seconds"),
            blocked=Sum("total_blocked_seconds"),
            sessions=Count("id"),
            people=Count("owner_id", distinct=True),
        )
        extra_context = extra_context or {}
        extra_context["gap_activity_stats"] = {
            "active": self._fmt(agg["active"]),
            "afk": self._fmt(agg["afk"]),
            "blocked": self._fmt(agg["blocked"]),
            "sessions": agg["sessions"] or 0,
            "people": agg["people"] or 0,
        }
        return super().changelist_view(request, extra_context=extra_context)
