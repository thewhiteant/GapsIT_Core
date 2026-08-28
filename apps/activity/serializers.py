from rest_framework import serializers

from .models import ActivitySession


class GateCheckInputSerializer(serializers.Serializer):
    """One row of the client's GateChecks table, camelCase to match the
    GapsSight desktop app's System.Text.Json output (see
    ActivitySyncService.cs on the client)."""

    timestamp = serializers.DateTimeField()
    mouseX = serializers.IntegerField(source="mouse_x")
    mouseY = serializers.IntegerField(source="mouse_y")
    mouseMoved = serializers.BooleanField(source="mouse_moved")
    keyPressed = serializers.BooleanField(source="key_pressed")
    processName = serializers.CharField(
        source="process_name", required=False, allow_blank=True, allow_null=True, default=""
    )
    windowTitle = serializers.CharField(
        source="window_title", required=False, allow_blank=True, allow_null=True, default=""
    )
    isAllowedApp = serializers.BooleanField(source="is_allowed_app")
    isPresent = serializers.BooleanField(source="is_present")
    timerRunning = serializers.BooleanField(source="timer_running")

    def validate_processName(self, value):
        return value or ""

    def validate_windowTitle(self, value):
        return value or ""


class StatusChangeInputSerializer(serializers.Serializer):
    """One row of the client's StatusChanges table."""

    timestamp = serializers.DateTimeField()
    status = serializers.CharField(max_length=30)
    reason = serializers.CharField(required=False, allow_blank=True, allow_null=True, default="")

    def validate_reason(self, value):
        return value or ""


class SessionInputSerializer(serializers.Serializer):
    """
    One finished GapsSight session plus its detail rows. Only *ended*
    sessions are accepted (endTime is required) -- the client's
    ActivitySyncService only ever offers sessions where EndTime is set, so
    a session mid-run never gets partially synced and re-synced with
    different totals.
    """

    clientSessionId = serializers.IntegerField(source="client_session_id")
    username = serializers.CharField(max_length=150)
    startTime = serializers.DateTimeField(source="start_time")
    endTime = serializers.DateTimeField(source="end_time")
    totalActiveSeconds = serializers.IntegerField(source="total_active_seconds", min_value=0)
    totalAfkSeconds = serializers.IntegerField(source="total_afk_seconds", min_value=0)
    totalBlockedSeconds = serializers.IntegerField(source="total_blocked_seconds", min_value=0)
    gateChecks = GateCheckInputSerializer(many=True, source="gate_checks", required=False, default=list)
    statusChanges = StatusChangeInputSerializer(
        many=True, source="status_changes", required=False, default=list
    )


class ActivitySyncRequestSerializer(serializers.Serializer):
    """POST body for /api/activity/sync/: { "sessions": [ ... ] }"""

    sessions = SessionInputSerializer(many=True)


class ActivitySessionSummarySerializer(serializers.ModelSerializer):
    """Read-only summary, used for admin-facing listing if/when needed."""

    class Meta:
        model = ActivitySession
        fields = [
            "id",
            "client_session_id",
            "username",
            "start_time",
            "end_time",
            "total_active_seconds",
            "total_afk_seconds",
            "total_blocked_seconds",
            "synced_at",
        ]
