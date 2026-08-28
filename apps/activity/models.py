from django.conf import settings
from django.db import models


class ActivitySession(models.Model):
    """
    Server-side durable copy of one GapsSight local session (see the
    desktop app's ActivityDatabase.Sessions table).

    The desktop app only ever keeps a rolling window of recent detail data
    in its local SQLite file (GateChecks/StatusChanges older than the
    configured retention period get pruned there once they're confirmed
    synced -- see ActivitySyncService/PruneOldPerformanceData on the
    client). This table -- plus ActivityGateCheck/ActivityStatusChange
    below -- is the permanent backup those local rows are pruned against.

    `client_session_id` is the local SQLite Sessions.Id from the machine
    that reported it. That id is only unique per-machine, not globally, so
    the real identity of a session server-side is the
    (owner, client_session_id) pair -- see the unique_together below. This
    makes POSTing the same already-synced session again a safe no-op
    instead of a duplicate (the client retries whenever a sync attempt
    fails partway through, e.g. the connection drops after some sessions
    were saved but before the response came back).
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="activity_sessions",
        help_text="The authenticated employee/admin whose desktop app reported this session.",
    )
    client_session_id = models.BigIntegerField(
        help_text="Local SQLite Sessions.Id on the reporting machine (unique per-device only)."
    )
    username = models.CharField(
        max_length=150,
        help_text="Username shown in the GapsSight session at the time it ran.",
    )

    start_time = models.DateTimeField()
    end_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Null sessions are never synced -- see build_sync_payload/the sync view, "
        "which only accept sessions the client has already ended.",
    )
    total_active_seconds = models.PositiveIntegerField(default=0)
    total_afk_seconds = models.PositiveIntegerField(default=0)
    total_blocked_seconds = models.PositiveIntegerField(default=0)

    synced_at = models.DateTimeField(auto_now_add=True)

    is_manual_entry = models.BooleanField(
        default=False,
        help_text="True if this session was hand-entered by an admin in the "
        "admin panel instead of synced automatically from the GapsSight "
        "desktop app.",
    )
    entered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activity_sessions_entered",
        help_text="Admin who manually created this session. Blank for "
        "sessions that arrived automatically via the sync API.",
    )

    class Meta:
        ordering = ["-start_time"]
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "client_session_id"],
                name="unique_activitysession_owner_client_id",
            )
        ]
        indexes = [
            models.Index(fields=["owner", "start_time"]),
        ]

    def __str__(self):
        return f"{self.username} session #{self.client_session_id} ({self.start_time:%Y-%m-%d %H:%M})"


class ActivityGateCheck(models.Model):
    """One 5-second P/M/K check, mirroring the local GateChecks table."""

    session = models.ForeignKey(
        ActivitySession, on_delete=models.CASCADE, related_name="gate_checks"
    )
    timestamp = models.DateTimeField()
    mouse_x = models.IntegerField(default=0)
    mouse_y = models.IntegerField(default=0)
    mouse_moved = models.BooleanField(default=False)
    key_pressed = models.BooleanField(default=False)
    process_name = models.CharField(max_length=255, blank=True, default="")
    window_title = models.CharField(max_length=500, blank=True, default="")
    is_allowed_app = models.BooleanField(default=False)
    is_present = models.BooleanField(default=False)
    timer_running = models.BooleanField(default=False)

    class Meta:
        ordering = ["timestamp"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
        ]


class ActivityStatusChange(models.Model):
    """One RUNNING/AFK/BLOCKED/PAUSED transition, mirroring StatusChanges."""

    session = models.ForeignKey(
        ActivitySession, on_delete=models.CASCADE, related_name="status_changes"
    )
    timestamp = models.DateTimeField()
    status = models.CharField(max_length=30)
    reason = models.CharField(max_length=500, blank=True, default="")

    class Meta:
        ordering = ["timestamp"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
        ]
