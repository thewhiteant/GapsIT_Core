from django.conf import settings
from django.db import models


class SecurityEvent(models.Model):
    """
    One recorded attack / suspicious event against the site.

    Rows are created automatically by two things (see signals.py and
    middleware.py):

      1. ``user_login_failed`` -- fired by Django's own ``authenticate()``,
         so it covers *both* the HTML login page (/accounts/login/) and the
         JWT API login used by the GapsSight desktop app (/api/auth/login/).
         Repeated failures from the same IP/username inside a short window
         are escalated into a single BRUTE_FORCE event instead of one row
         per attempt.

      2. ``SecurityMonitoringMiddleware`` -- inspects every incoming
         request's path, query string and POST body for known attack
         signatures (SQL injection, XSS, path traversal, command
         injection), known scanner/exploit-tool user agents, and probing
         of sensitive paths that don't exist on this site.

    Nothing here ever blocks a request -- this is detection/reporting
    only, kept deliberately separate from anything that could itself
    introduce a new vulnerability (no dynamic eval of the payload, no
    reflecting attacker input back unescaped, etc).
    """

    TYPE_FAILED_LOGIN = "failed_login"
    TYPE_BRUTE_FORCE = "brute_force"
    TYPE_SQL_INJECTION = "sql_injection"
    TYPE_XSS = "xss"
    TYPE_PATH_TRAVERSAL = "path_traversal"
    TYPE_COMMAND_INJECTION = "command_injection"
    TYPE_SUSPICIOUS_AGENT = "suspicious_agent"
    TYPE_SENSITIVE_PATH_PROBE = "sensitive_path_probe"
    TYPE_CSRF_FAILURE = "csrf_failure"
    TYPE_UNAUTHORIZED_ACCESS = "unauthorized_access"
    TYPE_OTHER = "other"

    TYPE_CHOICES = [
        (TYPE_FAILED_LOGIN, "Failed login"),
        (TYPE_BRUTE_FORCE, "Brute-force login attempt"),
        (TYPE_SQL_INJECTION, "SQL injection attempt"),
        (TYPE_XSS, "Cross-site scripting (XSS) attempt"),
        (TYPE_PATH_TRAVERSAL, "Path traversal attempt"),
        (TYPE_COMMAND_INJECTION, "Command injection attempt"),
        (TYPE_SUSPICIOUS_AGENT, "Known scanner / exploit-tool user agent"),
        (TYPE_SENSITIVE_PATH_PROBE, "Sensitive path probing (404 scanning)"),
        (TYPE_CSRF_FAILURE, "CSRF validation failure"),
        (TYPE_UNAUTHORIZED_ACCESS, "Unauthorized access attempt"),
        (TYPE_OTHER, "Other"),
    ]

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]
    # Used for sorting-by-severity and for the report card's counts.
    SEVERITY_ORDER = {SEVERITY_LOW: 0, SEVERITY_MEDIUM: 1, SEVERITY_HIGH: 2, SEVERITY_CRITICAL: 3}

    STATUS_NEW = "new"
    STATUS_ACKNOWLEDGED = "acknowledged"
    STATUS_RESOLVED = "resolved"
    STATUS_FALSE_POSITIVE = "false_positive"

    STATUS_CHOICES = [
        (STATUS_NEW, "New"),
        (STATUS_ACKNOWLEDGED, "Acknowledged"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_FALSE_POSITIVE, "False positive"),
    ]

    event_type = models.CharField(max_length=30, choices=TYPE_CHOICES, default=TYPE_OTHER)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default=SEVERITY_LOW)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_NEW)

    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
        help_text="Set only if the request was tied to a known account (e.g. a failed login for a real username).",
    )
    username_attempted = models.CharField(
        max_length=150,
        blank=True,
        default="",
        help_text="Raw username submitted, even if it doesn't match any account.",
    )

    path = models.CharField(max_length=500, blank=True, default="")
    method = models.CharField(max_length=10, blank=True, default="")
    user_agent = models.CharField(max_length=500, blank=True, default="")

    summary = models.CharField(
        max_length=255,
        help_text="One-line human-readable description shown in lists and the report card.",
    )
    details = models.TextField(
        blank=True,
        default="",
        help_text="Extra context -- the matched pattern, request params (sanitised), attempt count, etc.",
    )
    occurrence_count = models.PositiveIntegerField(
        default=1,
        help_text="How many raw attempts this row represents (used by brute-force de-duplication).",
    )

    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events_acknowledged",
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen_at"]
        verbose_name = "Security event"
        verbose_name_plural = "Security events"
        indexes = [
            models.Index(fields=["event_type", "created_at"]),
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["source_ip", "created_at"]),
        ]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.get_event_type_display()} - {self.summary}"

    @property
    def is_unresolved(self):
        return self.status in (self.STATUS_NEW, self.STATUS_ACKNOWLEDGED)

    @property
    def is_alertworthy(self):
        """High/critical + still open == worth surfacing on the in-app alert banner."""
        return self.severity in (self.SEVERITY_HIGH, self.SEVERITY_CRITICAL) and self.is_unresolved
