"""
Shared detection logic for the Cyber Security Report Card / Alert System.

Kept as plain functions (no view/request coupling beyond what's passed in)
so both the middleware and the auth signal receiver can reuse them.
"""
import ipaddress
import re
from datetime import timedelta

import requests
from django.core.cache import cache
from django.utils import timezone

from .models import SecurityEvent

# ---------------------------------------------------------------------
# Attack signatures. These are intentionally coarse "does this look
# suspicious" pattern checks for logging/reporting -- not a WAF, and not
# a claim that a match is definitely malicious (a security researcher's
# own testing, or a legitimate value that happens to contain a quote,
# can also match). Everything caught here just becomes one row an admin
# can review and dismiss as a false positive if needed.
# ---------------------------------------------------------------------

SQLI_PATTERN = re.compile(
    r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bdrop\s+table\b|\bxp_cmdshell\b|"
    r"--\s*$|;\s*--|\bselect\b.+\bfrom\b.+\binformation_schema\b|'\s*or\s*'1'\s*=\s*'1)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(
    r"(<\s*script\b|javascript\s*:|on(error|load|mouseover|click)\s*=|<\s*img[^>]+onerror|"
    r"document\.cookie|<\s*svg[^>]+onload)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|\\windows\\win\.ini)", re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(
    r"(;\s*(cat|ls|whoami|id|uname)\b|\|\s*(cat|ls|whoami|nc)\b|`.*`|\$\(.*\)|&&\s*curl\b|&&\s*wget\b)",
    re.IGNORECASE,
)

# Substrings of User-Agent headers commonly sent by scanners/exploit tools.
SUSPICIOUS_AGENT_SUBSTRINGS = [
    "sqlmap", "nikto", "nmap", "nessus", "acunetix", "netsparker", "fimap",
    "havij", "w3af", "dirbuster", "gobuster", "wpscan", "masscan", "zgrab",
    "metasploit", "burpsuite", "python-requests",  # noisy but frequently used by scripted probes
]

# Paths that don't exist in this project and are near-universally only ever
# requested by automated scanners looking for common misconfigurations.
SENSITIVE_PATH_PATTERNS = [
    "/.env", "/.git/", "/wp-admin", "/wp-login", "/phpmyadmin", "/.aws/",
    "/config.php", "/.ssh/", "/xmlrpc.php", "/vendor/phpunit", "/.docker",
    "/server-status", "/actuator", "/debug/default/view",
]

# How many failed logins from the same source (IP, or username if IP is
# unknown) within this window count as brute-forcing rather than one-off
# typos.
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_CRITICAL_THRESHOLD = 15


def get_client_ip(request) -> str | None:
    """
    Best-effort client IP, aware that this deployment sits behind a
    reverse proxy (see SECURE_PROXY_SSL_HEADER / USE_X_FORWARDED_HOST in
    settings.py) -- so X-Forwarded-For's first entry is preferred when
    present.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def scan_text_for_signatures(text: str):
    """Return (event_type, matched_snippet) for the first signature that matches, or (None, None)."""
    if not text:
        return None, None
    for pattern, event_type in (
        (SQLI_PATTERN, SecurityEvent.TYPE_SQL_INJECTION),
        (XSS_PATTERN, SecurityEvent.TYPE_XSS),
        (COMMAND_INJECTION_PATTERN, SecurityEvent.TYPE_COMMAND_INJECTION),
        (PATH_TRAVERSAL_PATTERN, SecurityEvent.TYPE_PATH_TRAVERSAL),
    ):
        match = pattern.search(text)
        if match:
            return event_type, match.group(0)[:200]
    return None, None


def is_suspicious_agent(user_agent: str) -> str | None:
    if not user_agent:
        return None
    ua_lower = user_agent.lower()
    for needle in SUSPICIOUS_AGENT_SUBSTRINGS:
        if needle in ua_lower:
            return needle
    return None


def is_sensitive_path_probe(path: str) -> str | None:
    path_lower = path.lower()
    for needle in SENSITIVE_PATH_PATTERNS:
        if needle in path_lower:
            return needle
    return None


# ---------------------------------------------------------------------
# IP geolocation -- purely cosmetic for the report card ("where is this
# attacking IP coming from"). Never used for any security decision
# (blocking, scoring, etc), so a slow/missing/wrong answer here is
# harmless -- it just shows "Unknown" on the report card.
# ---------------------------------------------------------------------

# ip-api.com's free tier: no signup, HTTP only, ~45 requests/minute. Fine
# for this use case because results are cached hard below. Swap this for
# a paid provider (ipinfo.io, MaxMind, etc.) if you outgrow the free tier.
GEOLOCATION_API_URL = "http://ip-api.com/json/{ip}"
GEOLOCATION_FIELDS = "status,country,countryCode,regionName,city,isp,query"
GEOLOCATION_TIMEOUT_SECONDS = 3
GEOLOCATION_CACHE_TIMEOUT = 60 * 60 * 24  # 24h -- an attacker's IP location doesn't change minute to minute.

UNKNOWN_LOCATION = {"label": "Unknown", "country": "", "city": "", "country_code": "", "isp": "", "flag": ""}
PRIVATE_LOCATION = {"label": "Private/local network", "country": "", "city": "", "country_code": "", "isp": "", "flag": ""}


def is_private_ip(ip: str) -> bool:
    """True for anything that isn't a real, publicly-routable address (LAN IPs, loopback, etc)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast


def _flag_emoji(country_code: str) -> str:
    """Turn 'US' into 🇺🇸 etc. Returns '' for anything that isn't a 2-letter code."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def get_ip_location(ip: str | None) -> dict:
    """
    Best-effort "where did this attack come from" lookup for a source IP,
    for display on the Cyber Security Report Card only. Results are
    cached per-IP for GEOLOCATION_CACHE_TIMEOUT so repeat sightings of
    the same attacking IP (very common -- that's the whole point of the
    report card) don't re-hit the geolocation API each time.

    Returns a dict with at least a "label" key safe to render directly,
    e.g. {"label": "Singapore, Singapore", "flag": "🇸🇬", ...}.
    """
    if not ip:
        return UNKNOWN_LOCATION

    if is_private_ip(ip):
        return PRIVATE_LOCATION

    cache_key = f"security:geoip:{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    result = UNKNOWN_LOCATION
    try:
        response = requests.get(
            GEOLOCATION_API_URL.format(ip=ip),
            params={"fields": GEOLOCATION_FIELDS},
            timeout=GEOLOCATION_TIMEOUT_SECONDS,
        )
        data = response.json()
        if data.get("status") == "success":
            country = data.get("country", "")
            city = data.get("city", "")
            region = data.get("regionName", "")
            country_code = data.get("countryCode", "")
            label_parts = [part for part in (city, region, country) if part]
            result = {
                "label": ", ".join(label_parts) if label_parts else "Unknown",
                "country": country,
                "city": city,
                "country_code": country_code,
                "isp": data.get("isp", ""),
                "flag": _flag_emoji(country_code),
            }
    except (requests.RequestException, ValueError, TypeError):
        # Slow/unreachable/rate-limited geolocation API should never break
        # the report card -- just fall back to "Unknown" for this IP.
        pass

    # Cache the miss too (as UNKNOWN_LOCATION) so a broken/rate-limited
    # API doesn't get hammered again for the same IP within the window.
    cache.set(cache_key, result, GEOLOCATION_CACHE_TIMEOUT)
    return result


SEVERITY_BY_TYPE = {
    SecurityEvent.TYPE_FAILED_LOGIN: SecurityEvent.SEVERITY_LOW,
    SecurityEvent.TYPE_BRUTE_FORCE: SecurityEvent.SEVERITY_HIGH,
    SecurityEvent.TYPE_SQL_INJECTION: SecurityEvent.SEVERITY_CRITICAL,
    SecurityEvent.TYPE_COMMAND_INJECTION: SecurityEvent.SEVERITY_CRITICAL,
    SecurityEvent.TYPE_XSS: SecurityEvent.SEVERITY_HIGH,
    SecurityEvent.TYPE_PATH_TRAVERSAL: SecurityEvent.SEVERITY_HIGH,
    SecurityEvent.TYPE_SUSPICIOUS_AGENT: SecurityEvent.SEVERITY_MEDIUM,
    SecurityEvent.TYPE_SENSITIVE_PATH_PROBE: SecurityEvent.SEVERITY_MEDIUM,
    SecurityEvent.TYPE_CSRF_FAILURE: SecurityEvent.SEVERITY_LOW,
    SecurityEvent.TYPE_UNAUTHORIZED_ACCESS: SecurityEvent.SEVERITY_LOW,
    SecurityEvent.TYPE_OTHER: SecurityEvent.SEVERITY_LOW,
}


def record_event(
    *,
    event_type: str,
    summary: str,
    request=None,
    source_ip: str | None = None,
    user=None,
    username_attempted: str = "",
    details: str = "",
    severity: str | None = None,
):
    """
    Create (or, for the deliberately de-duplicated types, update) one
    SecurityEvent row. Centralised here so the middleware and the
    login-failure signal don't duplicate the same "who/what/how bad" logic.
    """
    if request is not None:
        source_ip = source_ip or get_client_ip(request)
        path = request.path[:500]
        method = request.method
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]
    else:
        path = ""
        method = ""
        user_agent = ""

    severity = severity or SEVERITY_BY_TYPE.get(event_type, SecurityEvent.SEVERITY_LOW)

    # Repeat sightings of the *same* (type, source_ip, path) inside the
    # brute-force window get folded into one row with a rising
    # occurrence_count instead of flooding the report card with
    # thousands of near-identical entries for a single scan/attack.
    dedupe_since = timezone.now() - BRUTE_FORCE_WINDOW
    existing = (
        SecurityEvent.objects.filter(
            event_type=event_type,
            source_ip=source_ip,
            path=path,
            created_at__gte=dedupe_since,
        )
        .exclude(status=SecurityEvent.STATUS_RESOLVED)
        .order_by("-created_at")
        .first()
    )
    if existing and source_ip:
        existing.occurrence_count += 1
        existing.last_seen_at = timezone.now()
        # A single IP hammering the same endpoint repeatedly is itself
        # worse than any individual hit -- bump severity as it escalates.
        if existing.occurrence_count >= BRUTE_FORCE_CRITICAL_THRESHOLD:
            existing.severity = SecurityEvent.SEVERITY_CRITICAL
        elif existing.occurrence_count >= BRUTE_FORCE_THRESHOLD and existing.severity == SecurityEvent.SEVERITY_LOW:
            existing.severity = SecurityEvent.SEVERITY_MEDIUM
        existing.save(update_fields=["occurrence_count", "last_seen_at", "severity"])
        return existing

    return SecurityEvent.objects.create(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        user=user,
        username_attempted=username_attempted[:150],
        path=path,
        method=method,
        user_agent=user_agent,
        summary=summary[:255],
        details=details[:4000],
    )


def record_failed_login(*, request, username: str):
    """
    Called from signals.py on every django auth failure. Also detects
    brute-forcing: N failures from the same source inside the window get
    escalated into (or folded up into) a single BRUTE_FORCE event.
    """
    source_ip = get_client_ip(request) if request else None

    event = record_event(
        event_type=SecurityEvent.TYPE_FAILED_LOGIN,
        summary=f"Failed login attempt for '{username}'" if username else "Failed login attempt",
        request=request,
        username_attempted=username or "",
        details=f"source_ip={source_ip}",
    )

    since = timezone.now() - BRUTE_FORCE_WINDOW
    filters = {"event_type": SecurityEvent.TYPE_FAILED_LOGIN, "created_at__gte": since}
    if source_ip:
        filters["source_ip"] = source_ip
    else:
        filters["username_attempted"] = username or ""

    recent_failure_count = sum(
        e.occurrence_count for e in SecurityEvent.objects.filter(**filters)
    )

    if recent_failure_count >= BRUTE_FORCE_THRESHOLD:
        severity = (
            SecurityEvent.SEVERITY_CRITICAL
            if recent_failure_count >= BRUTE_FORCE_CRITICAL_THRESHOLD
            else SecurityEvent.SEVERITY_HIGH
        )
        record_event(
            event_type=SecurityEvent.TYPE_BRUTE_FORCE,
            summary=(
                f"Possible brute-force login attack: {recent_failure_count} failed attempts "
                f"in {int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} min"
                + (f" from {source_ip}" if source_ip else f" targeting '{username}'")
            ),
            request=request,
            source_ip=source_ip,
            username_attempted=username or "",
            details=f"failed_attempt_count={recent_failure_count}",
            severity=severity,
        )

    return event