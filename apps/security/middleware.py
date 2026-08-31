from .models import SecurityEvent
from .utils import (
    get_client_ip,
    is_sensitive_path_probe,
    is_suspicious_agent,
    record_event,
    scan_text_for_signatures,
)


class SecurityMonitoringMiddleware:
    """
    Passive attack detector for the Cyber Security Report Card.

    Deliberately detection-only: it never blocks, rewrites, or rejects a
    request (that's a separate, much higher-stakes decision left to a
    real WAF/firewall if you want one later). All it does is look at the
    request that's already about to be processed and, if something looks
    like an attack, drop a SecurityEvent row for the admin report card /
    alert banner to pick up.

    Runs late in MIDDLEWARE (after auth/session are set up) so ``request
    .user`` is available, and checks the *response* too so it can catch
    CSRF failures (403 from CsrfViewMiddleware) and probing that 404s.
    """

    # Never scan these -- they're large/binary and would just waste CPU.
    SKIP_PATH_PREFIXES = ("/core/static/", "/static/", "/media/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(self.SKIP_PATH_PREFIXES):
            return self.get_response(request)

        self._scan_request(request)
        response = self.get_response(request)
        self._scan_response(request, response)
        return response

    def _scan_request(self, request):
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        agent_hit = is_suspicious_agent(user_agent)
        if agent_hit:
            record_event(
                event_type=SecurityEvent.TYPE_SUSPICIOUS_AGENT,
                summary=f"Request from known scanner/exploit-tool user agent ('{agent_hit}')",
                request=request,
                details=f"user_agent={user_agent}",
            )

        probe_hit = is_sensitive_path_probe(request.path)
        if probe_hit:
            record_event(
                event_type=SecurityEvent.TYPE_SENSITIVE_PATH_PROBE,
                summary=f"Probe for sensitive path ({probe_hit})",
                request=request,
                details=f"path={request.path}",
            )

        # Scan the query string and, for form posts, the POST body. Never
        # scans file uploads or JSON API bodies here -- keeping this cheap
        # and low-noise is more valuable than perfect coverage.
        candidates = [request.META.get("QUERY_STRING", "")]
        if request.method == "POST" and request.content_type == "application/x-www-form-urlencoded":
            candidates.append("&".join(f"{k}={v}" for k, values in request.POST.lists() for v in values))

        for text in candidates:
            event_type, matched = scan_text_for_signatures(text)
            if event_type:
                record_event(
                    event_type=event_type,
                    summary=f"{dict(SecurityEvent.TYPE_CHOICES)[event_type]} in request",
                    request=request,
                    details=f"matched={matched!r}",
                )
                break  # one row per request is plenty; avoid double-counting overlapping patterns

    def _scan_response(self, request, response):
        # streaming_content responses have no .content -- skip those rather
        # than risk consuming/breaking the stream just to peek at it.
        body = b""
        if response.status_code == 403 and not response.streaming:
            body = bytes(response.content or b"")
        if response.status_code == 403 and b"CSRF" in body:
            record_event(
                event_type=SecurityEvent.TYPE_CSRF_FAILURE,
                summary="CSRF validation failed",
                request=request,
                details=f"path={request.path}",
            )
        elif response.status_code in (401, 403) and request.path.startswith("/api/"):
            record_event(
                event_type=SecurityEvent.TYPE_UNAUTHORIZED_ACCESS,
                summary=f"Unauthorized API request ({response.status_code})",
                request=request,
                details=f"path={request.path}",
            )
