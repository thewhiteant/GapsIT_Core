import logging

from django.db import transaction
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ActivityGateCheck, ActivitySession, ActivityStatusChange
from .serializers import SessionInputSerializer, ActivitySessionSummarySerializer

logger = logging.getLogger(__name__)


class ActivitySyncView(APIView):
    """
    POST /api/activity/sync/

    Body: { "sessions": [ { clientSessionId, username, startTime, endTime,
                             totalActiveSeconds, totalAfkSeconds, totalBlockedSeconds,
                             gateChecks: [...], statusChanges: [...] }, ... ] }

    Backs up finished GapsSight sessions (and their GateChecks/StatusChanges
    detail rows) from the desktop app's local SQLite database into this
    server's database, so the desktop app can safely prune its own old
    detail rows (see ActivitySyncService/PruneOldPerformanceData on the
    client -- it only keeps a rolling ~10 day window locally) without
    losing the history for good.

    Idempotent: a session already present for this user (matched by
    clientSessionId, which is only unique per-device) is left untouched and
    its id is just echoed back in "syncedSessionIds" -- so if a previous
    sync response never made it back to the client (dropped connection,
    etc.) and it retries the same batch, nothing gets duplicated.

    Each authenticated user can only sync/see their own sessions -- there's
    no "sync as someone else" here, `owner` always comes from the request's
    JWT, never from the payload.

    Each session in the batch is validated and committed INDIVIDUALLY
    (previously the whole batch was validated as one
    ActivitySyncRequestSerializer and rejected wholesale with a 400 if any
    single session failed validation -- since the client always re-offers
    the oldest unsynced sessions first, one permanently-malformed row would
    silently wedge every session behind it forever, with nothing visible on
    the client side. Now a bad session is reported back individually in
    "rejectedSessions" and every other session in the batch still syncs.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        raw_sessions = request.data.get("sessions")
        if not isinstance(raw_sessions, list):
            return Response(
                {"detail": "\"sessions\" must be a list."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        synced_ids = []
        skipped_ids = []
        rejected = []

        for raw_session in raw_sessions:
            # Pull this out before validation so we can still report *which*
            # session failed even if the rest of its payload is garbage.
            client_session_id = (
                raw_session.get("clientSessionId") if isinstance(raw_session, dict) else None
            )

            session_serializer = SessionInputSerializer(data=raw_session)
            if not session_serializer.is_valid():
                rejected.append(
                    {
                        "clientSessionId": client_session_id,
                        "errors": session_serializer.errors,
                    }
                )
                logger.warning(
                    "Rejected activity session client_session_id=%s for user=%s: %s",
                    client_session_id,
                    request.user,
                    session_serializer.errors,
                )
                continue

            session_data = dict(session_serializer.validated_data)
            client_session_id = session_data["client_session_id"]
            gate_checks = session_data.pop("gate_checks", [])
            status_changes = session_data.pop("status_changes", [])

            try:
                # Each session gets its own transaction so one unexpected
                # DB-level failure (e.g. a bulk_create integrity error) only
                # rolls back that single session, not the whole batch.
                with transaction.atomic():
                    existing = ActivitySession.objects.filter(
                        owner=request.user, client_session_id=client_session_id
                    ).first()
                    if existing is not None:
                        # Already backed up from an earlier sync -- report it
                        # as synced anyway so the client marks it done
                        # locally and stops retrying it, but don't touch the
                        # stored rows.
                        skipped_ids.append(client_session_id)
                        synced_ids.append(client_session_id)
                        continue

                    session = ActivitySession.objects.create(owner=request.user, **session_data)

                    if gate_checks:
                        ActivityGateCheck.objects.bulk_create(
                            [ActivityGateCheck(session=session, **row) for row in gate_checks]
                        )
                    if status_changes:
                        ActivityStatusChange.objects.bulk_create(
                            [ActivityStatusChange(session=session, **row) for row in status_changes]
                        )

                    synced_ids.append(client_session_id)
            except Exception as exc:  # pragma: no cover - defensive, see docstring
                rejected.append(
                    {"clientSessionId": client_session_id, "errors": {"detail": str(exc)}}
                )
                logger.exception(
                    "Failed to save activity session client_session_id=%s for user=%s",
                    client_session_id,
                    request.user,
                )

        return Response(
            {
                "syncedSessionIds": synced_ids,
                "alreadySynced": skipped_ids,
                "rejectedSessions": rejected,
            },
            status=status.HTTP_200_OK,
        )


class MyActivitySessionsView(generics.ListAPIView):
    """
    GET /api/activity/sessions/ -- read-only list of the current user's own
    synced sessions (most recent first), mainly to confirm a sync actually
    landed. Not used by the desktop app itself.
    """

    serializer_class = ActivitySessionSummarySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ActivitySession.objects.filter(owner=self.request.user)
