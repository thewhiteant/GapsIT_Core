import os
import secrets

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import FileResponse, Http404
from django.shortcuts import redirect
from django.utils import timezone

from .models import DownloadToken
from .utils import detect_platform

VALID_PLATFORMS = {"windows", "linux"}


@login_required(login_url="login")
def request_download_view(request, platform):
    """
    GET /accounts/download/<platform>/

    Only reachable by a signed-in user whose linked Employee profile has
    role "employee" or "admin". Accounts with no Employee record at all,
    or whose Employee role is still the default "user" (i.e. registered
    but never promoted), are rejected with 403 -- even if they guess/type
    the URL directly.

    Issues a brand-new, single-use token for the requested platform and
    immediately redirects to the file-serving URL below.
    """
    employee = getattr(request.user, "employee", None)
    if employee is None or employee.role == "user":
        raise PermissionDenied("You need employee access to download GapsSight.")

    if platform not in VALID_PLATFORMS:
        raise Http404("Unknown platform.")

    release = settings.GAPSIGHT_RELEASES[platform]
    file_path = os.path.join(settings.GAPSIGHT_RELEASES_DIR, release["filename"])

    if not os.path.exists(file_path):
        messages.error(
            request,
            f"The {release['label']} build isn't on the server yet. Please contact an admin.",
        )
        return redirect("dashboard")

    token = DownloadToken.objects.create(
        user=request.user,
        platform=platform,
        token=secrets.token_hex(32),
        expires_at=timezone.now()
        + timezone.timedelta(minutes=settings.GAPSIGHT_DOWNLOAD_TOKEN_MINUTES),
    )
    return redirect("gapsight_download_file", token=token.token)


@login_required(login_url="login")
def serve_download_view(request, token):
    """
    GET /accounts/download/file/<token>/

    Redeems a token exactly once. The lookup + "mark used" happens inside
    one atomic, row-locked transaction so two near-simultaneous requests
    for the same link can't both succeed.
    """
    with transaction.atomic():
        try:
            dl = DownloadToken.objects.select_for_update().get(token=token)
        except DownloadToken.DoesNotExist:
            raise Http404("This download link is invalid.")

        if dl.user_id != request.user.id:
            raise PermissionDenied("This download link doesn't belong to your account.")

        if dl.used_at is not None:
            messages.error(
                request,
                "That download link has already been used. Click Download again for a fresh one.",
            )
            return redirect("dashboard")

        if timezone.now() >= dl.expires_at:
            messages.error(
                request,
                "That download link expired. Click Download again for a fresh one.",
            )
            return redirect("dashboard")

        dl.used_at = timezone.now()
        dl.ip_address = request.META.get("REMOTE_ADDR")
        dl.save(update_fields=["used_at", "ip_address"])

    release = settings.GAPSIGHT_RELEASES[dl.platform]
    file_path = os.path.join(settings.GAPSIGHT_RELEASES_DIR, release["filename"])

    if not os.path.exists(file_path):
        raise Http404("Release file is missing on the server.")

    return FileResponse(
        open(file_path, "rb"), as_attachment=True, filename=release["filename"]
    )