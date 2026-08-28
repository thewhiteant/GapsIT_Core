from datetime import timedelta
from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.utils import timezone

from .emailer import send_notification
from .forms import BroadcastForm
from .models import EmailVerification, NotificationLog, NotificationPreference, NotificationType
from .signals import read_verification_token, send_verification_email

# ----------------------------------------------------------------------
# Small local admin check, mirroring the one in apps/allowlist/views.py,
# so this app doesn't need to import from other apps' view modules.
# ----------------------------------------------------------------------


def _is_admin(user):
    if not user or not user.is_authenticated:
        return False
    if user.is_staff or user.is_superuser:
        return True
    return bool(getattr(getattr(user, "employee", None), "is_admin", False))


def admin_required(view_func):
    @wraps(view_func)
    @login_required(login_url="login")
    def wrapper(request, *args, **kwargs):
        if not _is_admin(request.user):
            messages.error(request, "You need admin access for that page.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)

    return wrapper


# ----------------------------------------------------------------------
# Email verification
# ----------------------------------------------------------------------


def verify_email_view(request, token):
    """GET /accounts/verify-email/<token>/ -- link clicked from the email."""
    user_id = read_verification_token(token)
    if user_id is None:
        messages.error(
            request,
            "That verification link is invalid or has expired. Request a new one below.",
        )
        return redirect("resend_verification") if request.user.is_authenticated else redirect("login")

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, "That verification link is no longer valid.")
        return redirect("login")

    ev, _ = EmailVerification.objects.get_or_create(user=user)
    if not ev.is_verified:
        ev.is_verified = True
        ev.verified_at = timezone.now()
        ev.save(update_fields=["is_verified", "verified_at"])
        messages.success(request, "Your email address has been verified. Thanks!")
    else:
        messages.success(request, "Your email was already verified.")

    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


@login_required(login_url="login")
def resend_verification_view(request):
    """POST /accounts/verify-email/resend/ -- 'resend verification email' button."""
    ev, _ = EmailVerification.objects.get_or_create(user=request.user)

    if ev.is_verified:
        messages.success(request, "Your email is already verified.")
        return redirect("dashboard")

    if ev.last_sent_at and timezone.now() - ev.last_sent_at < timedelta(minutes=2):
        messages.error(
            request,
            "A verification email was just sent -- please wait a couple of minutes before requesting another.",
        )
        return redirect("dashboard")

    send_verification_email(request.user)
    messages.success(request, f"Verification email sent to {request.user.email}.")
    return redirect("dashboard")


# ----------------------------------------------------------------------
# Per-user notification preferences
# ----------------------------------------------------------------------


@login_required(login_url="login")
def notification_preferences_view(request):
    """GET/POST /accounts/notifications/ -- user picks what they get emailed about."""
    types = NotificationType.objects.filter(is_active=True, is_mandatory=False)
    existing = {
        p.notification_type_id: p.enabled
        for p in NotificationPreference.objects.filter(user=request.user)
    }

    if request.method == "POST":
        for ntype in types:
            enabled = request.POST.get(f"type_{ntype.id}") == "on"
            NotificationPreference.objects.update_or_create(
                user=request.user,
                notification_type=ntype,
                defaults={"enabled": enabled},
            )
        messages.success(request, "Your notification preferences were saved.")
        return redirect("notification_preferences")

    rows = [
        {"type": ntype, "enabled": existing.get(ntype.id, ntype.default_enabled)}
        for ntype in types
    ]
    mandatory_types = NotificationType.objects.filter(is_active=True, is_mandatory=True)
    return render(
        request,
        "notifications/preferences.html",
        {"rows": rows, "mandatory_types": mandatory_types},
    )


# ----------------------------------------------------------------------
# Admin broadcast page
# ----------------------------------------------------------------------


@admin_required
def broadcast_view(request):
    """GET/POST /accounts/notifications/send/ -- admin sends a notice/update by email."""
    sent_count = None
    total_count = None

    if request.method == "POST":
        form = BroadcastForm(request.POST)
        if form.is_valid():
            audience = form.cleaned_data["audience"]
            if audience == "all":
                recipients = list(User.objects.filter(is_active=True))
            elif audience == "specific":
                recipients = list(form.cleaned_data["specific_users"])
            else:
                role = audience.replace("role_", "")
                recipients = list(User.objects.filter(is_active=True, employee__role=role))

            subject = form.cleaned_data["subject"]
            message_text = form.cleaned_data["message"]
            force = form.cleaned_data["force_send"]

            sent_count = 0
            total_count = len(recipients)
            for user in recipients:
                ok = send_notification(
                    user,
                    "admin_broadcast",
                    subject=subject,
                    template_name="notifications/email/broadcast_email.html",
                    context={"message": message_text, "sent_by": request.user},
                    sent_by=request.user,
                    force=force,
                )
                if ok:
                    sent_count += 1

            messages.success(request, f"Notice sent to {sent_count} of {total_count} recipient(s).")
            form = BroadcastForm()
    else:
        form = BroadcastForm()

    recent_logs = NotificationLog.objects.filter(sent_by__isnull=False).select_related(
        "recipient_user", "sent_by"
    )[:25]
    return render(
        request,
        "notifications/broadcast.html",
        {"form": form, "recent_logs": recent_logs, "sent_count": sent_count, "total_count": total_count},
    )
