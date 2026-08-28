import logging

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .models import NotificationLog, NotificationPreference, NotificationType

logger = logging.getLogger(__name__)


def user_wants(user, code):
    """
    Returns (should_send: bool, notification_type: NotificationType|None)
    for whether `user` currently wants emails of category `code`.

    Mandatory types always return True. Otherwise: an explicit
    NotificationPreference wins; failing that, the type's default_enabled
    is used (covers accounts that never visited the settings page).
    """
    try:
        ntype = NotificationType.objects.get(code=code, is_active=True)
    except NotificationType.DoesNotExist:
        return False, None

    if ntype.is_mandatory:
        return True, ntype

    pref = NotificationPreference.objects.filter(user=user, notification_type=ntype).first()
    if pref is not None:
        return pref.enabled, ntype
    return ntype.default_enabled, ntype


def send_notification(user, code, subject, template_name, context=None, sent_by=None, force=False):
    """
    Renders `template_name` (an HTML email template) and emails `user`.

    - Checks the user's NotificationPreference for `code` first, unless
      `force=True` or the NotificationType itself is marked mandatory.
    - Every attempt (sent / failed / skipped) is written to
      NotificationLog so admins can see exactly what went out, and why
      something didn't, from /admin/.
    - Never raises: send failures (bad SMTP creds, offline mail server,
      etc.) are caught and logged instead of breaking whatever view
      triggered the notification (login, registration, promote, ...).

    Returns True if an email was actually sent.
    """
    context = dict(context or {})
    email = (getattr(user, "email", "") or "").strip()

    wants_it, ntype = user_wants(user, code)

    if not email:
        NotificationLog.objects.create(
            notification_type=ntype,
            recipient_user=user,
            recipient_email="",
            subject=subject,
            status="failed",
            error_message="User has no email address on file.",
            sent_by=sent_by,
        )
        return False

    if not wants_it and not force:
        NotificationLog.objects.create(
            notification_type=ntype,
            recipient_user=user,
            recipient_email=email,
            subject=subject,
            status="skipped",
            sent_by=sent_by,
        )
        return False

    context.setdefault("user", user)
    context.setdefault("subject", subject)
    context.setdefault("site_name", "GapsIT Core")

    try:
        html_body = render_to_string(template_name, context)
    except Exception as exc:  # template bug shouldn't ever 500 the request
        logger.exception("Failed to render notification template %s", template_name)
        NotificationLog.objects.create(
            notification_type=ntype,
            recipient_user=user,
            recipient_email=email,
            subject=subject,
            status="failed",
            error_message=f"Template render error: {exc}",
            sent_by=sent_by,
        )
        return False

    try:
        message = EmailMultiAlternatives(
            subject=subject,
            body=strip_tags(html_body),
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
        )
        message.attach_alternative(html_body, "text/html")
        message.send(fail_silently=False)
    except Exception as exc:  # SMTP down / bad creds / timeout, etc.
        logger.exception("Failed to send notification email to %s", email)
        NotificationLog.objects.create(
            notification_type=ntype,
            recipient_user=user,
            recipient_email=email,
            subject=subject,
            status="failed",
            error_message=str(exc),
            sent_by=sent_by,
        )
        return False

    NotificationLog.objects.create(
        notification_type=ntype,
        recipient_user=user,
        recipient_email=email,
        subject=subject,
        status="sent",
        sent_by=sent_by,
    )
    return True
