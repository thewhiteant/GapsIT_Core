from django.conf import settings
from django.contrib.auth.models import User
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils import timezone

from apps.employees.models import Employee

from .emailer import send_notification
from .models import EmailVerification

# ----------------------------------------------------------------------
# Email verification tokens. Stateless (signed + timestamped) so we don't
# need a token column anywhere -- just a secret-key signature over the
# user's id, the same trick Django's own password reset uses.
# ----------------------------------------------------------------------

_signer = TimestampSigner(salt="gapsit-email-verification")
VERIFICATION_MAX_AGE_SECONDS = 60 * 60 * 24 * 3  # 3 days
_RESEND_COOLDOWN_SECONDS = 60 * 2  # 2 minutes, enforced in views.py


def make_verification_token(user):
    return _signer.sign(str(user.pk))


def read_verification_token(token, max_age=VERIFICATION_MAX_AGE_SECONDS):
    """Returns the user id encoded in `token`, or None if invalid/expired."""
    try:
        value = _signer.unsign(token, max_age=max_age)
        return int(value)
    except (BadSignature, SignatureExpired, ValueError):
        return None


def send_verification_email(user):
    """Sends (or re-sends) the "confirm your email" message to `user`."""
    ev, _ = EmailVerification.objects.get_or_create(user=user)
    if ev.is_verified:
        return False

    token = make_verification_token(user)
    # reverse() already includes the FORCE_SCRIPT_NAME prefix (e.g. "/core"),
    # so SITE_BASE_URL must be scheme+host ONLY (e.g. "https://gapsit.bd"),
    # not "https://gapsit.bd/core" -- otherwise the prefix gets doubled and
    # every verification link 404s.
    path = reverse("verify_email", args=[token])
    base = getattr(settings, "SITE_BASE_URL", "").rstrip("/")
    link = f"{base}{path}" if base else path

    ev.last_sent_at = timezone.now()
    ev.save(update_fields=["last_sent_at"])

    # Verification mail is always sent (force=True) -- it's how the
    # account gets confirmed in the first place, so it can't be an
    # opt-out preference.
    return send_notification(
        user,
        "account_security",
        subject="Verify your email address - GapsIT Core",
        template_name="notifications/email/verify_email.html",
        context={"verify_link": link},
        force=True,
    )


# ----------------------------------------------------------------------
# Automatic account-lifecycle emails
# ----------------------------------------------------------------------

# Small in-process caches used to compare "before" vs "after" inside the
# post_save handler (Django signals don't hand you the old values).
_old_password_by_pk = {}
_old_role_by_pk = {}


@receiver(pre_save, sender=User)
def _capture_old_password(sender, instance, **kwargs):
    if not instance.pk:
        return
    old = User.objects.filter(pk=instance.pk).values_list("password", flat=True).first()
    if old is not None:
        _old_password_by_pk[instance.pk] = old


@receiver(post_save, sender=User)
def _on_user_saved(sender, instance, created, **kwargs):
    if created:
        EmailVerification.objects.get_or_create(user=instance)
        send_verification_email(instance)
        send_notification(
            instance,
            "account_updates",
            subject="Welcome to GapsIT Core",
            template_name="notifications/email/welcome_email.html",
        )
        return

    old_password = _old_password_by_pk.pop(instance.pk, None)
    if old_password is not None and old_password != instance.password:
        send_notification(
            instance,
            "account_security",
            subject="Your password was changed",
            template_name="notifications/email/password_changed_email.html",
            force=True,
        )


@receiver(pre_save, sender=Employee)
def _capture_old_role(sender, instance, **kwargs):
    if not instance.pk:
        return
    old = Employee.objects.filter(pk=instance.pk).values_list("role", flat=True).first()
    if old is not None:
        _old_role_by_pk[instance.pk] = old


@receiver(post_save, sender=Employee)
def _on_employee_saved(sender, instance, created, **kwargs):
    if created:
        return
    old_role = _old_role_by_pk.pop(instance.pk, None)
    if old_role is None or old_role == instance.role:
        return

    role_labels = dict(Employee.ROLE_CHOICES)
    send_notification(
        instance.user,
        "account_updates",
        subject="Your account role has changed",
        template_name="notifications/email/role_changed_email.html",
        context={
            "old_role": role_labels.get(old_role, old_role),
            "new_role": role_labels.get(instance.role, instance.role),
        },
    )
