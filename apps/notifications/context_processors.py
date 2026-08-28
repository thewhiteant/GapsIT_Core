from .models import EmailVerification


def email_verification_status(request):
    """
    Makes `email_verification` available in every template context so the
    dashboard (or anywhere else) can show a "please verify your email"
    banner without every view having to look it up itself.
    """
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {}
    ev = EmailVerification.objects.filter(user=user).first()
    return {"email_verification": ev}
