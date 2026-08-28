import ssl

from django.core.mail.backends.smtp import EmailBackend as DjangoSMTPEmailBackend


class LocalRelayEmailBackend(DjangoSMTPEmailBackend):
    """
    Identical to Django's built-in SMTP backend, except it skips SSL
    certificate hostname/CA verification.

    Use this ONLY when EMAIL_HOST is "localhost" or "127.0.0.1" on shared
    hosting where the Django app and the mail server live on the same
    physical machine. In that setup the mail server's SSL certificate is
    issued for the public mail hostname (e.g. mail.yourdomain.com), not
    for "localhost", so normal verification always fails with a hostname
    mismatch -- even though the connection itself never leaves the
    server's own loopback interface. Skipping verification here does NOT
    expose your mailbox password to the public internet; the traffic
    never goes further than the box it's running on.

    Do NOT point EMAIL_HOST at a real remote hostname while using this
    backend -- use the normal
    "django.core.mail.backends.smtp.EmailBackend" for anything that
    isn't same-machine localhost relay.

    Enable it in .env with:
        EMAIL_BACKEND=apps.notifications.email_backends.LocalRelayEmailBackend
        EMAIL_HOST=localhost
    """

    @property
    def ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
