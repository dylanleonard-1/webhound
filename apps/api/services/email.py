from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from apps.api.config import get_settings

logger = logging.getLogger(__name__)


def _email_html(title: str, body_html: str, cta_url: str, cta_label: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:40px 16px">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0">
        <!-- Header -->
        <tr><td style="background:#020617;padding:24px 32px">
          <table cellpadding="0" cellspacing="0">
            <tr>
              <td style="background:#8BFF3E;width:28px;height:28px;border-radius:8px;text-align:center;vertical-align:middle">
                <span style="color:#020617;font-weight:900;font-size:14px">W</span>
              </td>
              <td style="padding-left:10px;color:#ffffff;font-weight:700;font-size:15px;letter-spacing:0.08em">WEBHOUND</td>
            </tr>
          </table>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px">
          <h2 style="margin:0 0 12px;font-size:20px;color:#0f172a;font-weight:700">{title}</h2>
          {body_html}
          <div style="margin:28px 0">
            <a href="{cta_url}"
               style="display:inline-block;background:#020617;color:#ffffff;font-weight:600;
                      font-size:14px;padding:13px 28px;border-radius:8px;text-decoration:none">
              {cta_label}
            </a>
          </div>
          <p style="margin:0;color:#94a3b8;font-size:12px;line-height:1.6">
            Or copy this link into your browser:<br>
            <a href="{cta_url}" style="color:#475569;word-break:break-all">{cta_url}</a>
          </p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:16px 32px;border-top:1px solid #f1f5f9">
          <p style="margin:0;color:#cbd5e1;font-size:11px">
            WebHound · webhoundsecurity.com · You received this because an account action was performed.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _send_resend(to: str, subject: str, html: str, text: str) -> None:
    import resend  # type: ignore[import-untyped]
    settings = get_settings()
    resend.api_key = settings.resend_api_key
    response = resend.Emails.send({
        "from": f"{settings.resend_from_name} <{settings.resend_from_email}>",
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text,
    })
    # The SDK returns a dict — `{"id": "..."}` on success, `{"statusCode", "message", "name"}`
    # on error (older versions silently returned errors instead of raising).
    if isinstance(response, dict) and "id" not in response:
        msg = response.get("message") or response.get("name") or str(response)
        raise RuntimeError(f"Resend API error: {msg}")
    logger.info(
        "Resend accepted email to %s (id=%s, subject=%r)",
        to,
        response.get("id") if isinstance(response, dict) else None,
        subject,
    )


def _send_smtp(to: str, subject: str, html: str, text: str) -> None:
    settings = get_settings()
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
    msg["To"] = to
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
        server.ehlo()
        # FIX 11 — STARTTLS is opt-out via SMTP_USE_TLS (default on). Some
        # relays (localhost dev MTA, internal smtphost) don't offer STARTTLS.
        if getattr(settings, "smtp_use_tls", True):
            server.starttls()
            server.ehlo()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.sendmail(settings.smtp_from_email, to, msg.as_string())
    logger.info("SMTP delivered email to %s (subject=%r)", to, subject)


# FIX 11 — substrings that mark a permanent Resend/SMTP rejection. A bad
# recipient address will fail the same way on SMTP, so we must NOT burn the
# fallback (or retry) on these — re-raise immediately.
_PERMANENT_EMAIL_MARKERS = (
    "invalid",            # "invalid `to` field", "invalid recipient", "invalid email"
    "validation_error",   # Resend validation errors
    "not a valid",
    "recipient",          # SMTPRecipientsRefused str()
    "no such user",
    "mailbox unavailable",
    "does not exist",
    "5.1.1",              # SMTP enhanced status: bad destination mailbox
    "550",               # SMTP permanent: mailbox unavailable
)


def _is_permanent_email_error(exc: Exception) -> bool:
    """True when the failure is about the *message/recipient* (won't be fixed by
    trying another provider) rather than a transient provider/transport issue."""
    import smtplib as _smtplib

    if isinstance(exc, (_smtplib.SMTPRecipientsRefused, _smtplib.SMTPSenderRefused)):
        return True
    msg = str(exc).lower()
    return any(marker in msg for marker in _PERMANENT_EMAIL_MARKERS)


def _send_email(to: str, subject: str, html: str, text: str) -> str:
    """Send via Resend, failing over to SMTP if enabled. Returns the provider
    that delivered the message ("resend" or "smtp").

    Resend stays the primary provider. If a Resend send raises a *transient*
    error (outage, rate limit, domain issue) AND SMTP failover is enabled
    (SMTP_FALLBACK_ENABLED=1 with SMTP_HOST), we transparently fall back so a
    single-provider outage doesn't block verification / reset / login-code /
    notification emails. We do NOT fail over on a permanent error (e.g. invalid
    recipient) — that would just fail again and waste the attempt.
    """
    settings = get_settings()
    smtp_fallback = (
        bool(getattr(settings, "smtp_fallback_enabled", False))
        and bool(settings.smtp_host)
    )
    if settings.resend_api_key:
        try:
            _send_resend(to, subject, html, text)
            return "resend"
        except Exception as exc:
            if not smtp_fallback:
                raise
            if _is_permanent_email_error(exc):
                logger.warning(
                    "Resend rejected %s permanently (%s); not failing over to SMTP",
                    to, exc,
                )
                raise
            logger.exception("Resend send failed; failing over to SMTP for %s", to)
            _send_smtp(to, subject, html, text)
            return "smtp"
    if settings.smtp_host:
        _send_smtp(to, subject, html, text)
        return "smtp"
    raise RuntimeError("No email provider configured")


async def send_verification_email(to: str, token: str) -> str | None:
    """Returns the verify URL in dev mode so callers can surface it. Returns None when email is sent."""
    settings = get_settings()
    verify_url = f"{settings.frontend_url}/auth/verify-email?token={token}"
    subject = "Verify your WebHound email"
    text = f"Verify your WebHound account:\n\n{verify_url}\n\nThis link expires in 24 hours."
    body_html = '<p style="margin:0 0 8px;color:#475569;font-size:14px;line-height:1.6">Click below to verify your email address and activate your WebHound account. This link expires in 24 hours.</p>'
    html = _email_html("Verify your email", body_html, verify_url, "Verify email address")

    if not settings.resend_api_key and not settings.smtp_host:
        logger.info("No email provider configured — verification link for %s: %s", to, verify_url)
        print(f"\n[EMAIL] Verification link for {to}:\n  {verify_url}\n")
        return verify_url

    try:
        _send_email(to, subject, html, text)
    except Exception:
        logger.exception("Failed to send verification email to %s", to)
    return None


async def send_password_reset_email(to: str, token: str) -> str | None:
    """Returns the reset URL in dev mode so callers can surface it. Returns None when email is sent."""
    settings = get_settings()
    reset_url = f"{settings.frontend_url}/reset-password?token={token}"
    subject = "Reset your WebHound password"
    text = f"Reset your WebHound password:\n\n{reset_url}\n\nThis link expires in 1 hour. If you did not request this, ignore this email."
    body_html = (
        '<p style="margin:0 0 8px;color:#475569;font-size:14px;line-height:1.6">'
        'A password reset was requested for your WebHound account. Click below to choose a new password.'
        ' This link expires in 1 hour.</p>'
        '<p style="margin:12px 0 0;color:#94a3b8;font-size:13px;line-height:1.6">'
        'If you did not request this, you can safely ignore this email — your password will not change.</p>'
    )
    html = _email_html("Reset your password", body_html, reset_url, "Choose a new password")

    if not settings.resend_api_key and not settings.smtp_host:
        logger.info("No email provider configured — password reset link for %s: %s", to, reset_url)
        print(f"\n[EMAIL] Password reset link for {to}:\n  {reset_url}\n")
        return reset_url

    try:
        _send_email(to, subject, html, text)
    except Exception:
        logger.exception("Failed to send password reset email to %s", to)
    return None


class EmailDeliveryResult:
    __slots__ = ("delivered", "dev_value", "error")

    def __init__(self, delivered: bool, dev_value: str | None = None, error: str | None = None) -> None:
        self.delivered = delivered
        self.dev_value = dev_value
        self.error = error


async def send_login_code_email(to: str, code: str) -> EmailDeliveryResult:
    """Sends a 6-digit login verification code.

    Returns an EmailDeliveryResult so the caller can distinguish
    "delivered to inbox", "delivered to dev console", and "failed".
    """
    settings = get_settings()
    # Subjects that LEAD with a 6-digit number trip Gmail / Apple Mail spam
    # heuristics. Keep the number out of the subject.
    subject = "Your WebHound sign-in code"
    text = f"Your WebHound sign-in code is {code}.\n\nThis code expires in 10 minutes."
    body_html = (
        '<p style="margin:0 0 16px;color:#475569;font-size:14px;line-height:1.6">'
        'Use the code below to finish signing in to WebHound. It expires in 10 minutes.</p>'
        f'<div style="margin:20px 0;padding:18px 24px;background:#f1f5f9;border-radius:10px;'
        'text-align:center;font-family:ui-monospace,Menlo,Consolas,monospace;'
        'font-size:28px;font-weight:700;letter-spacing:6px;color:#020617">'
        f'{code}</div>'
        '<p style="margin:0;color:#94a3b8;font-size:13px;line-height:1.6">'
        "If you didn't try to sign in, you can ignore this email and your account stays safe.</p>"
    )
    cta_url = f"{settings.frontend_url}/login"
    html = _email_html("Your sign-in code", body_html, cta_url, "Open WebHound")

    if not settings.resend_api_key and not settings.smtp_host:
        logger.info("No email provider configured — sign-in code for %s: %s", to, code)
        print(f"\n[EMAIL] Sign-in code for {to}: {code}\n")
        return EmailDeliveryResult(delivered=False, dev_value=code)

    try:
        _send_email(to, subject, html, text)
        return EmailDeliveryResult(delivered=True)
    except Exception as exc:
        logger.exception("Failed to send sign-in code to %s", to)
        return EmailDeliveryResult(delivered=False, error=str(exc))


async def send_login_alert(to: str, ip: str, user_agent: str) -> None:
    """Sends a login-from-new-device alert. No-op in dev when email not configured."""
    settings = get_settings()
    if not settings.resend_api_key and not settings.smtp_host:
        return
    subject = "New sign-in to your WebHound account"
    text = f"A new sign-in was detected from IP {ip}. If this was you, no action needed."
    body_html = f'<p style="margin:0 0 8px;color:#475569;font-size:14px;line-height:1.6">A new sign-in was detected on your WebHound account.</p><p style="margin:0 0 8px;color:#475569;font-size:14px">IP: <code>{ip}</code><br>Device: <code>{user_agent[:80]}</code></p><p style="margin:0;color:#475569;font-size:14px">If this wasn\'t you, secure your account immediately.</p>'
    security_url = f"{settings.frontend_url}/dashboard/settings"
    html = _email_html("New sign-in detected", body_html, security_url, "Review account security")
    try:
        _send_email(to, subject, html, text)
    except Exception:
        logger.exception("Failed to send login alert to %s", to)
