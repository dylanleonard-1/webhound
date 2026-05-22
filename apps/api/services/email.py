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
    resend.Emails.send({
        "from": f"{settings.resend_from_name} <{settings.resend_from_email}>",
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text,
    })


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
        server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.sendmail(settings.smtp_from_email, to, msg.as_string())


def _send_email(to: str, subject: str, html: str, text: str) -> None:
    settings = get_settings()
    if settings.resend_api_key:
        _send_resend(to, subject, html, text)
    elif settings.smtp_host:
        _send_smtp(to, subject, html, text)
    else:
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
