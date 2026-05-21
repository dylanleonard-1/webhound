from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from apps.api.config import get_settings

logger = logging.getLogger(__name__)


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


async def send_verification_email(to: str, token: str) -> None:
    settings = get_settings()
    verify_url = f"{settings.frontend_url}/auth/verify-email?token={token}"
    subject = "Verify your WebHound email"
    text = f"Click the link to verify your email:\n\n{verify_url}\n\nExpires in 24 hours."
    html = f"""
<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 16px">
  <h2 style="margin:0 0 8px;font-size:20px;color:#0f172a">Verify your email</h2>
  <p style="margin:0 0 24px;color:#475569;font-size:14px">
    Click the button below to verify your WebHound account. The link expires in 24 hours.
  </p>
  <a href="{verify_url}"
     style="display:inline-block;background:#8BFF3E;color:#020617;font-weight:600;
            font-size:14px;padding:12px 24px;border-radius:10px;text-decoration:none">
    Verify email
  </a>
  <p style="margin:24px 0 0;color:#94a3b8;font-size:12px">
    If you didn't create a WebHound account, you can ignore this email.
  </p>
</div>"""

    if not settings.smtp_host:
        logger.info("SMTP not configured — verification link: %s", verify_url)
        print(f"\n[EMAIL] Verification link for {to}:\n  {verify_url}\n")
        return

    try:
        _send_smtp(to, subject, html, text)
    except Exception:
        logger.exception("Failed to send verification email to %s", to)
