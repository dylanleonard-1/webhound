# WebHound — apps/api/services/notification_delivery.py
# FIX 6 — outbound email delivery for customer-facing scan notifications.
#
# Posture:
#   * Feature-flagged. Sends nothing unless NOTIFICATIONS_ENABLED=1 AND an
#     email provider is configured. When off, every notification is marked
#     "skipped" — the UI/API must never claim an email was sent.
#   * Only customer-facing P0 events are email-eligible (critical/high
#     finding, WADE suspicious change, scan failed). scan_completed (INFO)
#     and internal schedule_failed are in-app only.
#   * Idempotent: an already sent/suppressed notification is never re-sent.
#   * Deduplicated: a second email for the same (user, type, website) within
#     the dedup window is suppressed, not sent.
#   * Retries with backoff are owned by the Celery task
#     (worker.notification_tasks); this module performs ONE send attempt and
#     records the outcome.
#
# The pure helpers (is_email_eligible / compute_dedup_key / build_email /
# provider_configured) are import-light and unit-testable without a DB.

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import NotificationType
from apps.api.models.notification import Notification

logger = logging.getLogger(__name__)


class EmailStatus:
    """String values stored in Notification.email_status."""

    SKIPPED = "skipped"        # not eligible / feature off — never attempted
    PENDING = "pending"        # eligible + queued, not yet sent
    SENT = "sent"
    FAILED = "failed"          # attempted, retries exhausted
    SUPPRESSED = "suppressed"  # duplicate within the dedup window


# Customer-facing events that warrant an email. INFO scan_completed and the
# internal schedule_failed are intentionally excluded.
EMAIL_ELIGIBLE_TYPES = frozenset({
    NotificationType.SCAN_FAILED,
    NotificationType.HIGH_RISK_FINDING,
    NotificationType.CRITICAL_FINDING,
    NotificationType.WADE_ANOMALY,
})

# Suppress a second email for the same (user, type, website) within this window.
_DEDUP_WINDOW = timedelta(hours=6)


class RetryableDeliveryError(Exception):
    """Raised when a send failed but retries remain — the Celery task
    catches this and reschedules with backoff."""


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def is_email_eligible(ntype: NotificationType) -> bool:
    return ntype in EMAIL_ELIGIBLE_TYPES


def provider_configured(settings) -> bool:
    """True when an email provider can actually deliver. Mirrors
    Settings._has_email_provider but tolerant of partial settings."""
    return bool(getattr(settings, "resend_api_key", "")) or (
        bool(getattr(settings, "smtp_fallback_enabled", False))
        and bool(getattr(settings, "smtp_host", ""))
    )


def compute_dedup_key(
    user_id: uuid.UUID, ntype: NotificationType, website_id: uuid.UUID | None,
) -> str:
    type_val = getattr(ntype, "value", str(ntype))
    return f"email:{user_id}:{type_val}:{website_id or '-'}"


def build_email(notification: Notification) -> tuple[str, str, str]:
    """Return (subject, html, text) for a customer notification."""
    from apps.api.services.email import _email_html

    settings = _get_settings()
    title = notification.title
    subject = f"WebHound: {title}"
    meta = notification.extra_metadata or {}
    website_url = meta.get("website_url") or ""
    cta_url = f"{settings.frontend_url}/dashboard"
    if notification.website_id:
        cta_url = f"{settings.frontend_url}/dashboard/websites/{notification.website_id}"
    body_html = (
        '<p style="margin:0 0 8px;color:#475569;font-size:14px;line-height:1.6">'
        f"{notification.message}</p>"
    )
    if website_url:
        body_html += (
            '<p style="margin:8px 0 0;color:#94a3b8;font-size:13px">'
            f"Site: {website_url}</p>"
        )
    html = _email_html(title, body_html, cta_url, "View in dashboard")
    text = f"{title}\n\n{notification.message}\n\n{cta_url}"
    return subject, html, text


# ---------------------------------------------------------------------------
# Delivery (one attempt; retries/backoff owned by the Celery task)
# ---------------------------------------------------------------------------

def _get_settings():
    from apps.api.config import get_settings

    return get_settings()


async def attempt_delivery(
    db: AsyncSession,
    notification_id: uuid.UUID,
    to_email: str | None,
    *,
    is_final_attempt: bool = True,
    settings=None,
    send=None,
) -> str:
    """Perform a single delivery attempt and persist the outcome.

    Returns the resulting :class:`EmailStatus` value. Raises
    :class:`RetryableDeliveryError` when the send failed and ``is_final_attempt``
    is False, so the caller can reschedule with backoff. Never raises for
    config / eligibility / dedup outcomes — those resolve to a terminal status.

    ``settings`` and ``send`` are injectable for tests; defaults read the live
    settings and use the real Resend/SMTP path.
    """
    settings = settings or _get_settings()
    n = await db.get(Notification, notification_id)
    if n is None:
        return "missing"

    # Idempotent: never re-send a terminal-success/suppressed row.
    if n.email_status in (EmailStatus.SENT, EmailStatus.SUPPRESSED):
        return n.email_status

    # Feature flag / provider gate — mark skipped, never pretend it sent.
    if not getattr(settings, "notifications_enabled", False) or not provider_configured(settings):
        n.email_status = EmailStatus.SKIPPED
        await db.flush()
        return EmailStatus.SKIPPED

    if not is_email_eligible(n.type) or not to_email:
        n.email_status = EmailStatus.SKIPPED
        await db.flush()
        return EmailStatus.SKIPPED

    # Dedup: a recent SENT email for the same (user, type, website) suppresses.
    cutoff = datetime.now(timezone.utc) - _DEDUP_WINDOW
    dup = await db.scalar(
        sa.select(sa.func.count())
        .select_from(Notification)
        .where(
            Notification.id != n.id,
            Notification.user_id == n.user_id,
            Notification.type == n.type,
            Notification.website_id == n.website_id,
            Notification.email_status == EmailStatus.SENT,
            Notification.email_sent_at >= cutoff,
        )
    )
    if dup and dup > 0:
        n.email_status = EmailStatus.SUPPRESSED
        await db.flush()
        return EmailStatus.SUPPRESSED

    subject, html, text = build_email(n)
    sender = send or _default_send
    try:
        # The Resend/SMTP send is blocking I/O — never block the event loop.
        await asyncio.to_thread(sender, to_email, subject, html, text)
    except Exception as exc:  # noqa: BLE001
        n.email_attempts = (n.email_attempts or 0) + 1
        n.email_last_error = str(exc)[:500]
        if is_final_attempt:
            n.email_status = EmailStatus.FAILED
            await db.flush()
            logger.warning(
                "notification email to %s failed permanently: %s", to_email, exc,
            )
            return EmailStatus.FAILED
        n.email_status = EmailStatus.PENDING
        await db.flush()
        raise RetryableDeliveryError(str(exc)) from exc

    n.email_status = EmailStatus.SENT
    n.email_attempts = (n.email_attempts or 0) + 1
    n.email_sent_at = datetime.now(timezone.utc)
    n.email_last_error = None
    await db.flush()
    return EmailStatus.SENT


def _default_send(to: str, subject: str, html: str, text: str) -> None:
    from apps.api.services.email import _send_email

    _send_email(to, subject, html, text)


def eligible_for_email(notifications, settings=None) -> list[Notification]:
    """Filter created notifications down to the email-eligible set, honouring
    the feature flag + provider config. Used by the worker to decide what to
    enqueue. Returns [] when the feature is off (no enqueue, no pretending)."""
    settings = settings or _get_settings()
    if not getattr(settings, "notifications_enabled", False) or not provider_configured(settings):
        return []
    return [n for n in notifications if is_email_eligible(n.type)]
