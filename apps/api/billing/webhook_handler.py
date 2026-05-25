# WebHound — apps/api/billing/webhook_handler.py
# Stripe webhook event handler.
#
# Single entry point: handle_stripe_event(db, event). Dispatches on
# event.type and updates the local subscriptions table + users.plan column.
# All writes are idempotent — replaying a webhook delivers the same state.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
import stripe
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.stripe_service import price_id_to_tier
from apps.api.models.enums import PlanTier, SubscriptionStatus
from apps.api.models.subscription import Subscription
from apps.api.models.user import User

logger = logging.getLogger(__name__)


# Events we care about. Everything else is acknowledged and ignored.
_HANDLED_EVENTS = {
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
}


async def handle_stripe_event(db: AsyncSession, event: stripe.Event) -> None:
    # stripe.Event is a StripeObject, not a plain dict — has no .get().
    # Use subscript access and convert to plain dicts for downstream handlers.
    et = event["type"]
    if et not in _HANDLED_EVENTS:
        logger.debug("stripe webhook: ignoring %s", et)
        return

    raw_obj = event["data"]["object"]
    # Deep-convert so nested .get() calls in the handlers work — StripeObject
    # supports __getitem__ but not .get(), and we use .get() pervasively.
    if hasattr(raw_obj, "to_dict_recursive"):
        obj = raw_obj.to_dict_recursive()
    elif isinstance(raw_obj, dict):
        obj = raw_obj
    else:
        obj = dict(raw_obj)
    logger.info("stripe webhook: processing %s id=%s", et, event["id"])
    if et == "checkout.session.completed":
        await _on_checkout_completed(db, obj)
    elif et in ("customer.subscription.created",
                "customer.subscription.updated"):
        await _on_subscription_upsert(db, obj)
    elif et == "customer.subscription.deleted":
        await _on_subscription_deleted(db, obj)
    elif et == "invoice.payment_failed":
        await _on_payment_failed(db, obj)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


async def _on_checkout_completed(db: AsyncSession, session: dict) -> None:
    """Initial post-checkout sync. customer.subscription.created usually
    fires just before this with the same data, so this is largely a backup."""
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")
    user_id_str = (session.get("metadata") or {}).get("webhound_user_id")
    if not (customer_id and subscription_id and user_id_str):
        logger.warning("checkout.session.completed missing fields: %s",
                       {k: session.get(k) for k in
                        ("customer", "subscription", "metadata")})
        return
    user = await _user_by_id(db, user_id_str)
    if user is None:
        logger.warning("webhook checkout: unknown user_id=%s", user_id_str)
        return
    if not user.stripe_customer_id:
        user.stripe_customer_id = customer_id
    # The customer.subscription.created event will fire alongside this and
    # do the real upsert with the full subscription object. We just make
    # sure the customer link is established.


async def _on_subscription_upsert(db: AsyncSession, sub: dict) -> None:
    """Insert or update local Subscription row from a Stripe sub payload."""
    customer_id = sub.get("customer")
    sub_id = sub.get("id")
    if not (customer_id and sub_id):
        return

    # Locate user via customer_id (most reliable across all event types).
    user = await db.scalar(
        sa.select(User).where(User.stripe_customer_id == customer_id)
    )
    if user is None:
        # Try fallback via metadata.webhound_user_id.
        meta_uid = (sub.get("metadata") or {}).get("webhound_user_id")
        if meta_uid:
            user = await _user_by_id(db, meta_uid)
            if user is not None:
                user.stripe_customer_id = customer_id
    if user is None:
        logger.warning("subscription upsert: no user for customer=%s sub=%s",
                       customer_id, sub_id)
        return

    items = (sub.get("items") or {}).get("data") or []
    price_id = items[0]["price"]["id"] if items and items[0].get("price") else None
    tier = price_id_to_tier(price_id)

    status_raw = sub.get("status") or "incomplete"
    try:
        status = SubscriptionStatus(status_raw)
    except ValueError:
        status = SubscriptionStatus.INCOMPLETE

    period_start = _epoch_to_dt(sub.get("current_period_start"))
    period_end = _epoch_to_dt(sub.get("current_period_end"))
    canceled_at = _epoch_to_dt(sub.get("canceled_at"))
    cancel_at_period_end = bool(sub.get("cancel_at_period_end"))

    # Upsert by stripe_subscription_id
    existing = await db.scalar(
        sa.select(Subscription)
        .where(Subscription.stripe_subscription_id == sub_id)
    )
    if existing is None:
        record = Subscription(
            user_id=user.id,
            stripe_subscription_id=sub_id,
            stripe_customer_id=customer_id,
            stripe_price_id=price_id,
            status=status,
            plan=tier,
            current_period_start=period_start,
            current_period_end=period_end,
            cancel_at_period_end=cancel_at_period_end,
            canceled_at=canceled_at,
        )
        db.add(record)
    else:
        existing.stripe_customer_id = customer_id
        existing.stripe_price_id = price_id
        existing.status = status
        existing.plan = tier
        existing.current_period_start = period_start
        existing.current_period_end = period_end
        existing.cancel_at_period_end = cancel_at_period_end
        existing.canceled_at = canceled_at

    # Reflect on user.plan only when the subscription is actually paying.
    if status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING):
        user.plan = tier
    elif status in (SubscriptionStatus.CANCELED,
                     SubscriptionStatus.INCOMPLETE_EXPIRED,
                     SubscriptionStatus.UNPAID):
        user.plan = PlanTier.FREE


async def _on_subscription_deleted(db: AsyncSession, sub: dict) -> None:
    """Subscription fully cancelled — downgrade user to free."""
    sub_id = sub.get("id")
    customer_id = sub.get("customer")
    record = await db.scalar(
        sa.select(Subscription)
        .where(Subscription.stripe_subscription_id == sub_id)
    )
    if record is not None:
        record.status = SubscriptionStatus.CANCELED
        record.canceled_at = datetime.now(timezone.utc)
    if customer_id:
        user = await db.scalar(
            sa.select(User).where(User.stripe_customer_id == customer_id)
        )
        if user is not None:
            user.plan = PlanTier.FREE


async def _on_payment_failed(db: AsyncSession, invoice: dict) -> None:
    """A renewal payment failed. Mark subscription past_due; user.plan stays
    until Stripe sends a customer.subscription.deleted at the end of the
    grace period."""
    sub_id = invoice.get("subscription")
    if not sub_id:
        return
    record = await db.scalar(
        sa.select(Subscription)
        .where(Subscription.stripe_subscription_id == sub_id)
    )
    if record is not None:
        record.status = SubscriptionStatus.PAST_DUE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _epoch_to_dt(value: int | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


async def _user_by_id(db: AsyncSession, user_id_str: str) -> User | None:
    try:
        user_uuid = uuid.UUID(user_id_str)
    except (TypeError, ValueError):
        return None
    return await db.scalar(sa.select(User).where(User.id == user_uuid))
