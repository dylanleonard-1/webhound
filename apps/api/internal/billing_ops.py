# WebHound — apps/api/internal/billing_ops.py
# Phase 4: Billing Operations Center — true MRR/ARR/churn from Stripe,
# subscriptions list, and recent webhook events (delivery monitoring proxy).
#
# Each Stripe call is wrapped + run in a thread so a slow API call degrades
# its own tile rather than the whole page. Local DB is used for subscription
# joining (we already mirror via webhooks).

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

import sqlalchemy as sa
import stripe
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole, SubscriptionStatus
from apps.api.models.subscription import Subscription
from apps.api.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/billing", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.BILLING))]
_DB = Annotated[AsyncSession, Depends(get_db)]


def _configured() -> bool:
    return bool(get_settings().stripe_secret_key)


def _set_key() -> None:
    stripe.api_key = get_settings().stripe_secret_key


def _interval_factor(interval: str | None) -> float:
    # Convert a Stripe price interval to a monthly multiplier.
    return {"year": 1 / 12, "month": 1.0, "week": 4.345, "day": 30.44}.get(interval or "month", 1.0)


def _g(obj, key, default=None):
    """Safe accessor for stripe.StripeObject (which doesn't expose dict.get
    via __getattr__) and for plain dicts. Returns `default` if missing/None."""
    if obj is None:
        return default
    try:
        val = obj[key]
    except (KeyError, TypeError):
        return default
    return default if val is None else val


def _sum_mrr_cents() -> tuple[int, int]:
    """Walk all active+trialing subs and sum recurring revenue → (mrr_cents, count)."""
    total_cents = 0
    count = 0
    for status in ("active", "trialing"):
        iterator = stripe.Subscription.list(status=status, limit=100,
                                            expand=["data.items.data.price"]).auto_paging_iter()
        for sub in iterator:
            count += 1
            try:
                discount = _g(sub, "discount", {}) or {}
                coupon = _g(discount, "coupon", {}) or {}
                percent_off = _g(coupon, "percent_off")
                amount_off = _g(coupon, "amount_off")
                discount_pct = float(percent_off) / 100.0 if percent_off else 0.0
                items = _g(_g(sub, "items", {}), "data", []) or []
                for item in items:
                    price = _g(item, "price", {}) or {}
                    amt = int(_g(price, "unit_amount", 0) or 0)
                    qty = int(_g(item, "quantity", 1) or 1)
                    recurring = _g(price, "recurring", {}) or {}
                    factor = _interval_factor(_g(recurring, "interval"))
                    monthly = amt * qty * factor
                    if amount_off:
                        monthly -= int(amount_off) * factor  # rough ceiling
                    monthly *= (1 - discount_pct)
                    total_cents += max(0, int(monthly))
            except Exception:  # noqa: BLE001
                logger.warning("MRR aggregation failed on a subscription", exc_info=True)
    return total_cents, count


async def _stripe_metrics() -> dict:
    if not _configured():
        return {"error": "stripe not configured"}
    _set_key()

    def _work() -> dict:
        mrr_c, active = _sum_mrr_cents()
        # Past-due — needs payment fix.
        past_due_count = 0
        try:
            for _ in stripe.Subscription.list(status="past_due", limit=100).auto_paging_iter():
                past_due_count += 1
        except Exception:  # noqa: BLE001
            past_due_count = -1
        # Churn proxy — invoice.payment_failed in last 24h (Stripe Events).
        failed_24h = 0
        cutoff = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())
        try:
            for ev in stripe.Event.list(type="invoice.payment_failed", limit=100,
                                        created={"gte": cutoff}).auto_paging_iter():
                failed_24h += 1
                if failed_24h >= 100:
                    break
        except Exception:  # noqa: BLE001
            failed_24h = -1
        return {
            "mrr_usd": round(mrr_c / 100, 2),
            "arr_usd": round(mrr_c * 12 / 100, 2),
            "active_subscriptions": active,
            "past_due": past_due_count,
            "failed_payments_24h": failed_24h,
        }

    try:
        return await asyncio.to_thread(_work)
    except Exception as exc:  # noqa: BLE001
        logger.exception("stripe metrics failed")
        return {"error": str(exc)[:120]}


async def _local_metrics(db: AsyncSession) -> dict:
    """Cheap local approximations as a sanity check against Stripe."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    canceled_30d = await db.scalar(
        select(func.count()).select_from(Subscription)
        .where(Subscription.status == SubscriptionStatus.CANCELED,
               Subscription.canceled_at >= cutoff)
    ) or 0
    active_local = await db.scalar(
        select(func.count()).select_from(Subscription)
        .where(Subscription.status.in_((SubscriptionStatus.ACTIVE,
                                        SubscriptionStatus.TRIALING)))
    ) or 0
    return {
        "active_subscriptions_local": int(active_local),
        "canceled_last_30d": int(canceled_30d),
    }


@router.get("/metrics")
async def billing_metrics(admin: _Read, db: _DB) -> dict:
    """True MRR/ARR + churn + payment-failure signal from Stripe."""
    stripe_part = await _stripe_metrics()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stripe": stripe_part,
        "local": await _local_metrics(db),
    }


@router.get("/subscriptions")
async def list_subscriptions(
    admin: _Read, db: _DB,
    status: str | None = None,
    limit: int = 100,
) -> dict:
    base = (
        select(Subscription, User.email)
        .join(User, Subscription.user_id == User.id)
    )
    if status:
        base = base.where(Subscription.status == status)
    rows = await db.execute(base.order_by(Subscription.created_at.desc()).limit(limit))
    items = []
    for sub, email in rows.all():
        items.append({
            "id": str(sub.id),
            "email": email,
            "stripe_subscription_id": sub.stripe_subscription_id,
            "stripe_customer_id": sub.stripe_customer_id,
            "plan": sub.plan.value if hasattr(sub.plan, "value") else str(sub.plan),
            "status": sub.status.value if hasattr(sub.status, "value") else str(sub.status),
            "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            "cancel_at_period_end": sub.cancel_at_period_end,
            "canceled_at": sub.canceled_at.isoformat() if sub.canceled_at else None,
        })
    return {"items": items}


@router.get("/events")
async def recent_events(admin: _Read, limit: int = 50) -> dict:
    """Recent Stripe webhook deliveries — health proxy for webhook reliability."""
    if not _configured():
        return {"items": [], "error": "stripe not configured"}
    _set_key()

    def _work() -> list[dict]:
        out = []
        for ev in stripe.Event.list(limit=min(limit, 100)).auto_paging_iter():
            out.append({
                "id": _g(ev, "id"),
                "type": _g(ev, "type"),
                "livemode": bool(_g(ev, "livemode")),
                "created": int(_g(ev, "created", 0) or 0),
                "request_id": _g(_g(ev, "request"), "id"),
            })
            if len(out) >= limit:
                break
        return out

    try:
        return {"items": await asyncio.to_thread(_work)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("stripe events list failed")
        return {"items": [], "error": str(exc)[:120]}
