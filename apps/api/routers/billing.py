from __future__ import annotations

import logging
from typing import Annotated

import sqlalchemy as sa
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing import stripe_service
from apps.api.billing.plans import PLAN_DEFINITIONS, plan_for_route_display
from apps.api.billing.quota import (
    QuotaViolation,
)
from apps.api.billing.webhook_handler import (
    _on_subscription_upsert,
    handle_stripe_event,
    to_plain_dict,
)
from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.models.enums import PlanTier, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.subscription import Subscription
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CheckoutSessionRequest(BaseModel):
    tier: PlanTier
    success_path: str = "/dashboard/billing/success"
    cancel_path: str = "/pricing?status=cancelled"


class CheckoutSessionResponse(BaseModel):
    id: str
    url: str


class PortalSessionRequest(BaseModel):
    return_path: str = "/dashboard/settings?tab=billing"


class PortalSessionResponse(BaseModel):
    id: str
    url: str


class PlanResponse(BaseModel):
    tier: str
    name: str
    tagline: str
    price_usd_monthly: int
    max_websites: int
    scans_per_month: int
    scan_history_days: int
    max_concurrent_scans: int
    monitoring_enabled: bool
    monitoring_min_frequency: str
    exports_enabled: bool
    alerts_enabled: bool
    threat_intel_external: bool
    team_seats: int
    api_access: bool
    is_popular: bool
    cta_label: str
    sort_order: int
    features: list[dict]


class CurrentPlanUsage(BaseModel):
    websites_used: int
    websites_limit: int
    scans_used_30d: int
    scans_limit: int


class CurrentSubscriptionResponse(BaseModel):
    plan: str                         # current PlanTier
    status: str | None                # current Stripe subscription status, if any
    current_period_end: str | None
    cancel_at_period_end: bool
    usage: CurrentPlanUsage


# ---------------------------------------------------------------------------
# Public — list plans (no auth required so the marketing pricing page works)
# ---------------------------------------------------------------------------


@router.get("/plans", response_model=list[PlanResponse])
async def list_plans() -> list[dict]:
    return [
        plan_for_route_display(tier)
        for tier in sorted(PLAN_DEFINITIONS, key=lambda t: PLAN_DEFINITIONS[t].sort_order)
    ]


# ---------------------------------------------------------------------------
# Authenticated — current plan + usage
# ---------------------------------------------------------------------------


@router.get("/subscription", response_model=CurrentSubscriptionResponse)
async def get_current_subscription(
    db: _DB, current_user: _CurrentUser,
) -> CurrentSubscriptionResponse:
    from datetime import datetime, timedelta, timezone
    window_start = datetime.now(timezone.utc) - timedelta(days=30)

    sub = await db.scalar(
        sa.select(Subscription)
        .where(Subscription.user_id == current_user.id)
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    websites_used = await db.scalar(
        sa.select(sa.func.count()).select_from(Website)
        .where(Website.user_id == current_user.id)
    ) or 0
    scans_used = await db.scalar(
        sa.select(sa.func.count()).select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .where(Website.user_id == current_user.id)
        .where(ScanJob.created_at >= window_start)
    ) or 0

    plan_def = PLAN_DEFINITIONS[current_user.plan]
    return CurrentSubscriptionResponse(
        plan=current_user.plan.value,
        status=sub.status.value if sub else None,
        current_period_end=(
            sub.current_period_end.isoformat() if sub and sub.current_period_end
            else None
        ),
        cancel_at_period_end=sub.cancel_at_period_end if sub else False,
        usage=CurrentPlanUsage(
            websites_used=int(websites_used),
            websites_limit=plan_def.max_websites,
            scans_used_30d=int(scans_used),
            scans_limit=plan_def.scans_per_month,
        ),
    )


# ---------------------------------------------------------------------------
# Authenticated — reconcile from Stripe (self-service, post-checkout)
# ---------------------------------------------------------------------------
#
# The webhook is the steady-state path that keeps plan state current, but it
# can be missed: in test mode without a configured webhook endpoint, during
# downtime, or after a secret rotation. When that happens the user completes
# checkout, gets redirected back, and the dashboard still shows their old plan
# because nothing ever updated users.plan.
#
# This route pulls the caller's own latest Stripe subscription and replays it
# through the exact same upsert the webhook uses, so access updates
# immediately and deterministically without depending on webhook delivery.
# The success redirect calls this before reading /subscription.


@router.post("/sync", response_model=CurrentSubscriptionResponse)
async def sync_subscription(
    db: _DB, current_user: _CurrentUser,
) -> CurrentSubscriptionResponse:
    settings = get_settings()
    if settings.stripe_secret_key and current_user.stripe_customer_id:
        stripe.api_key = settings.stripe_secret_key
        try:
            subs = stripe.Subscription.list(
                customer=current_user.stripe_customer_id, status="all", limit=10,
            )
        except stripe.StripeError as exc:
            # Don't fail the request — fall through to the plain DB read so the
            # dashboard still renders. Worst case the user sees stale state.
            logger.warning(
                "billing sync stripe lookup failed for %s: %s",
                current_user.id, exc,
            )
            subs = None
        if subs and subs.data:
            latest = sorted(subs.data, key=lambda s: s["created"], reverse=True)[0]
            await _on_subscription_upsert(db, to_plain_dict(latest))
            await db.commit()

    return await get_current_subscription(db, current_user)


# ---------------------------------------------------------------------------
# Authenticated — start checkout
# ---------------------------------------------------------------------------


@router.post("/checkout-session", response_model=CheckoutSessionResponse)
async def create_checkout_session(
    data: CheckoutSessionRequest, db: _DB, current_user: _CurrentUser,
) -> CheckoutSessionResponse:
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail="Stripe is not configured on this server.",
        )
    if data.tier == PlanTier.FREE:
        raise HTTPException(
            status_code=400,
            detail="Free plan does not need a checkout session.",
        )
    try:
        customer_id = await stripe_service.get_or_create_customer(
            email=current_user.email,
            user_id=str(current_user.id),
            existing_customer_id=current_user.stripe_customer_id,
        )
        if not current_user.stripe_customer_id:
            current_user.stripe_customer_id = customer_id
            await db.commit()
        session = stripe_service.create_checkout_session(
            customer_id=customer_id,
            tier=data.tier,
            success_url=f"{settings.frontend_url}{data.success_path}",
            cancel_url=f"{settings.frontend_url}{data.cancel_path}",
            user_id=str(current_user.id),
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except stripe.StripeError as exc:
        logger.warning("stripe checkout failed for %s: %s", current_user.id, exc)
        raise HTTPException(status_code=502, detail="Stripe API call failed.")
    return CheckoutSessionResponse(id=session["id"], url=session["url"])


# ---------------------------------------------------------------------------
# Authenticated — portal session
# ---------------------------------------------------------------------------


@router.post("/portal-session", response_model=PortalSessionResponse)
async def create_portal_session(
    data: PortalSessionRequest, current_user: _CurrentUser,
) -> PortalSessionResponse:
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail="Stripe is not configured on this server.",
        )
    if not current_user.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail=(
                "No Stripe customer linked to this account yet. Upgrade "
                "through checkout first."
            ),
        )
    try:
        session = stripe_service.create_portal_session(
            customer_id=current_user.stripe_customer_id,
            return_url=f"{settings.frontend_url}{data.return_path}",
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except stripe.StripeError as exc:
        logger.warning("stripe portal failed for %s: %s", current_user.id, exc)
        raise HTTPException(status_code=502, detail="Stripe API call failed.")
    return PortalSessionResponse(id=session["id"], url=session["url"])


# ---------------------------------------------------------------------------
# Webhook — verifies stripe-signature, dispatches to handler
# ---------------------------------------------------------------------------


@router.post("/webhook")
async def stripe_webhook(request: Request, db: _DB) -> dict[str, str]:
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe_service.verify_webhook_signature(
            payload=payload, signature=sig,
        )
    except (stripe.SignatureVerificationError, ValueError) as exc:
        logger.warning("stripe webhook signature verification failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid signature")
    except RuntimeError as exc:
        # Webhook secret not configured — still a 503 (server config issue)
        logger.error("stripe webhook misconfigured: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))

    # stripe.Event is a StripeObject — supports subscript access, not .get().
    event_type = event["type"] if "type" in event else "?"
    try:
        await handle_stripe_event(db, event)
        await db.commit()
    except Exception:
        logger.exception("stripe webhook handler error: %s", event_type)
        # Return 200 anyway — Stripe will retry on non-2xx, but our DB state
        # might already be partially updated; surfacing a 500 risks an
        # infinite retry loop. Log and move on.

    return {"received": "ok"}


# ---------------------------------------------------------------------------
# Admin — manual re-sync from Stripe
# ---------------------------------------------------------------------------
#
# When a Stripe webhook is missed (endpoint not configured, downtime, secret
# rotation, etc.) the DB lags Stripe and the user sees the wrong plan. This
# route fetches the named user's most recent Stripe subscription and replays
# it through the same handler the webhook would have, getting the DB back in
# sync without waiting for the next billing event.


class ResyncRequest(BaseModel):
    email: str


@router.post("/admin/resync")
async def admin_resync(
    data: ResyncRequest, db: _DB, current_user: _CurrentUser,
) -> dict:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Stripe not configured")

    target = await db.scalar(sa.select(User).where(User.email == data.email))
    if target is None:
        raise HTTPException(status_code=404, detail=f"User not found: {data.email}")
    if not target.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{data.email} has no Stripe customer linked. They need to "
                "complete checkout at least once before a resync is possible."
            ),
        )

    stripe.api_key = settings.stripe_secret_key
    try:
        subs = stripe.Subscription.list(
            customer=target.stripe_customer_id, status="all", limit=10,
        )
    except stripe.StripeError as exc:
        logger.warning("admin resync stripe lookup failed: %s", exc)
        raise HTTPException(status_code=502, detail="Stripe API call failed.")

    if not subs.data:
        raise HTTPException(
            status_code=404,
            detail="No Stripe subscriptions found for this customer.",
        )

    # Pick the most recently created subscription Stripe knows about and run
    # it through the same upsert path the webhook would have used. Convert to
    # a plain dict first — the handler uses .get() and a raw StripeObject has
    # tripped that before.
    latest = sorted(subs.data, key=lambda s: s["created"], reverse=True)[0]
    await _on_subscription_upsert(db, to_plain_dict(latest))
    await db.commit()

    return {
        "ok": True,
        "user_email": data.email,
        "subscription_id": latest["id"],
        "status": latest["status"],
    }


# ---------------------------------------------------------------------------
# Helpers — admin-only debug
# ---------------------------------------------------------------------------


def _violation_response(v: QuotaViolation) -> dict:
    """Used by routes that need to manually surface a quota response."""
    return {
        "error": "quota_exceeded",
        "limit_name": v.limit_name,
        "limit_value": v.limit_value,
        "current_value": v.current_value,
        "current_plan": v.plan.value,
        "upgrade_to": v.upgrade_to.value if v.upgrade_to else None,
        "message": v.message,
    }
