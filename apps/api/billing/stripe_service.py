# WebHound — apps/api/billing/stripe_service.py
# Stripe SDK wrapper. Two responsibilities:
#   1. Lazily set the stripe.api_key from settings.
#   2. Provide thin helpers for the operations the routes need
#      (create checkout session, create portal session, verify webhook).
#
# Webhook event handling lives in webhook_handler.py — this file is just
# the SDK boundary.

from __future__ import annotations

from typing import Any

import stripe

from apps.api.billing.plans import get_plan
from apps.api.config import get_settings
from apps.api.models.enums import PlanTier


def _ensure_configured() -> None:
    s = get_settings()
    if not s.stripe_secret_key:
        raise RuntimeError(
            "Stripe is not configured: set STRIPE_SECRET_KEY in env."
        )
    if stripe.api_key != s.stripe_secret_key:
        stripe.api_key = s.stripe_secret_key


def _price_id_for(tier: PlanTier, cadence: str) -> str:
    """Look up the Stripe price ID for a tier + cadence ('monthly' | 'yearly')."""
    plan = get_plan(tier)
    price_id = (plan.stripe_price_id_monthly if cadence == "monthly"
                else plan.stripe_price_id_yearly)
    if not price_id:
        raise ValueError(
            f"No Stripe price ID configured for {tier.value} {cadence}. "
            f"Set STRIPE_PRICE_{tier.value.upper()}_{cadence.upper()} in env."
        )
    return price_id


async def get_or_create_customer(
    *, email: str, user_id: str, existing_customer_id: str | None,
) -> str:
    """Return the user's Stripe customer ID, creating one if needed."""
    _ensure_configured()
    if existing_customer_id:
        return existing_customer_id
    customer = stripe.Customer.create(
        email=email,
        metadata={"webhound_user_id": user_id},
    )
    return customer.id


def create_checkout_session(
    *,
    customer_id: str,
    tier: PlanTier,
    cadence: str,
    success_url: str,
    cancel_url: str,
    user_id: str,
) -> dict[str, Any]:
    """Create a Stripe Checkout session and return its URL + id."""
    _ensure_configured()
    price_id = _price_id_for(tier, cadence)
    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        allow_promotion_codes=True,
        subscription_data={
            "metadata": {
                "webhound_user_id": user_id,
                "webhound_tier": tier.value,
            },
        },
        metadata={
            "webhound_user_id": user_id,
            "webhound_tier": tier.value,
        },
    )
    return {"id": session.id, "url": session.url}


def create_portal_session(
    *, customer_id: str, return_url: str,
) -> dict[str, Any]:
    """Create a Stripe Customer Portal session for subscription management."""
    _ensure_configured()
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )
    return {"id": session.id, "url": session.url}


def verify_webhook_signature(
    *, payload: bytes, signature: str | None,
) -> stripe.Event:
    """Validate the stripe-signature header and parse the event.

    Raises stripe.SignatureVerificationError on tamper / replay.
    """
    _ensure_configured()
    s = get_settings()
    if not s.stripe_webhook_secret:
        raise RuntimeError(
            "Stripe webhook secret not configured: set STRIPE_WEBHOOK_SECRET."
        )
    if not signature:
        raise stripe.SignatureVerificationError(
            "Missing stripe-signature header", payload, signature,
        )
    return stripe.Webhook.construct_event(
        payload=payload, sig_header=signature,
        secret=s.stripe_webhook_secret,
    )


def price_id_to_tier(price_id: str | None) -> PlanTier:
    """Reverse-lookup a Stripe price ID to a tier — used by webhook handler."""
    if not price_id:
        return PlanTier.FREE
    for tier, plan in __import__(
        "apps.api.billing.plans", fromlist=["PLAN_DEFINITIONS"]
    ).PLAN_DEFINITIONS.items():
        if price_id in (plan.stripe_price_id_monthly, plan.stripe_price_id_yearly):
            return tier
    return PlanTier.FREE
