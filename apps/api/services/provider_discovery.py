# WebHound — apps/api/services/provider_discovery.py
# Phase 3.1 — run provider discovery (scanner package) and upsert the website's
# ProviderProfile (1:1, refreshed in place). Discovery is detection-only; it
# never triggers a scan or changes scanner findings/scoring.

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.website import Website

logger = logging.getLogger(__name__)

_STACK_FIELDS = (
    "registrar", "dns_provider", "hosting_provider",
    "cdn_provider", "waf_provider", "cms", "framework",
)


async def run_provider_discovery(db: AsyncSession, website: Website) -> ProviderProfile:
    """Discover the provider stack for *website* and upsert its ProviderProfile.

    The persisted profile (with ``detected_at``) is the durable record of the
    discovery; the 4 lifecycle events are logged via the service callback.
    Raises ImportError if the scanner package is unavailable.
    """
    # Imported lazily so the router module loads even if the scanner package
    # isn't importable in a given environment (the endpoint then 503s cleanly).
    from webhound.providers.discovery import ProviderDiscoveryService

    def _on_event(name: str, payload: dict) -> None:
        # Drop the full profile blob from the log line; keep it terse.
        safe = {k: v for k, v in payload.items() if k != "profile"}
        logger.info("provider-discovery %s: %s", name, safe)

    result = await ProviderDiscoveryService().discover(website.url, on_event=_on_event)

    now = datetime.now(timezone.utc)
    profile = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id)
    )
    if profile is None:
        profile = ProviderProfile(
            website_id=website.id,
            org_id=website.org_id,
            domain=website.hostname,
            detected_at=now,
        )
        db.add(profile)
    else:
        profile.org_id = website.org_id
        profile.domain = website.hostname
        profile.detected_at = now

    for fname in _STACK_FIELDS:
        setattr(profile, fname, getattr(result, fname))
    profile.confidence = result.confidence
    profile.evidence = list(result.evidence)

    await db.flush()
    await db.refresh(profile)
    return profile
