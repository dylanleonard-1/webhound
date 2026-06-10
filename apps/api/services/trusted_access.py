# WebHound — apps/api/services/trusted_access.py
# Phase 3.4 — Trusted Scanner Access foundation. Permission/guidance only:
# records that a verified owner intends WebHound to have trusted access, and
# returns provider-specific *guidance*. NO OAuth automation, NO token storage,
# NO secrets, NO scan-behaviour changes, NO scan gating (the only gate here is
# the precondition on CREATING the record).

from __future__ import annotations

import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import TrustedAccessMethod, TrustedAccessStatus
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.trusted_access import TrustedAccessProfile
from apps.api.models.website import DomainVerification, Website
from apps.api.models.enums import VerificationStatus
from apps.api.owned_domains import is_host_allowlisted
from apps.api.services.phase3_audit import record_phase3_event
from apps.api.services.verification import is_ownership_verified
from webhound.identity import (
    SCANNER_IP_RANGES_URL,
    SCANNER_NAME,
    SCANNER_USER_AGENT,
    SCANNER_VERIFICATION_URL,
    SCANNER_VERSION,
    SCANNER_DOCS_URL,
)

logger = logging.getLogger(__name__)

# --- audit events (logger-backed; never log tokens — there are none here) ---
TRUSTED_ACCESS_STARTED = "trusted_access.started"
TRUSTED_ACCESS_ACTIVE = "trusted_access.active"
TRUSTED_ACCESS_LIMITED = "trusted_access.limited"
TRUSTED_ACCESS_FAILED = "trusted_access.failed"
TRUSTED_ACCESS_REVOKED = "trusted_access.revoked"
TRUSTED_ACCESS_PROVIDER_GUIDANCE = "trusted_access.provider_guidance.generated"
TRUSTED_ACCESS_INTERNAL_DOMAIN = "trusted_access.internal_domain_configured"


class OwnershipRequiredError(Exception):
    code = "ownership_required"


class ProviderDiscoveryRequiredError(Exception):
    code = "provider_discovery_required"


# --- provider-specific guidance (static text — NO automation claims) --------
# recommended_action drives the dashboard; steps are the detail. Honest: we say
# "connect or configure" — we do NOT claim an automated integration exists.
_PROVIDER_GUIDANCE: dict[str, dict] = {
    "cloudflare": {
        "recommended_action": "Allowlist the WebHound scanner in Cloudflare (WAF skip rule for our User-Agent), then validate access.",
        "steps": [
            "In Cloudflare WAF, add a skip/allow rule matching the WebHound scanner User-Agent.",
            "Keep the rule scoped to WebHound — do not broaden your protections.",
            "Run coverage validation after the rule is live.",
        ],
    },
    "vercel": {
        "recommended_action": "For verified/owned domains, configure Vercel's official automation-bypass for the WebHound scanner, then validate browser access.",
        "steps": [
            "Use Vercel's official protection-bypass-for-automation mechanism (owned/verified domains only).",
            "Apply it for the WebHound scanner identity — never a blanket disable.",
            "Validate browser rendering after setup.",
        ],
    },
    "godaddy": {
        "recommended_action": "Confirm DNS ownership via GoDaddy, then validate domain access.",
        "steps": [
            "Verify ownership using the DNS TXT method (GoDaddy manages your DNS).",
            "Validate that scans reach the real site.",
        ],
    },
    "squarespace": {
        "recommended_action": "Verify ownership and validate scanner visibility — no unsafe bypass.",
        "steps": [
            "Verify ownership (meta tag is usually easiest on Squarespace).",
            "Validate scanner visibility; we never bypass platform protections.",
        ],
    },
    "wix": {
        "recommended_action": "Verify ownership and validate scanner visibility — no unsafe bypass.",
        "steps": [
            "Verify ownership (meta tag is usually easiest on Wix).",
            "Validate scanner visibility; we never bypass platform protections.",
        ],
    },
    "shopify": {
        "recommended_action": "Verify ownership and validate scanner visibility — no unsafe bypass.",
        "steps": [
            "Verify ownership of the storefront domain.",
            "Validate scanner visibility; we never bypass platform protections.",
        ],
    },
    "unknown": {
        "recommended_action": "Verify domain ownership and allowlist the WebHound scanner identity, then validate access.",
        "steps": [
            "Confirm ownership (DNS TXT / meta / .well-known).",
            "Allowlist the published WebHound scanner User-Agent.",
            "Validate that scans reach the real site.",
        ],
    },
}


def emit_trusted_access_event(
    event: str, website: Website, *, user_id=None, org_id=None,
    provider: str | None = None, status: str | None = None,
    reason: str | None = None,
) -> None:
    """Single emit seam for trusted_access.* audit events. Carries who/where for
    SOC2 'who enabled access'. NEVER logs tokens/secrets (none exist here)."""
    logger.info(
        "trusted-access-event %s user_id=%s org_id=%s domain=%s provider=%s "
        "status=%s reason=%s",
        event, user_id, org_id, website.hostname, provider, status, reason,
    )


def guidance_key(profile: ProviderProfile | None) -> str:
    """Map a ProviderProfile to a guidance key, in access-gating priority
    (WAF/CDN first, then platform, then DNS). Returns 'unknown' when none of the
    guided providers are present."""
    if profile is None:
        return "unknown"
    joined = " ".join(
        str(getattr(profile, f, None) or "").lower()
        for f in ("waf_provider", "cdn_provider", "hosting_provider", "cms", "dns_provider")
    )
    for key in ("cloudflare", "vercel", "godaddy", "squarespace", "wix", "shopify"):
        if key in joined:
            return key
    return "unknown"


def recommend_provider_guidance(profile: ProviderProfile | None) -> dict:
    key = guidance_key(profile)
    g = _PROVIDER_GUIDANCE[key]
    return {"provider": key, **g}


def is_owned_domain(hostname: str) -> bool:
    """WebHound-owned/internal domain (explicit allowlist only — reuses the
    single source: WEBHOUND_INTERNAL_SCAN_ALLOWLIST)."""
    return is_host_allowlisted(hostname)


async def get_trusted_access(db: AsyncSession, website: Website) -> TrustedAccessProfile | None:
    return await db.scalar(
        sa.select(TrustedAccessProfile).where(
            TrustedAccessProfile.website_id == website.id
        )
    )


async def start_trusted_access(
    db: AsyncSession, website: Website, *, user_id=None, org_id=None,
) -> tuple[TrustedAccessProfile, dict]:
    """Create/refresh the trusted-access record (status -> pending) for a
    VERIFIED website with a known provider, and return provider guidance.

    Raises OwnershipRequiredError / ProviderDiscoveryRequiredError on
    unmet preconditions. Does NOT mark access active (that is validation /
    admin — Phase 3.5).
    """
    if not is_ownership_verified(website):
        raise OwnershipRequiredError()

    provider_profile = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id)
    )
    if provider_profile is None:
        raise ProviderDiscoveryRequiredError()

    guidance = recommend_provider_guidance(provider_profile)
    provider = guidance["provider"]
    owned = is_owned_domain(website.hostname)
    method = (TrustedAccessMethod.INTERNAL_OWNED_DOMAIN if owned
              else TrustedAccessMethod.PROVIDER_MANUAL)

    verification = await db.scalar(
        sa.select(DomainVerification).where(
            DomainVerification.website_id == website.id,
            DomainVerification.status == VerificationStatus.VERIFIED,
        ).order_by(DomainVerification.verified_at.desc())
    )

    profile = await get_trusted_access(db, website)
    now = datetime.now(timezone.utc)
    evidence = [
        f"scanner identity {SCANNER_NAME}/{SCANNER_VERSION}",
        f"provider detected: {provider}",
    ]
    if verification is not None:
        evidence.append(f"ownership verified via {verification.method.value}")
    if owned:
        evidence.append("internal owned-domain (allowlisted)")

    if profile is None:
        profile = TrustedAccessProfile(website_id=website.id)
        db.add(profile)
    profile.org_id = org_id if org_id is not None else website.org_id
    profile.user_id = user_id if user_id is not None else website.user_id
    profile.domain = website.hostname
    profile.provider = provider
    profile.provider_profile_id = provider_profile.id
    profile.verification_id = verification.id if verification else None
    profile.scanner_identity_version = SCANNER_VERSION
    profile.scanner_user_agent = SCANNER_USER_AGENT
    # Pending on start — even owned domains do NOT jump to active (validation /
    # admin promotes to active; keeps Phase 3.5 the single 'active' gate).
    profile.access_status = TrustedAccessStatus.PENDING.value
    profile.access_method = method.value
    profile.permissions_granted = []  # nothing granted yet (pending) — never fabricated
    profile.evidence = evidence
    profile.revoked_at = None
    await db.flush()
    await db.refresh(profile)

    emit_trusted_access_event(
        TRUSTED_ACCESS_STARTED, website, user_id=user_id, org_id=org_id,
        provider=provider, status=profile.access_status, reason=method.value)
    record_phase3_event(
        db, event_type=TRUSTED_ACCESS_STARTED, website=website, actor_user_id=user_id,
        org_id=org_id, provider=provider, status=profile.access_status,
        reason=method.value, resource_type="trusted_access", resource_id=profile.id)
    emit_trusted_access_event(
        TRUSTED_ACCESS_PROVIDER_GUIDANCE, website, user_id=user_id, org_id=org_id,
        provider=provider, status=profile.access_status)
    if owned:
        emit_trusted_access_event(
            TRUSTED_ACCESS_INTERNAL_DOMAIN, website, user_id=user_id, org_id=org_id,
            provider=provider, status=profile.access_status,
            reason="internal_owned_domain")

    return profile, guidance


async def start_provider_oauth_access(
    db: AsyncSession, website: Website, *, provider: str,
    evidence: list | None = None, user_id=None, org_id=None,
) -> TrustedAccessProfile:
    """Phase 4.2 — record/refresh a provider-OAuth trusted-access profile in
    PENDING after a provider (Cloudflare) connection is verified. Reuses the
    TrustedAccessProfile model + audit seam; status stays PENDING because no
    scanner access has actually been configured yet (Phase 3.5 validation remains
    the single 'active' gate — we never claim active here)."""
    profile = await get_trusted_access(db, website)
    if profile is None:
        profile = TrustedAccessProfile(website_id=website.id)
        db.add(profile)
    profile.org_id = org_id if org_id is not None else website.org_id
    profile.user_id = user_id if user_id is not None else website.user_id
    profile.domain = website.hostname
    profile.provider = provider
    profile.scanner_identity_version = SCANNER_VERSION
    profile.scanner_user_agent = SCANNER_USER_AGENT
    profile.access_status = TrustedAccessStatus.PENDING.value
    profile.access_method = TrustedAccessMethod.PROVIDER_OAUTH.value
    profile.permissions_granted = []  # no scanner access configured yet (pending)
    profile.evidence = list(evidence or [])
    profile.revoked_at = None
    await db.flush()
    await db.refresh(profile)
    emit_trusted_access_event(
        TRUSTED_ACCESS_STARTED, website, user_id=user_id, org_id=org_id,
        provider=provider, status=profile.access_status, reason="provider_oauth")
    record_phase3_event(
        db, event_type=TRUSTED_ACCESS_STARTED, website=website, actor_user_id=user_id,
        org_id=org_id, provider=provider, status=profile.access_status,
        reason="provider_oauth", resource_type="trusted_access", resource_id=profile.id)
    return profile


async def _set_status(
    db: AsyncSession, website: Website, profile: TrustedAccessProfile,
    status: TrustedAccessStatus, event: str, *, reason: str | None = None,
    validated: bool = False, revoked: bool = False, user_id=None, org_id=None,
) -> TrustedAccessProfile:
    now = datetime.now(timezone.utc)
    profile.access_status = status.value
    if validated:
        profile.validated_at = now
    if revoked:
        profile.revoked_at = now
    await db.flush()
    await db.refresh(profile)
    emit_trusted_access_event(
        event, website, user_id=user_id, org_id=org_id,
        provider=profile.provider, status=profile.access_status, reason=reason)
    record_phase3_event(
        db, event_type=event, website=website, actor_user_id=user_id, org_id=org_id,
        provider=profile.provider, status=profile.access_status, reason=reason,
        resource_type="trusted_access", resource_id=profile.id)
    return profile


async def mark_active(db, website, profile, *, reason=None, user_id=None, org_id=None):
    """Promote to ACTIVE. The seam Phase 3.5 (coverage validation) or an admin
    calls once access is confirmed to actually work."""
    return await _set_status(db, website, profile, TrustedAccessStatus.ACTIVE,
                             TRUSTED_ACCESS_ACTIVE, reason=reason, validated=True,
                             user_id=user_id, org_id=org_id)


async def mark_limited(db, website, profile, *, reason=None, user_id=None, org_id=None):
    return await _set_status(db, website, profile, TrustedAccessStatus.LIMITED,
                             TRUSTED_ACCESS_LIMITED, reason=reason, validated=True,
                             user_id=user_id, org_id=org_id)


async def mark_failed(db, website, profile, *, reason=None, user_id=None, org_id=None):
    return await _set_status(db, website, profile, TrustedAccessStatus.FAILED,
                             TRUSTED_ACCESS_FAILED, reason=reason, validated=True,
                             user_id=user_id, org_id=org_id)


async def revoke_trusted_access(db, website, profile, *, reason=None, user_id=None, org_id=None):
    return await _set_status(db, website, profile, TrustedAccessStatus.REVOKED,
                             TRUSTED_ACCESS_REVOKED, reason=reason, revoked=True,
                             user_id=user_id, org_id=org_id)


def dashboard_view(
    profile: TrustedAccessProfile | None,
    provider_profile: ProviderProfile | None,
) -> dict:
    """Dashboard contract — works whether or not a record exists yet. When a
    record exists, guidance is keyed off the STORED provider (so callers need
    not re-pass the ProviderProfile); otherwise it's derived from it."""
    if profile is None:
        key = guidance_key(provider_profile)
        provider = key
        status = TrustedAccessStatus.NOT_CONFIGURED.value
        method = TrustedAccessMethod.UNKNOWN.value
        validated_at = None
    else:
        key = profile.provider if profile.provider in _PROVIDER_GUIDANCE else "unknown"
        provider = profile.provider
        status = profile.access_status
        method = profile.access_method
        validated_at = profile.validated_at
    g = _PROVIDER_GUIDANCE[key]
    return {
        "provider": provider,
        "status": status,
        "access_method": method,
        "recommended_action": g["recommended_action"],
        "scanner_identity_url": SCANNER_DOCS_URL,
        "verification_url": SCANNER_VERIFICATION_URL,
        "ip_ranges_url": SCANNER_IP_RANGES_URL,
        "last_validated_at": validated_at,
    }
