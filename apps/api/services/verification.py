from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone

import httpx
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.enums import (
    ScanProfile,
    ScheduleFrequency,
    VerificationMethod,
    VerificationStatus,
)
from apps.api.models.scan_schedule import ScanSchedule
from apps.api.models.website import DomainVerification, Website
from apps.api.services.phase3_audit import record_phase3_event

logger = logging.getLogger(__name__)

# --- Phase-3.2 verification audit events ------------------------------------
# Single emit seam (emit_verification_event) so callers and tests have one
# stable hook. Logged into the standard pipeline; the DomainVerification row +
# website.verification_status are the durable state of record. A dedicated
# customer-audit table is deferred (see Phase-3.2/3.8 audit).
VERIFICATION_STARTED = "website.verification.started"
VERIFICATION_COMPLETED = "website.verification.completed"
VERIFICATION_FAILED = "website.verification.failed"
VERIFICATION_REVOKED = "website.verification.revoked"
VERIFICATION_EXPIRED = "website.verification.expired"


def emit_verification_event(
    event: str, website: Website, *,
    method: str | None = None, reason: str | None = None,
) -> None:
    """Emit a website.verification.* audit event (logger-backed)."""
    logger.info(
        "verification-event %s website_id=%s hostname=%s method=%s reason=%s",
        event, website.id, website.hostname, method, reason,
    )


class OwnershipConflictError(Exception):
    """A proof passed, but a different account already holds a VERIFIED site
    for the same (normalised) hostname. Surfaced as HTTP 409."""


def generate_token() -> str:
    return f"webhound-verify={secrets.token_urlsafe(24)}"


async def get_or_create_verification(
    db: AsyncSession,
    website: Website,
    method: VerificationMethod,
) -> DomainVerification:
    """Return an in-flight verification or issue a new token.

    Reuses any existing non-VERIFIED DV (PENDING or FAILED). This is
    important — if a previous poll-cycle marked a DV as FAILED (the bug
    fix in check_verification leaves these alone going forward, but
    older rows from before that fix still exist), we want to reuse the
    same token rather than rotate it every page-refresh. Rotating
    tokens silently broke the entire DNS flow because the user's DNS
    record still pointed at the original.
    """
    existing = await db.scalar(
        sa.select(DomainVerification).where(
            DomainVerification.website_id == website.id,
            DomainVerification.method == method,
            DomainVerification.status != VerificationStatus.VERIFIED,
        ).order_by(DomainVerification.created_at.desc())
    )
    if existing:
        # Bump back to PENDING if it was marked FAILED by an older deploy;
        # subsequent polls will continue checking against the same token.
        if existing.status != VerificationStatus.PENDING:
            existing.status = VerificationStatus.PENDING
        return existing

    dv = DomainVerification(
        website_id=website.id,
        method=method,
        token=generate_token(),
        status=VerificationStatus.PENDING,
    )
    db.add(dv)
    await db.flush()
    await db.refresh(dv)
    return dv


async def check_verification(
    db: AsyncSession,
    website: Website,
    dv: DomainVerification,
) -> bool:
    settings = get_settings()

    if settings.dev_skip_domain_verification:
        logger.warning(
            "verify: bypass via DEV_SKIP_DOMAIN_VERIFICATION for %s",
            website.hostname,
        )
        _mark_verified(website, dv)
        emit_verification_event(
            VERIFICATION_COMPLETED, website,
            method=dv.method.value, reason="dev_skip",
        )
        record_phase3_event(
            db, event_type=VERIFICATION_COMPLETED, website=website,
            actor_user_id=website.user_id, org_id=website.org_id, status="verified",
            reason="dev_skip", resource_type="domain_verification", resource_id=dv.id)
        return True

    method = dv.method
    token = dv.token
    logger.info(
        "verify: starting %s check for hostname=%s token_prefix=%s",
        method.value, website.hostname, token[:20],
    )

    try:
        if method == VerificationMethod.DNS_TXT:
            result = await _check_dns(website.hostname, token)
        elif method == VerificationMethod.HTML_FILE:
            result = await _check_file(website.url, token)
        else:
            result = await _check_meta(website.url, token)
    except Exception:
        logger.exception("verify: lookup raised for %s", website.hostname)
        result = False

    logger.info(
        "verify: %s check for hostname=%s -> %s",
        method.value, website.hostname,
        "VERIFIED" if result else "not-found",
    )

    if result:
        # Ownership-integrity guard: the proof passed, but block if a different
        # account already holds a VERIFIED site for the same hostname (apex/www
        # variants) — uq_websites_url only dedupes the exact URL.
        conflict = await _find_ownership_conflict(db, website)
        if conflict is not None:
            logger.warning(
                "verify: ownership conflict for hostname=%s — already verified "
                "under website_id=%s (different owner)",
                website.hostname, conflict.id,
            )
            emit_verification_event(
                VERIFICATION_FAILED, website,
                method=method.value, reason="ownership_conflict",
            )
            record_phase3_event(
                db, event_type=VERIFICATION_FAILED, website=website,
                actor_user_id=website.user_id, org_id=website.org_id,
                status="failed", reason="ownership_conflict",
                resource_type="domain_verification", resource_id=dv.id)
            raise OwnershipConflictError(
                "This domain is already verified under a different account."
            )
        _mark_verified(website, dv)
        await _ensure_default_schedule(db, website)
        emit_verification_event(VERIFICATION_COMPLETED, website, method=method.value)
        record_phase3_event(
            db, event_type=VERIFICATION_COMPLETED, website=website,
            actor_user_id=website.user_id, org_id=website.org_id, status="verified",
            reason=method.value, resource_type="domain_verification", resource_id=dv.id)
    else:
        emit_verification_event(
            VERIFICATION_FAILED, website,
            method=method.value, reason="proof_not_found",
        )
        record_phase3_event(
            db, event_type=VERIFICATION_FAILED, website=website,
            actor_user_id=website.user_id, org_id=website.org_id, status="failed",
            reason="proof_not_found", resource_type="domain_verification",
            resource_id=dv.id)
    # Note: we no longer mark dv.status = FAILED on a failed check.
    # Verification is a polling flow — failure on tick N just means the
    # DNS record hasn't propagated yet; we want subsequent ticks to
    # continue checking the SAME token. Previously, marking FAILED
    # caused get_or_create_verification to issue a brand-new token on
    # the next initiate call (page refresh), while the user's DNS still
    # held the original token, leading to permanent "never matches"
    # state. The token stays valid until the user actually verifies.

    return result


def _mark_verified(website: Website, dv: DomainVerification) -> None:
    dv.status = VerificationStatus.VERIFIED
    dv.verified_at = datetime.now(timezone.utc)
    website.verification_status = VerificationStatus.VERIFIED


async def _ensure_default_schedule(db: AsyncSession, website: Website) -> None:
    """Auto-create a daily continuous-monitoring schedule on first verification.

    Every user gets one scheduled scan per day per verified website,
    regardless of plan tier. The user can change frequency or disable it
    later from the dashboard's monitoring view.

    No-op if any ScanSchedule already exists for this website (handles the
    re-verification path).
    """
    from datetime import timedelta

    existing = await db.scalar(
        sa.select(ScanSchedule.id)
        .where(ScanSchedule.website_id == website.id)
        .limit(1)
    )
    if existing is not None:
        return

    # First run tomorrow at the same wall-clock time the site was verified
    # — keeps it predictable for the user, avoids stacking scans on the
    # exact verification minute across many users.
    now = datetime.now(timezone.utc)
    schedule = ScanSchedule(
        website_id=website.id,
        user_id=website.user_id,
        profile=ScanProfile.STANDARD,
        frequency=ScheduleFrequency.DAILY,
        is_enabled=True,
        use_latest_baseline=True,
        save_baseline=True,
        next_run_at=now + timedelta(days=1),
    )
    db.add(schedule)
    await db.flush()


async def mark_verified_via_provider(
    db: AsyncSession,
    website: Website,
    *,
    provider: str,
    evidence: list | None = None,
    actor_user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
) -> DomainVerification:
    """Phase 4.2 — mark ownership VERIFIED using connected-provider evidence
    (e.g. an ACTIVE Cloudflare zone the customer demonstrably controls).

    Reuses the same guards + side effects as DNS/meta/file verification: the
    cross-account ownership-conflict guard STILL runs (provider evidence must not
    let one account hijack a hostname already verified by another), the default
    monitoring schedule is ensured, and the same website.verification.* events
    fire with method ``provider_connection``. The CALLER must have already proven
    control (active-zone match) before calling this — this does not re-check the
    provider.
    """
    conflict = await _find_ownership_conflict(db, website)
    if conflict is not None:
        emit_verification_event(
            VERIFICATION_FAILED, website,
            method=VerificationMethod.PROVIDER_CONNECTION.value, reason="ownership_conflict")
        record_phase3_event(
            db, event_type=VERIFICATION_FAILED, website=website,
            actor_user_id=actor_user_id or website.user_id, org_id=org_id or website.org_id,
            status="failed", reason="ownership_conflict", resource_type="domain_verification")
        raise OwnershipConflictError(
            "This domain is already verified under a different account.")
    dv = await get_or_create_verification(db, website, VerificationMethod.PROVIDER_CONNECTION)
    _mark_verified(website, dv)
    await _ensure_default_schedule(db, website)
    emit_verification_event(
        VERIFICATION_COMPLETED, website,
        method=VerificationMethod.PROVIDER_CONNECTION.value, reason=f"provider:{provider}")
    record_phase3_event(
        db, event_type=VERIFICATION_COMPLETED, website=website,
        actor_user_id=actor_user_id or website.user_id, org_id=org_id or website.org_id,
        status="verified", reason=f"provider:{provider}",
        resource_type="domain_verification", resource_id=dv.id)
    return dv


async def _check_dns(hostname: str, token: str) -> bool:
    """Look up _webhound-verify.<hostname> TXT and match the expected token.

    Uses Cloudflare (1.1.1.1) + Google (8.8.8.8) public resolvers explicitly
    rather than the system DNS — bypasses local NXDOMAIN caching that can
    delay verification by 5+ minutes after a record is added. Per-query
    timeout 4s, total lifetime 8s.

    Some DNS providers split long TXT values into multiple chunks per
    record; we concatenate the chunks before comparing.
    """
    import dns.asyncresolver  # type: ignore[import-untyped]

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
    resolver.timeout = 4.0
    resolver.lifetime = 8.0

    record = f"_webhound-verify.{hostname}"
    try:
        answers = await resolver.resolve(record, "TXT")
    except Exception as exc:
        logger.info("verify-dns: lookup %s failed: %s", record, type(exc).__name__)
        return False

    found_strings: list[str] = []
    for rdata in answers:
        # rdata.strings is a tuple of bytes chunks for one TXT record.
        # Match either each individual chunk OR the concatenation, since
        # some providers split values at 255-char boundaries.
        chunks = [
            s.decode("utf-8", errors="ignore") for s in rdata.strings
        ]
        found_strings.extend(chunks)
        if token in chunks:
            logger.info(
                "verify-dns: %s matched (single chunk, %d records returned)",
                record, len(list(answers)),
            )
            return True
        if "".join(chunks) == token:
            logger.info("verify-dns: %s matched (concatenated chunks)", record)
            return True

    # Log what we DID find so it's clear why a non-match happened — most
    # often a copy-paste of the token with surrounding quotes or spaces.
    sample = [s[:50] for s in found_strings[:5]]
    logger.info(
        "verify-dns: %s found %d records, none matched token. samples=%s",
        record, len(found_strings), sample,
    )
    return False


async def _check_file(base_url: str, token: str) -> bool:
    url = base_url.rstrip("/") + "/.well-known/webhound-verify.txt"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url)
            return resp.is_success and resp.text.strip() == token
    except Exception:
        return False


async def _check_meta(base_url: str, token: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(base_url)
            if not resp.is_success:
                return False
            needle = f'content="{token}"'
            return needle in resp.text
    except Exception:
        return False


async def get_pending_verification(
    db: AsyncSession, website_id: uuid.UUID
) -> DomainVerification | None:
    """Return any active verification (PENDING or FAILED) for *website_id*.

    Used by /verify/check to find the DV to check against. We include
    FAILED rows so a verification that was prematurely marked FAILED by
    a prior buggy code path (now fixed in check_verification) can still
    be checked again by subsequent polls. Only VERIFIED is excluded —
    those don't need rechecking.
    """
    return await db.scalar(
        sa.select(DomainVerification).where(
            DomainVerification.website_id == website_id,
            DomainVerification.status != VerificationStatus.VERIFIED,
        ).order_by(DomainVerification.created_at.desc())
    )


# --- Phase-3.2 ownership gate, recommendation, revoke -----------------------

def is_ownership_verified(website: Website) -> bool:
    """True only when ownership is currently proven. PENDING / FAILED /
    EXPIRED / REVOKED / UNVERIFIED all count as not-verified. This is the
    single gate for advanced actions (deep scan, monitoring, baselines, WADE,
    trusted scanner access)."""
    return website.verification_status == VerificationStatus.VERIFIED


def recommend_verification(provider_profile: object | None) -> dict:
    """Order the (always-valid) verification methods using the Phase-3.1
    ProviderProfile when present. Hosted site builders often lock raw DNS but
    allow markup injection, so a meta tag is the smoother path there."""
    all_methods = [
        VerificationMethod.DNS_TXT,
        VerificationMethod.META_TAG,
        VerificationMethod.HTML_FILE,
    ]
    recommended = VerificationMethod.DNS_TXT
    cms = (getattr(provider_profile, "cms", None) or "").lower()
    if cms in {"wix", "squarespace", "shopify"}:
        recommended = VerificationMethod.META_TAG
    return {
        "recommended_method": recommended.value,
        "fallback_methods": [m.value for m in all_methods if m != recommended],
    }


async def revoke_verification(db: AsyncSession, website: Website) -> None:
    """Owner withdraws verified access: mark REVOKED and pause (not delete) any
    monitoring schedules. Advanced actions are blocked thereafter via
    is_ownership_verified."""
    website.verification_status = VerificationStatus.REVOKED
    await db.execute(
        sa.update(ScanSchedule)
        .where(ScanSchedule.website_id == website.id)
        .values(is_enabled=False)
    )
    emit_verification_event(VERIFICATION_REVOKED, website)
    record_phase3_event(
        db, event_type=VERIFICATION_REVOKED, website=website,
        actor_user_id=website.user_id, org_id=website.org_id, status="revoked")


def _normalize_hostname(hostname: str) -> str:
    return (hostname or "").strip().lower().removeprefix("www.")


async def _find_ownership_conflict(
    db: AsyncSession, website: Website,
) -> Website | None:
    """Another user's already-VERIFIED website for the same normalised hostname
    (apex/www variants), or None. Guards against two accounts each 'owning' the
    same site via http/https/www URL variants."""
    base = _normalize_hostname(website.hostname)
    variants = [base, f"www.{base}"]
    return await db.scalar(
        sa.select(Website).where(
            Website.id != website.id,
            Website.user_id != website.user_id,
            Website.verification_status == VerificationStatus.VERIFIED,
            sa.func.lower(Website.hostname).in_(variants),
        ).limit(1)
    )
