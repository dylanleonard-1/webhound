from __future__ import annotations

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


def generate_token() -> str:
    return f"webhound-verify={secrets.token_urlsafe(24)}"


async def get_or_create_verification(
    db: AsyncSession,
    website: Website,
    method: VerificationMethod,
) -> DomainVerification:
    existing = await db.scalar(
        sa.select(DomainVerification).where(
            DomainVerification.website_id == website.id,
            DomainVerification.method == method,
            DomainVerification.status == VerificationStatus.PENDING,
        )
    )
    if existing:
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
        _mark_verified(website, dv)
        return True

    method = dv.method
    token = dv.token

    try:
        if method == VerificationMethod.DNS_TXT:
            result = await _check_dns(website.hostname, token)
        elif method == VerificationMethod.HTML_FILE:
            result = await _check_file(website.url, token)
        else:
            result = await _check_meta(website.url, token)
    except Exception:
        result = False

    if result:
        _mark_verified(website, dv)
        await _ensure_default_schedule(db, website)
    else:
        dv.status = VerificationStatus.FAILED

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


async def _check_dns(hostname: str, token: str) -> bool:
    import dns.asyncresolver  # type: ignore[import-untyped]
    try:
        answers = await dns.asyncresolver.resolve(f"_webhound-verify.{hostname}", "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                if txt.decode("utf-8", errors="ignore") == token:
                    return True
    except Exception:
        pass
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
    return await db.scalar(
        sa.select(DomainVerification).where(
            DomainVerification.website_id == website_id,
            DomainVerification.status == VerificationStatus.PENDING,
        ).order_by(DomainVerification.created_at.desc())
    )
