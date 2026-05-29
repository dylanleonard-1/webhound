# WebHound — apps/api/services/suppressions.py
# Phase-5F: suppression CRUD + matcher.

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.suppression import Suppression, SuppressionScope


class SuppressionError(ValueError):
    pass


async def create_suppression(
    db: AsyncSession,
    *,
    org_id: uuid.UUID | None,
    scope: SuppressionScope,
    pattern: str,
    reason: str,
    scanner_engine: str | None = None,
    creator_email: str | None = None,
    creator_user_id: uuid.UUID | None = None,
    expires_at: datetime | None = None,
) -> Suppression:
    pattern = (pattern or "").strip()
    reason = (reason or "").strip()
    if not pattern:
        raise SuppressionError("pattern must be non-empty")
    if not reason:
        raise SuppressionError("reason must be non-empty")
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        raise SuppressionError("expires_at must be in the future")
    s = Suppression(
        org_id=org_id, scope=scope, pattern=pattern,
        scanner_engine=scanner_engine, reason=reason,
        creator_email=creator_email,
        creator_user_id=creator_user_id,
        expires_at=expires_at, is_active=True,
    )
    db.add(s)
    await db.flush()
    return s


async def list_suppressions(
    db: AsyncSession,
    *,
    org_id: uuid.UUID | None = None,
    include_inactive: bool = False,
) -> list[Suppression]:
    stmt = sa.select(Suppression).order_by(
        Suppression.created_at.desc(),
    )
    if org_id is not None:
        stmt = stmt.where(
            sa.or_(Suppression.org_id.is_(None),
                   Suppression.org_id == org_id),
        )
    if not include_inactive:
        stmt = stmt.where(Suppression.is_active.is_(True))
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows)


async def deactivate_suppression(
    db: AsyncSession, suppression_id: uuid.UUID,
) -> Suppression | None:
    s = await db.get(Suppression, suppression_id)
    if s is None:
        return None
    s.is_active = False
    await db.flush()
    return s


# ---------------------------------------------------------------------------
# Matcher — called by the dashboard / export filters
# ---------------------------------------------------------------------------


def _hostname_matches(suppression_pattern: str, host: str) -> bool:
    p = suppression_pattern.lower().strip().lstrip(".")
    h = (host or "").lower().strip().lstrip(".")
    if not p or not h:
        return False
    if p.startswith("*."):
        suffix = p[2:]
        return h == suffix or h.endswith("." + suffix)
    return h == p or h.endswith("." + p)


def is_finding_suppressed(
    finding: dict,
    suppressions: Iterable[Suppression],
) -> Suppression | None:
    """Return the first live :class:`Suppression` matching the
    finding, or None. Accepts a *dict-shaped* finding so the matcher
    works against both ORM rows + serialised JSON without coupling
    to the scanner-side Finding pydantic model.

    The finding dict is expected to carry: ``title``, ``scanner_engine``,
    ``evidence_location`` (URL), and optional ``metadata`` (with
    ``host`` + ``registrable_domain``). Missing fields are treated as
    'no match' rather than raising."""
    title = (finding.get("title") or "").lower()
    engine = (finding.get("scanner_engine") or "").lower()
    loc = finding.get("evidence_location") or ""
    md = finding.get("metadata") or {}
    host = md.get("host") or _host_from_url(loc)
    vendor = md.get("registrable_domain") or host
    site_id = md.get("website_id") or ""

    for s in suppressions:
        if not getattr(s, "is_live", True):
            continue
        if s.scope == SuppressionScope.DOMAIN:
            if host and _hostname_matches(s.pattern, host):
                return s
        elif s.scope == SuppressionScope.VENDOR:
            if vendor and _hostname_matches(s.pattern, vendor):
                return s
        elif s.scope == SuppressionScope.FINDING_TITLE:
            if (s.scanner_engine
                    and s.scanner_engine.lower() != engine):
                continue
            if s.pattern.lower() in title:
                return s
        elif s.scope == SuppressionScope.SITE:
            if site_id and str(site_id) == s.pattern:
                return s
    return None


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""
