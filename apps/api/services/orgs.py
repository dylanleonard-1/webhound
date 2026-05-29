# WebHound — apps/api/services/orgs.py
# Phase-4 multi-tenancy service layer.
#
# Helper primitives for org creation, membership management, and
# role-based access checks. Intentionally minimal in this first slice —
# enough to start populating ``org_id`` on new rows and to gate the
# next admin-panel pages, but not enough on its own to enforce tenant
# isolation across every query (that's the cutover migration, which
# also flips ``org_id NOT NULL``).
#
# Role semantics live in ``models.enums.OrgRole`` / ``ORG_ROLE_RANK``.

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import (
    ORG_ROLE_RANK,
    OrgRole,
    PlanTier,
)
from apps.api.models.org import Org, OrgMembership


_SLUG_OK = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class OrgServiceError(ValueError):
    """Raised for invalid org input (bad slug, duplicate membership, etc.)."""


def normalize_slug(raw: str) -> str:
    """Lowercase, hyphenate, strip. Returns the canonical slug or raises
    ``OrgServiceError`` if the input can't be turned into a valid one."""
    slug = (raw or "").strip().lower()
    slug = re.sub(r"[^a-z0-9-]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    if not _SLUG_OK.match(slug):
        raise OrgServiceError(
            "slug must be lowercase letters / digits / hyphens, "
            "1-63 chars, not starting or ending with a hyphen",
        )
    return slug


async def create_org(
    db: AsyncSession,
    *,
    name: str,
    slug: str,
    owner_user_id: uuid.UUID,
    billing_email: str | None = None,
    plan_tier: PlanTier = PlanTier.FREE,
) -> Org:
    """Create a new org and add the founder as :class:`OrgRole.OWNER`.

    The founder's membership is auto-accepted (``accepted_at=now``) so
    they don't need to "accept their own invite". Raises if the slug is
    invalid or already in use."""
    canonical_slug = normalize_slug(slug)
    existing = await db.execute(
        sa.select(Org).where(Org.slug == canonical_slug),
    )
    if existing.scalar_one_or_none() is not None:
        raise OrgServiceError(f"org slug '{canonical_slug}' already taken")

    org = Org(
        slug=canonical_slug,
        name=name.strip(),
        billing_email=(billing_email or None),
        plan_tier=plan_tier,
        is_active=True,
    )
    db.add(org)
    await db.flush()

    membership = OrgMembership(
        org_id=org.id,
        user_id=owner_user_id,
        role=OrgRole.OWNER,
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()
    return org


async def add_membership(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    role: OrgRole = OrgRole.VIEWER,
    invited_by_user_id: uuid.UUID | None = None,
    auto_accept: bool = False,
) -> OrgMembership:
    """Add a member to an org. Idempotent on (org_id, user_id) — if a
    membership already exists, this raises rather than silently
    upgrading the role (which would be a confusing privilege change)."""
    existing = await db.execute(
        sa.select(OrgMembership).where(
            OrgMembership.org_id == org_id,
            OrgMembership.user_id == user_id,
        ),
    )
    if existing.scalar_one_or_none() is not None:
        raise OrgServiceError("user is already a member of this org")

    m = OrgMembership(
        org_id=org_id,
        user_id=user_id,
        role=role,
        invited_by_user_id=invited_by_user_id,
        accepted_at=(datetime.now(timezone.utc) if auto_accept else None),
    )
    db.add(m)
    await db.flush()
    return m


async def get_membership(
    db: AsyncSession,
    *, org_id: uuid.UUID, user_id: uuid.UUID,
) -> OrgMembership | None:
    """Fetch a single membership. Returns ``None`` when the user isn't
    a member or has only a pending (unaccepted) invite."""
    res = await db.execute(
        sa.select(OrgMembership).where(
            OrgMembership.org_id == org_id,
            OrgMembership.user_id == user_id,
            OrgMembership.accepted_at.is_not(None),
        ),
    )
    return res.scalar_one_or_none()


async def list_user_orgs(
    db: AsyncSession, user_id: uuid.UUID,
) -> list[tuple[Org, OrgRole]]:
    """Return every org the user belongs to (accepted memberships only)
    paired with their effective role. Ordered by org name."""
    rows = await db.execute(
        sa.select(Org, OrgMembership.role)
        .join(OrgMembership, OrgMembership.org_id == Org.id)
        .where(
            OrgMembership.user_id == user_id,
            OrgMembership.accepted_at.is_not(None),
            Org.is_active.is_(True),
        )
        .order_by(Org.name),
    )
    return [(org, role) for org, role in rows.all()]


def has_org_role(actual: OrgRole | None, minimum: OrgRole) -> bool:
    """``True`` iff ``actual`` is at least ``minimum`` by privilege rank.

    OWNER implicitly satisfies every check. ``None`` (no membership)
    always returns ``False`` — convenient for the common ``has_org_role(
    role_or_none, OrgRole.ANALYST)`` pattern."""
    if actual is None:
        return False
    return ORG_ROLE_RANK[actual] >= ORG_ROLE_RANK[minimum]


async def check_ownership(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID | None,
    minimum_role: OrgRole = OrgRole.VIEWER,
) -> bool:
    """Look up the user's role in the given org and return whether they
    meet ``minimum_role``.

    ``org_id=None`` returns ``True`` — the caller is operating on a row
    that doesn't have an org yet (single-tenant legacy path). This is
    the intentionally permissive behaviour during the additive scaffold
    phase; the cutover migration removes the None branch."""
    if org_id is None:
        return True
    membership = await get_membership(db, org_id=org_id, user_id=user_id)
    if membership is None:
        return False
    return has_org_role(membership.role, minimum_role)
