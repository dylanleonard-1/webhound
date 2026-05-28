# WebHound — apps/api/services/threat_intel.py
# Threat-intelligence lifecycle: upsert indicators, fast match probe,
# bulk feed import, expiry pruning.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.threat_indicator import ThreatIndicator

logger = logging.getLogger(__name__)

VALID_KINDS = ("ip", "domain", "url", "hash", "cve")
VALID_SEVERITIES = ("low", "medium", "high", "critical")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_value(kind: str, value: str) -> str:
    """Canonicalize an indicator value so dedup actually dedups across casing,
    trailing dots, schemes, etc. — minor but it matters at scale."""
    v = value.strip()
    if kind in ("domain", "url"):
        v = v.lower().rstrip(".")
    if kind == "hash":
        v = v.lower()
    return v


async def upsert_indicator(
    db: AsyncSession, *,
    kind: str, value: str, source: str,
    severity: str = "medium", confidence: int = 80,
    tags: list[str] | None = None, notes: str | None = None,
    expires_at: datetime | None = None,
) -> tuple[ThreatIndicator, bool]:
    """Upsert by (kind, value, source). Returns (row, created)."""
    if kind not in VALID_KINDS:
        raise ValueError(f"Invalid kind: {kind}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")
    confidence = max(0, min(100, int(confidence)))
    v = _normalize_value(kind, value)

    existing = await db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.kind == kind,
            ThreatIndicator.value == v,
            ThreatIndicator.source == source,
        )
    )
    now = _now()
    if existing is None:
        row = ThreatIndicator(
            kind=kind, value=v, source=source, severity=severity,
            confidence=confidence, tags=list(tags or []), notes=notes,
            first_seen_at=now, last_seen_at=now, expires_at=expires_at,
        )
        db.add(row)
        await db.flush()
        return row, True

    existing.last_seen_at = now
    existing.severity = severity
    existing.confidence = confidence
    if tags is not None:
        existing.tags = list(tags)
    if notes is not None:
        existing.notes = notes
    if expires_at is not None:
        existing.expires_at = expires_at
    await db.flush()
    return existing, False


async def delete_indicator(db: AsyncSession, indicator_id: uuid.UUID) -> bool:
    row = await db.get(ThreatIndicator, indicator_id)
    if row is None:
        return False
    await db.delete(row)
    await db.flush()
    return True


async def search(
    db: AsyncSession, *,
    kind: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    include_expired: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[ThreatIndicator], int]:
    base = select(ThreatIndicator)
    count_base = select(func.count()).select_from(ThreatIndicator)
    conds = []
    if kind:
        conds.append(ThreatIndicator.kind == kind)
    if source:
        conds.append(ThreatIndicator.source == source)
    if severity:
        conds.append(ThreatIndicator.severity == severity)
    if q:
        like = f"%{q.lower()}%"
        conds.append(sa.func.lower(ThreatIndicator.value).like(like))
    if not include_expired:
        conds.append(sa.or_(ThreatIndicator.expires_at.is_(None),
                            ThreatIndicator.expires_at > _now()))
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(ThreatIndicator.last_seen_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


async def match(
    db: AsyncSession, *, kind: str, value: str,
) -> list[ThreatIndicator]:
    """Fast lookup: is this atom flagged anywhere in our intel? Returns every
    matching row (could be flagged by multiple feeds with different
    severities). Excludes expired entries."""
    if kind not in VALID_KINDS:
        return []
    v = _normalize_value(kind, value)
    rows = await db.scalars(
        select(ThreatIndicator)
        .where(ThreatIndicator.kind == kind,
               ThreatIndicator.value == v,
               sa.or_(ThreatIndicator.expires_at.is_(None),
                      ThreatIndicator.expires_at > _now()))
        .order_by(ThreatIndicator.severity.desc())
    )
    return list(rows.all())


_BULK_THRESHOLD = 100   # below this, the per-row path is fine + clearer
_BULK_CHUNK = 1000      # one round-trip per chunk


async def import_feed(
    db: AsyncSession, *,
    source: str,
    rows: list[dict],
    default_severity: str = "medium",
    default_confidence: int = 70,
    expires_in_days: int | None = 30,
) -> dict:
    """Bulk import. Each row must have `kind` + `value`; optional `severity`,
    `confidence`, `tags`, `notes`. Returns counts (created/updated/skipped).

    For Postgres the bulk path uses INSERT ... ON CONFLICT DO UPDATE, which
    completes in one round-trip per chunk. The per-row fallback is used on
    SQLite (no equivalent ON CONFLICT against named unique constraints with
    sa.dialects.postgresql.insert) and for small feeds where readability +
    explicit (created, updated) counts matter more than throughput."""
    counts = {"created": 0, "updated": 0, "skipped": 0}
    expires_at = (_now() + timedelta(days=expires_in_days)) if expires_in_days else None

    is_pg = db.bind is not None and db.bind.dialect.name == "postgresql"
    if not is_pg or len(rows) < _BULK_THRESHOLD:
        # Per-row path — used in unit tests + small feeds. Counts created vs
        # updated precisely (the bulk path can't, without an extra query).
        for r in rows:
            try:
                kind = (r.get("kind") or "").strip()
                value = (r.get("value") or "").strip()
                if not kind or not value:
                    counts["skipped"] += 1
                    continue
                _, created = await upsert_indicator(
                    db, kind=kind, value=value, source=source,
                    severity=r.get("severity") or default_severity,
                    confidence=int(r.get("confidence") or default_confidence),
                    tags=r.get("tags") or [],
                    notes=r.get("notes"),
                    expires_at=expires_at,
                )
                counts["created" if created else "updated"] += 1
            except ValueError:
                counts["skipped"] += 1
        return counts

    # Postgres bulk path. Build payloads, validate cheaply, then
    # ON CONFLICT (kind, value, source) DO UPDATE in chunks.
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from apps.api.models.threat_indicator import ThreatIndicator

    now = _now()
    payloads: list[dict] = []
    for r in rows:
        try:
            kind = (r.get("kind") or "").strip()
            value = (r.get("value") or "").strip()
            if not kind or not value or kind not in VALID_KINDS:
                counts["skipped"] += 1
                continue
            sev = r.get("severity") or default_severity
            if sev not in VALID_SEVERITIES:
                counts["skipped"] += 1
                continue
            conf = max(0, min(100, int(r.get("confidence") or default_confidence)))
            payloads.append({
                "kind": kind,
                "value": _normalize_value(kind, value),
                "source": source,
                "severity": sev,
                "confidence": conf,
                "tags": list(r.get("tags") or []),
                "notes": r.get("notes"),
                "first_seen_at": now,
                "last_seen_at": now,
                "expires_at": expires_at,
            })
        except (ValueError, TypeError):
            counts["skipped"] += 1

    written = 0
    for i in range(0, len(payloads), _BULK_CHUNK):
        chunk = payloads[i:i + _BULK_CHUNK]
        stmt = pg_insert(ThreatIndicator).values(chunk)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_threat_indicator_kvs",
            set_={
                # On dedup hit: refresh the recency + intent fields. We leave
                # first_seen_at + tags + notes alone (the original rows are
                # the source of truth for "when we first saw this").
                "last_seen_at": stmt.excluded.last_seen_at,
                "severity": stmt.excluded.severity,
                "confidence": stmt.excluded.confidence,
                "expires_at": stmt.excluded.expires_at,
            },
        )
        await db.execute(stmt)
        written += len(chunk)

    # We can't cheaply distinguish created vs updated in one round-trip;
    # report total writes under `created` (the operationally interesting
    # number — "we ingested N rows from this feed") and leave updated=0.
    counts["created"] = written
    return counts


async def expire_stale(db: AsyncSession) -> int:
    """Delete indicators whose TTL has passed. Returns the row count."""
    result = await db.execute(
        sa.delete(ThreatIndicator).where(
            ThreatIndicator.expires_at.is_not(None),
            ThreatIndicator.expires_at <= _now(),
        )
    )
    return int(result.rowcount or 0)


def to_dict(r: ThreatIndicator) -> dict:
    return {
        "id": str(r.id),
        "kind": r.kind, "value": r.value, "source": r.source,
        "severity": r.severity, "confidence": r.confidence,
        "tags": list(r.tags or []), "notes": r.notes,
        "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
    }
