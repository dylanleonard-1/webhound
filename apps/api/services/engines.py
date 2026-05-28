# WebHound — apps/api/services/engines.py
# Engine state machine + registry lifecycle. Health states are derived from
# engine_diagnostics (which already exists) plus the new engines registry row
# for maintenance + auto-disable thresholds.

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.engine import EngineRegistry
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord


# Operational state codes — UI maps these to colors. Ordered by severity.
STATE_HEALTHY = "healthy"
STATE_DEGRADED = "degraded"
STATE_UNSTABLE = "unstable"
STATE_CRITICAL = "critical"
STATE_MAINTENANCE = "maintenance"


# Default thresholds — failure_pct above each line bumps the state up one
# level. Tuned to surface real problems (sensitive_paths at 81.8% lands in
# CRITICAL immediately).
_DEGRADED_PCT  = 15.0
_UNSTABLE_PCT  = 40.0
_CRITICAL_PCT  = 70.0
_MIN_RUNS_FOR_STATE = 3   # below this we keep saying healthy (not enough data)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def compute_state(*, runs: int, failed: int, maintenance_mode: bool) -> str:
    """Map run counters → operational state. Maintenance trumps everything."""
    if maintenance_mode:
        return STATE_MAINTENANCE
    if runs < _MIN_RUNS_FOR_STATE:
        return STATE_HEALTHY
    fail_pct = 100 * failed / runs
    if fail_pct >= _CRITICAL_PCT:
        return STATE_CRITICAL
    if fail_pct >= _UNSTABLE_PCT:
        return STATE_UNSTABLE
    if fail_pct >= _DEGRADED_PCT:
        return STATE_DEGRADED
    return STATE_HEALTHY


async def get_registry(db: AsyncSession, name: str) -> EngineRegistry | None:
    return await db.scalar(select(EngineRegistry).where(EngineRegistry.name == name))


async def get_or_create_registry(db: AsyncSession, name: str) -> EngineRegistry:
    existing = await get_registry(db, name)
    if existing is not None:
        return existing
    row = EngineRegistry(name=name)
    db.add(row)
    await db.flush()
    return row


async def list_registry(db: AsyncSession) -> list[EngineRegistry]:
    rows = await db.scalars(select(EngineRegistry).order_by(EngineRegistry.name))
    return list(rows.all())


async def set_maintenance(db: AsyncSession, name: str, *,
                          on: bool, actor_email: str | None) -> EngineRegistry:
    row = await get_or_create_registry(db, name)
    row.maintenance_mode = on
    row.updated_by_email = actor_email
    if not on:
        row.auto_disabled_at = None
    await db.flush()
    return row


async def set_auto_disable_threshold(
    db: AsyncSession, name: str, *, failure_pct: int | None,
    actor_email: str | None,
) -> EngineRegistry:
    if failure_pct is not None:
        failure_pct = max(0, min(100, int(failure_pct)))
    row = await get_or_create_registry(db, name)
    row.auto_disable_at_failure_pct = failure_pct
    row.updated_by_email = actor_email
    await db.flush()
    return row


async def health_scorecards(db: AsyncSession, *, window_days: int = 7) -> list[dict]:
    """Per-engine health derived from the last `window_days` of diagnostics
    joined to the registry. The Phase 2 scorecard endpoint already returns
    similar data — this enriches it with state + maintenance + threshold."""
    since = _now() - timedelta(days=window_days)
    rows = await db.execute(
        select(
            EngineDiagnosticRecord.engine_name,
            func.count().label("runs"),
            func.sum(sa.case((EngineDiagnosticRecord.status == "failed", 1), else_=0)).label("failed"),
            func.sum(sa.case((EngineDiagnosticRecord.status == "skipped", 1), else_=0)).label("skipped"),
            func.sum(sa.case((EngineDiagnosticRecord.findings_count == 0, 1), else_=0)).label("empty"),
            func.avg(EngineDiagnosticRecord.duration_ms).label("avg_ms"),
            func.max(EngineDiagnosticRecord.duration_ms).label("max_ms"),
        )
        .where(EngineDiagnosticRecord.created_at >= since)
        .group_by(EngineDiagnosticRecord.engine_name)
    )
    rows_by_name: dict[str, dict] = {}
    for name, runs, failed, skipped, empty, avg_ms, max_ms in rows.all():
        runs = int(runs or 0)
        failed = int(failed or 0)
        skipped = int(skipped or 0)
        rows_by_name[name] = {
            "engine": name, "runs": runs, "failed": failed, "skipped": skipped,
            "empty": int(empty or 0),
            "failure_rate": round(100 * failed / runs, 1) if runs else 0,
            "empty_rate": round(100 * int(empty or 0) / runs, 1) if runs else 0,
            "avg_ms": round(float(avg_ms), 1) if avg_ms is not None else None,
            "max_ms": round(float(max_ms), 1) if max_ms is not None else None,
            "reliability": round(100 * (runs - failed - skipped) / runs, 1) if runs else None,
        }

    # Mix in registry overrides (maintenance flag, threshold).
    reg_rows = await list_registry(db)
    reg_by_name = {r.name: r for r in reg_rows}

    out: list[dict] = []
    for name, row in rows_by_name.items():
        reg = reg_by_name.get(name)
        row["maintenance_mode"] = bool(reg and reg.maintenance_mode)
        row["auto_disable_at_failure_pct"] = reg.auto_disable_at_failure_pct if reg else None
        row["state"] = compute_state(
            runs=row["runs"], failed=row["failed"],
            maintenance_mode=row["maintenance_mode"],
        )
        row["notes"] = reg.notes if reg else None
        out.append(row)

    # Also surface registry-only engines (e.g. paused before they ran).
    for name, reg in reg_by_name.items():
        if name in rows_by_name:
            continue
        out.append({
            "engine": name, "runs": 0, "failed": 0, "skipped": 0, "empty": 0,
            "failure_rate": 0, "empty_rate": 0, "avg_ms": None, "max_ms": None,
            "reliability": None, "maintenance_mode": reg.maintenance_mode,
            "auto_disable_at_failure_pct": reg.auto_disable_at_failure_pct,
            "state": STATE_MAINTENANCE if reg.maintenance_mode else STATE_HEALTHY,
            "notes": reg.notes,
        })

    # Critical first.
    state_rank = {STATE_CRITICAL: 4, STATE_UNSTABLE: 3, STATE_DEGRADED: 2,
                  STATE_MAINTENANCE: 1, STATE_HEALTHY: 0}
    out.sort(key=lambda r: state_rank.get(r["state"], 0), reverse=True)
    return out
