# WebHound — apps/api/services/maintenance.py
# Redis-backed maintenance-mode flag. When engaged, the MaintenanceModeMiddleware
# returns 503 for write paths that would queue scan work, so staff can do
# infra-affecting changes without losing scan jobs mid-flight.

from __future__ import annotations

import logging

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

MAINTENANCE_FLAG_KEY = "webhound:maintenance_mode"
MAINTENANCE_REASON_KEY = "webhound:maintenance_mode:reason"


async def is_active() -> bool:
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            return bool(await r.exists(MAINTENANCE_FLAG_KEY))
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        # Fail open: if Redis is unreachable we don't want to brick the API.
        return False


async def status() -> dict:
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1,
                              decode_responses=True)
        try:
            on = bool(await r.exists(MAINTENANCE_FLAG_KEY))
            reason = (await r.get(MAINTENANCE_REASON_KEY)) if on else None
            return {"active": on, "reason": reason}
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        return {"active": False, "reason": None, "error": "redis unavailable"}


async def engage(reason: str | None) -> None:
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            await r.set(MAINTENANCE_FLAG_KEY, "1")
            if reason:
                await r.set(MAINTENANCE_REASON_KEY, reason)
            else:
                await r.delete(MAINTENANCE_REASON_KEY)
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        logger.warning("maintenance engage failed (redis unreachable)")


async def disengage() -> None:
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=1)
        try:
            await r.delete(MAINTENANCE_FLAG_KEY, MAINTENANCE_REASON_KEY)
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        logger.warning("maintenance disengage failed (redis unreachable)")
