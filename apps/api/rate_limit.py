# WebHound — apps/api/security/rate_limit.py
# Redis-backed rate limiting + cooldowns.
#
# Three primitives:
#   1. RateLimiter — generic sliding-window limiter (per-IP, per-user, per-key)
#   2. Cooldown    — single-action lockout ("don't scan X again for 60s")
#   3. AuthLockout — after N failures within a window, lock the email for M
#
# All three share a single Redis connection pool.

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable

import redis.asyncio as redis_async

from apps.api.config import get_settings

_REDIS: redis_async.Redis | None = None


def _client() -> redis_async.Redis:
    """Lazy-init module-level Redis client (one per process)."""
    global _REDIS
    if _REDIS is None:
        s = get_settings()
        _REDIS = redis_async.from_url(s.redis_url, decode_responses=True)
    return _REDIS


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: int            # how many more requests in this window
    reset_seconds: int        # seconds until the sliding window slot opens


# ---------------------------------------------------------------------------
# Generic sliding-window limiter
# ---------------------------------------------------------------------------


async def check_rate(
    key: str, *, limit: int, window_seconds: int,
) -> RateDecision:
    """Sliding-window counter via Redis sorted sets.

    Each request inserts a timestamped member; old members past the window
    are pruned and the cardinality is the rolling count. O(log N) per call.
    """
    r = _client()
    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - window_seconds * 1000

    pipe = r.pipeline(transaction=False)
    pipe.zremrangebyscore(key, 0, cutoff_ms)
    pipe.zcard(key)
    pipe.zadd(key, {f"{now_ms}-{id(object())}": now_ms})
    pipe.expire(key, window_seconds + 5)
    _, count_before, _, _ = await pipe.execute()

    count_after = int(count_before) + 1
    remaining = max(0, limit - count_after)
    allowed = count_after <= limit

    return RateDecision(
        allowed=allowed,
        remaining=remaining,
        reset_seconds=window_seconds if not allowed else 0,
    )


# ---------------------------------------------------------------------------
# Single-action cooldown
# ---------------------------------------------------------------------------


async def cooldown_set(key: str, *, seconds: int) -> None:
    """Set a one-shot cooldown — any cooldown_check before expiry returns blocked."""
    r = _client()
    await r.set(key, "1", ex=seconds, nx=False)


async def cooldown_check(key: str) -> int:
    """Return remaining seconds if cooled-down, else 0."""
    r = _client()
    ttl = await r.ttl(key)
    return int(ttl) if ttl > 0 else 0


async def cooldown_acquire(key: str, *, seconds: int) -> int:
    """Atomic check-and-set: if not cooled, set it; if cooled, return TTL.

    Returns 0 when acquired (no prior cooldown) or remaining seconds when
    blocked. Use this when you want one call to both check and arm.
    """
    r = _client()
    # SET NX EX — only set if not present
    ok = await r.set(key, "1", ex=seconds, nx=True)
    if ok:
        return 0
    ttl = await r.ttl(key)
    return max(1, int(ttl))


# ---------------------------------------------------------------------------
# Auth-failure lockout
# ---------------------------------------------------------------------------


async def auth_record_failure(
    email: str, *, max_attempts: int = 5, window_seconds: int = 900,
    lock_seconds: int = 900,
) -> tuple[bool, int]:
    """Record a failed auth attempt. Return (is_locked_now, remaining_attempts).

    Window: 15 minutes. After 5 failures within the window, lock the email
    for 15 minutes. Counter resets on a successful login (call auth_clear).
    """
    r = _client()
    counter_key = f"auth:fail:{email.lower()}"
    lock_key = f"auth:lock:{email.lower()}"

    # If already locked, surface that state.
    locked_ttl = await r.ttl(lock_key)
    if locked_ttl > 0:
        return True, 0

    pipe = r.pipeline(transaction=True)
    pipe.incr(counter_key)
    pipe.expire(counter_key, window_seconds)
    count, _ = await pipe.execute()
    count = int(count)

    if count >= max_attempts:
        await r.set(lock_key, "1", ex=lock_seconds, nx=True)
        await r.delete(counter_key)
        return True, 0

    return False, max_attempts - count


async def auth_is_locked(email: str) -> int:
    """Return remaining lockout seconds (0 = not locked)."""
    r = _client()
    ttl = await r.ttl(f"auth:lock:{email.lower()}")
    return int(ttl) if ttl > 0 else 0


async def auth_clear(email: str) -> None:
    """Clear failure counter + any active lock — call after successful login."""
    r = _client()
    await r.delete(f"auth:fail:{email.lower()}", f"auth:lock:{email.lower()}")


# ---------------------------------------------------------------------------
# Helper to time-safe coroutines (mostly for tests)
# ---------------------------------------------------------------------------


def _await_in_loop(coro: Awaitable):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return loop.create_task(coro)
