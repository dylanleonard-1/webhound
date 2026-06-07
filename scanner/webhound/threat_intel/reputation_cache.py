# WebHound — scanner/webhound/threat_intel/reputation_cache.py
# Phase-13: a small TTL cache for reputation verdicts so repeated lookups
# within a scan (and across scans, if the caller persists it) are cheap
# and STABLE — a domain shouldn't flip verdict between two pages of the
# same scan. Pure in-memory; serializable for cross-scan reuse.

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_TTL = 3600.0       # 1 hour


@dataclass
class _Entry:
    value: dict[str, Any]
    expires_at: float


class ReputationCache:
    """Keyed TTL cache. Keys are namespaced ('domain:evil.com',
    'script:<hash>') so domain and script verdicts never collide."""

    def __init__(self, ttl_seconds: float = _DEFAULT_TTL) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, _Entry] = {}
        self.hits = 0
        self.misses = 0

    def _now(self) -> float:
        return time.time()

    def get(self, key: str) -> dict[str, Any] | None:
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return None
        if entry.expires_at <= self._now():
            self._store.pop(key, None)
            self.misses += 1
            return None
        self.hits += 1
        return entry.value

    def put(self, key: str, value: dict[str, Any],
            ttl_seconds: float | None = None) -> None:
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        self._store[key] = _Entry(value=value,
                                  expires_at=self._now() + ttl)

    def get_or_compute(self, key: str, compute) -> dict[str, Any]:
        cached = self.get(key)
        if cached is not None:
            return cached
        value = compute()
        self.put(key, value)
        return value

    def purge_expired(self) -> int:
        now = self._now()
        expired = [k for k, e in self._store.items() if e.expires_at <= now]
        for k in expired:
            self._store.pop(k, None)
        return len(expired)

    @property
    def size(self) -> int:
        return len(self._store)

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "size": self.size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }

    # Serialization for cross-scan reuse (TTL-relative → absolute is
    # preserved as remaining seconds so a reload doesn't resurrect stale
    # entries).
    def to_dict(self) -> dict[str, Any]:
        now = self._now()
        return {
            "ttl": self._ttl,
            "entries": {
                k: {"value": e.value,
                    "remaining": round(max(0.0, e.expires_at - now), 1)}
                for k, e in self._store.items()
                if e.expires_at > now
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ReputationCache":
        cache = cls(ttl_seconds=float((data or {}).get("ttl", _DEFAULT_TTL)))
        now = cache._now()
        for k, rec in (data or {}).get("entries", {}).items():
            remaining = float(rec.get("remaining", 0))
            if remaining > 0:
                cache._store[k] = _Entry(value=rec.get("value", {}),
                                         expires_at=now + remaining)
        return cache
