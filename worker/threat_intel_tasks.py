from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Iterable

import httpx

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)


# Opt-in by default — fetching public threat feeds is harmless but we don't
# want a surprise outbound HTTP burst on the first deploy after this lands.
# Set WEBHOUND_THREAT_FEEDS_ENABLED=1 on the worker service to turn it on.
_ENABLED_ENV = "WEBHOUND_THREAT_FEEDS_ENABLED"

# Conservative defaults — two well-known open feeds, no API keys, one
# indicator per line. Each tuple is (source_name, kind, url, severity).
# Edit via WEBHOUND_THREAT_FEEDS (json) if you want to override.
_DEFAULT_FEEDS: list[tuple[str, str, str, str]] = [
    ("emerging_threats_compromised", "ip",
     "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "high"),
    ("blocklist_de", "ip",
     "https://lists.blocklist.de/lists/all.txt", "medium"),
]

_HTTP_TIMEOUT_S = 20
_MAX_INDICATORS_PER_FEED = 50_000   # safety net — clip pathological feeds
_TTL_DAYS = 30

# Matches an IPv4 address. We deliberately skip CIDR ranges, IPv6, etc. —
# the threat_indicator model stores individual atoms and our match() helper
# does exact lookups, so a /24 would be 256 useless rows.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _enabled() -> bool:
    return os.getenv(_ENABLED_ENV, "").lower() in ("1", "true", "yes")


def _parse_lines(body: str) -> Iterable[str]:
    """Generic one-atom-per-line parser. Strips comments + whitespace."""
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            yield line


@celery.task(name="worker.threat_intel_tasks.import_threat_feeds")
def import_threat_feeds() -> dict:
    """Pull configured public threat feeds and upsert into threat_indicators.

    Fires weekly via beat (Sunday 03:15 UTC). Opt-in via
    WEBHOUND_THREAT_FEEDS_ENABLED=1. Returns per-feed counts."""
    if not _enabled():
        logger.info("threat-intel auto-import is disabled (set %s=1 to enable)", _ENABLED_ENV)
        return {"enabled": False, "feeds": []}
    try:
        return asyncio.run(_run())
    except Exception:
        logger.exception("import_threat_feeds failed")
        raise


async def _fetch(url: str) -> str | None:
    """Fetch one feed body. Best-effort: a slow/down feed shouldn't block
    the rest of the run."""
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": "WebHound-ThreatIntel/1.0"})
        if r.status_code != 200:
            logger.warning("feed %s returned %s", url, r.status_code)
            return None
        return r.text
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed %s fetch failed: %s", url, exc)
        return None


async def _run() -> dict:
    import apps.api.models  # noqa: F401 — register models
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from apps.api.services import threat_intel as ti_svc

    out: dict = {"enabled": True, "feeds": []}
    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        for source, kind, url, severity in _DEFAULT_FEEDS:
            body = await _fetch(url)
            if body is None:
                out["feeds"].append({"source": source, "url": url, "error": "fetch_failed"})
                continue
            rows: list[dict] = []
            for line in _parse_lines(body):
                if kind == "ip" and not _IPV4_RE.match(line):
                    continue   # skip ranges / IPv6 / garbage lines
                rows.append({"kind": kind, "value": line})
                if len(rows) >= _MAX_INDICATORS_PER_FEED:
                    break
            if not rows:
                out["feeds"].append({"source": source, "url": url,
                                     "created": 0, "updated": 0, "skipped": 0,
                                     "note": "feed empty after parse"})
                continue
            async with factory() as db:
                counts = await ti_svc.import_feed(
                    db, source=source, rows=rows,
                    default_severity=severity, default_confidence=65,
                    expires_in_days=_TTL_DAYS,
                )
                await db.commit()
            out["feeds"].append({"source": source, "url": url,
                                 "total_parsed": len(rows), **counts})
            logger.info("threat-intel feed %s: %s", source, counts)
    finally:
        await engine.dispose()
    return out
