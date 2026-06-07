# WebHound — scanner/webhound/threat_intel/feed_manager.py
# Phase-13 Task 1: hold normalized indicators from many feeds and answer
# "is this host / url / script-hash a known indicator?" with the merged,
# deduplicated verdict + per-feed confidence.
#
# Offline by design — feeds are INGESTED (already-fetched payloads handed
# in), not fetched here. A scan consults the manager; live provider
# lookups remain the job of enrichment_service (operator-gated).

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

from webhound.threat_intel.feed_normalizer import (
    IndicatorKind,
    ThreatCategory,
    ThreatIndicator,
    dedupe,
)


def _host(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    return v.split("/", 1)[0]


@dataclass
class FeedMatch:
    """The verdict for one looked-up indicator."""

    matched: bool
    value: str
    indicators: list[ThreatIndicator] = field(default_factory=list)

    @property
    def max_confidence(self) -> float:
        return max((i.confidence for i in self.indicators), default=0.0)

    @property
    def category(self) -> ThreatCategory:
        if not self.indicators:
            return ThreatCategory.UNKNOWN
        # Most-severe category wins.
        order = [ThreatCategory.SKIMMER, ThreatCategory.MALWARE,
                 ThreatCategory.PHISHING, ThreatCategory.SCAM,
                 ThreatCategory.ABUSE, ThreatCategory.SUSPICIOUS,
                 ThreatCategory.UNKNOWN]
        for c in order:
            if any(i.category == c for i in self.indicators):
                return c
        return ThreatCategory.UNKNOWN

    @property
    def sources(self) -> list[str]:
        seen: list[str] = []
        for i in self.indicators:
            for s in i.source.split("+"):
                if s not in seen:
                    seen.append(s)
        return seen

    def to_dict(self) -> dict:
        return {
            "matched": self.matched,
            "value": self.value,
            "max_confidence": round(self.max_confidence, 3),
            "category": self.category.value,
            "sources": self.sources,
            "indicators": [i.to_dict() for i in self.indicators],
        }


class FeedManager:
    """Indexed store of normalized indicators across feeds."""

    def __init__(self) -> None:
        self._by_domain: dict[str, list[ThreatIndicator]] = {}
        self._by_ip: dict[str, list[ThreatIndicator]] = {}
        self._by_hash: dict[str, list[ThreatIndicator]] = {}

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, indicators: Iterable[ThreatIndicator]) -> int:
        """Add + dedupe indicators. Returns the count newly stored."""
        before = self.indicator_count
        merged = dedupe(list(self._all()) + list(indicators))
        self._by_domain.clear()
        self._by_ip.clear()
        self._by_hash.clear()
        for ind in merged:
            if ind.kind == IndicatorKind.DOMAIN:
                self._by_domain.setdefault(ind.value, []).append(ind)
            elif ind.kind == IndicatorKind.IP:
                self._by_ip.setdefault(ind.value, []).append(ind)
            elif ind.kind == IndicatorKind.SCRIPT_HASH:
                self._by_hash.setdefault(ind.value, []).append(ind)
        return self.indicator_count - before

    def _all(self) -> list[ThreatIndicator]:
        out: list[ThreatIndicator] = []
        for d in (self._by_domain, self._by_ip, self._by_hash):
            for lst in d.values():
                out.extend(lst)
        return out

    @property
    def indicator_count(self) -> int:
        return (sum(len(v) for v in self._by_domain.values())
                + sum(len(v) for v in self._by_ip.values())
                + sum(len(v) for v in self._by_hash.values()))

    @property
    def feeds(self) -> list[str]:
        seen: set[str] = set()
        for ind in self._all():
            for s in ind.source.split("+"):
                seen.add(s)
        return sorted(seen)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup_domain(self, host_or_url: str) -> FeedMatch:
        """Match a host (or URL). Checks the exact host AND its parent
        domains, so a feed hit on evil.com matches sub.evil.com too."""
        host = _host(host_or_url)
        hits: list[ThreatIndicator] = []
        if host:
            labels = host.split(".")
            for i in range(len(labels) - 1):
                candidate = ".".join(labels[i:])
                hits.extend(self._by_domain.get(candidate, []))
        return FeedMatch(matched=bool(hits), value=host, indicators=hits)

    def lookup_ip(self, ip: str) -> FeedMatch:
        ip = (ip or "").strip()
        hits = self._by_ip.get(ip, [])
        return FeedMatch(matched=bool(hits), value=ip, indicators=list(hits))

    def lookup_script_hash(self, sha256: str) -> FeedMatch:
        h = (sha256 or "").strip().lower()
        hits = self._by_hash.get(h, [])
        return FeedMatch(matched=bool(hits), value=h, indicators=list(hits))

    def to_dict(self) -> dict:
        return {
            "indicator_count": self.indicator_count,
            "feeds": self.feeds,
            "domain_indicators": len(self._by_domain),
            "ip_indicators": len(self._by_ip),
            "script_hash_indicators": len(self._by_hash),
        }
