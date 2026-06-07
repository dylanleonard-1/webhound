# WebHound — scanner/webhound/threat_intel/domain_reputation.py
# Phase-13 Task 2/7/8: the domain reputation engine. Combines the local
# DomainClassifier (tier + vendor category), threat-feed hits, and brand
# impersonation into a single explainable verdict + reputation score.
#
# Suppression (Task 8) falls out of the design: a trusted/known vendor
# stays TRUSTED/KNOWN_VENDOR unless a feed hit or impersonation signal
# supplies real threat context — so Stripe/Google/Cloudflare never alarm
# on presence alone.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.threat_intel.brand_impersonation import (
    ImpersonationVerdict,
    assess_domain,
)
from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassifier,
)
from webhound.threat_intel.feed_manager import FeedManager
from webhound.threat_intel.reputation_cache import ReputationCache


class ReputationClass(str, Enum):
    """Task 2 reputation tiers (benign → malicious)."""

    TRUSTED = "trusted"            # CDN/infra allowlist
    KNOWN_VENDOR = "known_vendor"  # recognised legitimate service
    NORMAL = "normal"              # ordinary, no signals
    UNKNOWN = "unknown"            # unrecognised, no signals either way
    SUSPICIOUS = "suspicious"      # soft signals
    MALICIOUS = "malicious"        # feed hit / strong impersonation

    @property
    def rank(self) -> int:
        return {"trusted": 0, "known_vendor": 1, "normal": 2,
                "unknown": 3, "suspicious": 4, "malicious": 5}[self.value]


@dataclass
class DomainReputation:
    host: str
    reputation: ReputationClass
    score: float                      # 0 (trusted) .. 1 (malicious)
    vendor_category: str = "unknown"
    signals: list[str] = field(default_factory=list)
    feed_hit: bool = False
    feed_sources: list[str] = field(default_factory=list)
    impersonation: ImpersonationVerdict | None = None
    # Observed-behavior placeholders (populated by callers that have scan
    # context — kept here so reports/WADE have a stable shape; Task 2).
    age_days: int | None = None
    popularity_rank: int | None = None

    @property
    def is_threat(self) -> bool:
        return self.reputation in (ReputationClass.SUSPICIOUS,
                                   ReputationClass.MALICIOUS)

    @property
    def should_alert(self) -> bool:
        """Task 8: only alert when real threat context exists. MALICIOUS
        always alerts; merely-SUSPICIOUS (soft heuristics like excessive
        hyphens) alerts ONLY when corroborated by a feed hit or brand
        impersonation. Trusted / known-vendor / normal / unknown never
        alert on presence alone."""
        if self.reputation == ReputationClass.MALICIOUS:
            return True
        if self.reputation == ReputationClass.SUSPICIOUS:
            return self.feed_hit or bool(
                self.impersonation and self.impersonation.is_impersonation)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "reputation": self.reputation.value,
            "score": round(self.score, 3),
            "vendor_category": self.vendor_category,
            "feed_hit": self.feed_hit,
            "feed_sources": list(self.feed_sources),
            "impersonation": (self.impersonation.to_dict()
                              if self.impersonation
                              and self.impersonation.is_impersonation else None),
            "signals": list(self.signals),
            "age_days": self.age_days,
            "popularity_rank": self.popularity_rank,
            "should_alert": self.should_alert,
        }


class DomainReputationEngine:
    """Blends local classification + feeds + impersonation into a verdict."""

    def __init__(
        self,
        *,
        classifier: DomainClassifier | None = None,
        feed_manager: FeedManager | None = None,
        cache: ReputationCache | None = None,
    ) -> None:
        self._clf = classifier or DomainClassifier()
        self._feeds = feed_manager or FeedManager()
        self._cache = cache or ReputationCache()

    def assess(self, host_or_url: str) -> DomainReputation:
        cls = self._clf.classify(host_or_url)
        host = cls.domain
        cache_key = f"domain:{host}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return _from_cache(cached)

        feed = self._feeds.lookup_domain(host)
        imp = assess_domain(host)

        rep, score, signals = self._combine(cls, feed, imp)
        result = DomainReputation(
            host=host, reputation=rep, score=score,
            vendor_category=cls.vendor_category,
            signals=signals,
            feed_hit=feed.matched,
            feed_sources=feed.sources,
            impersonation=imp,
        )
        self._cache.put(cache_key, result.to_dict())
        return result

    # ------------------------------------------------------------------

    def _combine(self, cls, feed, imp) -> tuple[ReputationClass, float, list[str]]:
        signals: list[str] = []

        # 1. A threat-feed hit dominates everything.
        if feed.matched:
            signals.append(
                f"threat-feed hit ({feed.category.value}) from "
                f"{', '.join(feed.sources)}")
            return ReputationClass.MALICIOUS, max(0.85, feed.max_confidence), signals

        # 2. Strong brand impersonation = malicious; softer = suspicious.
        if imp.is_impersonation:
            signals.append(imp.detail)
            if imp.confidence >= 0.85:
                return ReputationClass.MALICIOUS, imp.confidence, signals
            return ReputationClass.SUSPICIOUS, max(0.5, imp.confidence), signals

        # 3. Fall back to the local classifier tier (Task 8 suppression:
        #    trusted/benign stay benign with no further signal).
        if cls.classification == DomainClass.TRUSTED:
            return ReputationClass.TRUSTED, 0.0, signals + cls.signals
        if cls.classification == DomainClass.COMMON_BENIGN:
            return ReputationClass.KNOWN_VENDOR, 0.05, signals + cls.signals
        if cls.classification == DomainClass.MALICIOUS_INDICATOR:
            return ReputationClass.MALICIOUS, max(0.8, cls.score / 10.0), \
                signals + cls.signals
        if cls.classification == DomainClass.RISKY:
            return ReputationClass.SUSPICIOUS, max(0.5, cls.score / 10.0), \
                signals + cls.signals
        if cls.classification == DomainClass.SUSPICIOUS:
            return ReputationClass.SUSPICIOUS, max(0.4, cls.score / 10.0), \
                signals + cls.signals
        # UNKNOWN: no signals either way.
        return ReputationClass.UNKNOWN, 0.3, signals + cls.signals


def _from_cache(d: dict[str, Any]) -> DomainReputation:
    return DomainReputation(
        host=d["host"],
        reputation=ReputationClass(d["reputation"]),
        score=float(d["score"]),
        vendor_category=d.get("vendor_category", "unknown"),
        signals=list(d.get("signals", [])),
        feed_hit=bool(d.get("feed_hit")),
        feed_sources=list(d.get("feed_sources", [])),
    )
