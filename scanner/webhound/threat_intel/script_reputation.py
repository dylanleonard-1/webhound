# WebHound — scanner/webhound/threat_intel/script_reputation.py
# Phase-13 Task 3: reputation for third-party / dynamic / browser-loaded
# scripts. A script's risk is its HOST's reputation plus script-specific
# signals — known-skimmer host patterns, malware indicators in the body,
# and threat-feed hits on the script hash. Pure, offline.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from webhound.threat_intel.domain_reputation import (
    DomainReputationEngine,
    ReputationClass,
)
from webhound.threat_intel.feed_manager import FeedManager
from webhound.utils.hashing import sha256_hex

# Host substrings historically associated with skimmers / magecart
# staging infrastructure. Heuristic — corroboration required to escalate.
_SKIMMER_HOST_HINTS = (
    "magento-cdn", "googie-analytics", "google-anaiytics", "jquery-cdn",
    "cdn-imgcloud", "js-stats", "cloudfront-cdn", "static-cdn-",
)

# Inert markers of malicious script behavior (matched in inline bodies).
_MALWARE_BODY_PATTERNS = (
    "document.location=atob", "eval(atob", "fromcharcode",
    "websocket(\"wss://", "navigator.sendbeacon", "createelement('script')",
    ".value+", "addeventlistener('keypress'", "addeventlistener('input'",
    "stripe.card", "cardnumber", "document.forms",
)


class ScriptVerdict(str, Enum):
    TRUSTED = "trusted"
    KNOWN_VENDOR = "known_vendor"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    KNOWN_SKIMMER = "known_skimmer"
    MALICIOUS = "malicious"

    @property
    def is_threat(self) -> bool:
        return self in (ScriptVerdict.SUSPICIOUS, ScriptVerdict.KNOWN_SKIMMER,
                        ScriptVerdict.MALICIOUS)


@dataclass
class ScriptReputation:
    src: str | None
    host: str
    verdict: ScriptVerdict
    score: float
    vendor_category: str = "unknown"
    signals: list[str] = field(default_factory=list)
    feed_hit: bool = False
    content_hash: str | None = None

    @property
    def should_alert(self) -> bool:
        return self.verdict.is_threat

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "host": self.host,
            "verdict": self.verdict.value,
            "score": round(self.score, 3),
            "vendor_category": self.vendor_category,
            "feed_hit": self.feed_hit,
            "content_hash": self.content_hash,
            "signals": list(self.signals),
            "should_alert": self.should_alert,
        }


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


class ScriptReputationEngine:
    def __init__(
        self,
        *,
        domain_engine: DomainReputationEngine | None = None,
        feed_manager: FeedManager | None = None,
    ) -> None:
        self._domain = domain_engine or DomainReputationEngine(
            feed_manager=feed_manager)
        self._feeds = feed_manager or FeedManager()

    def assess(
        self, src: str | None, *, inline_body: str | None = None,
    ) -> ScriptReputation:
        host = _host(src or "")
        signals: list[str] = []
        content_hash = sha256_hex(inline_body) if inline_body else None

        # 1. Script-hash feed hit dominates.
        if content_hash:
            hashmatch = self._feeds.lookup_script_hash(content_hash)
            if hashmatch.matched:
                signals.append(
                    f"script-hash flagged ({hashmatch.category.value})")
                return ScriptReputation(
                    src=src, host=host, verdict=ScriptVerdict.MALICIOUS,
                    score=max(0.85, hashmatch.max_confidence), signals=signals,
                    feed_hit=True, content_hash=content_hash)

        # 2. Host reputation (covers domain feed hits + impersonation).
        if host:
            dom = self._domain.assess(host)
            if dom.reputation == ReputationClass.MALICIOUS:
                signals.extend(dom.signals)
                return ScriptReputation(
                    src=src, host=host, verdict=ScriptVerdict.MALICIOUS,
                    score=max(0.85, dom.score), signals=signals,
                    feed_hit=dom.feed_hit, vendor_category=dom.vendor_category,
                    content_hash=content_hash)

        # 3. Known-skimmer host hints (heuristic).
        skimmer = next((h for h in _SKIMMER_HOST_HINTS if h in host), None)
        body_hits = self._body_signals(inline_body)
        if skimmer and body_hits:
            signals.append(f"skimmer-style host '{skimmer}' + suspicious body")
            return ScriptReputation(
                src=src, host=host, verdict=ScriptVerdict.KNOWN_SKIMMER,
                score=0.8, signals=signals, content_hash=content_hash)
        if skimmer:
            signals.append(f"skimmer-style host pattern '{skimmer}'")
            return ScriptReputation(
                src=src, host=host, verdict=ScriptVerdict.SUSPICIOUS,
                score=0.55, signals=signals, content_hash=content_hash)

        # 4. Malicious body patterns on an unknown host → suspicious.
        if body_hits:
            signals.append(f"suspicious body patterns: {', '.join(body_hits[:3])}")
            dom = self._domain.assess(host) if host else None
            known = dom and dom.reputation in (ReputationClass.TRUSTED,
                                               ReputationClass.KNOWN_VENDOR)
            if not known:
                return ScriptReputation(
                    src=src, host=host, verdict=ScriptVerdict.SUSPICIOUS,
                    score=0.5, signals=signals, content_hash=content_hash)

        # 5. Fall through to host vendor classification.
        if host:
            dom = self._domain.assess(host)
            if dom.reputation == ReputationClass.TRUSTED:
                return ScriptReputation(src=src, host=host,
                                        verdict=ScriptVerdict.TRUSTED, score=0.0,
                                        vendor_category=dom.vendor_category,
                                        content_hash=content_hash)
            if dom.reputation == ReputationClass.KNOWN_VENDOR:
                return ScriptReputation(src=src, host=host,
                                        verdict=ScriptVerdict.KNOWN_VENDOR,
                                        score=0.05,
                                        vendor_category=dom.vendor_category,
                                        content_hash=content_hash)
        return ScriptReputation(src=src, host=host,
                                verdict=ScriptVerdict.UNKNOWN, score=0.3,
                                signals=signals, content_hash=content_hash)

    def _body_signals(self, body: str | None) -> list[str]:
        if not body:
            return []
        low = body.lower()
        return [p for p in _MALWARE_BODY_PATTERNS if p in low]
