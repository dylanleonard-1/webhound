# WebHound — scanner/webhound/threat_intel/feed_normalizer.py
# Phase-13 Task 1: normalize heterogeneous threat-feed payloads into one
# canonical ThreatIndicator shape so the rest of the engine reasons about
# a single vocabulary regardless of source.
#
# Feeds differ wildly: VirusTotal returns analysis stats, URLHaus returns
# rows with a threat label, OpenPhish is a flat URL list, PhishTank is
# JSON entries, AbuseIPDB returns an abuse confidence score. This module
# maps each into ThreatIndicator (kind, value, source, category,
# confidence). No network — it transforms already-fetched payloads
# (fetching stays in enrichment_service / operator-gated clients).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urlparse


class IndicatorKind(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    SCRIPT_HASH = "script_hash"


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    SKIMMER = "skimmer"
    SCAM = "scam"
    ABUSE = "abuse"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ThreatIndicator:
    """One normalized indicator of compromise."""

    kind: IndicatorKind
    value: str                       # normalized: lowercased host / hash / url
    source: str                      # feed name (urlhaus, openphish, ...)
    category: ThreatCategory = ThreatCategory.UNKNOWN
    confidence: float = 0.5          # 0..1, the feed's reliability for this hit
    label: str | None = None         # raw threat label from the feed

    def key(self) -> tuple[str, str]:
        return (self.kind.value, self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "source": self.source,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "label": self.label,
        }


def _host(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    # bare host (maybe with path)
    return v.split("/", 1)[0]


def _label_to_category(label: str | None) -> ThreatCategory:
    t = (label or "").lower()
    if any(k in t for k in ("phish", "credential")):
        return ThreatCategory.PHISHING
    if any(k in t for k in ("skim", "magecart", "formjack", "inject")):
        return ThreatCategory.SKIMMER
    if any(k in t for k in ("malware", "trojan", "ransom", "exploit",
                            "c2", "botnet", "payload")):
        return ThreatCategory.MALWARE
    if "scam" in t or "fraud" in t:
        return ThreatCategory.SCAM
    if "abuse" in t:
        return ThreatCategory.ABUSE
    return ThreatCategory.SUSPICIOUS if t else ThreatCategory.UNKNOWN


# ---------------------------------------------------------------------------
# Per-feed normalizers. Each accepts the feed's native payload shape and
# yields ThreatIndicators. All defensive — junk rows are skipped.
# ---------------------------------------------------------------------------


def normalize_urlhaus(rows: Iterable[dict[str, Any]]) -> list[ThreatIndicator]:
    """URLHaus query/feed rows: {url, threat, url_status, tags?}."""
    out: list[ThreatIndicator] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        host = _host(str(url or ""))
        if not host:
            continue
        label = r.get("threat") or (r.get("tags") or [None])[0]
        # Online entries are higher confidence than offline.
        conf = 0.9 if str(r.get("url_status", "")).lower() == "online" else 0.7
        out.append(ThreatIndicator(
            kind=IndicatorKind.DOMAIN, value=host, source="urlhaus",
            category=_label_to_category(label), confidence=conf,
            label=label if isinstance(label, str) else None))
    return out


def normalize_openphish(urls: Iterable[str]) -> list[ThreatIndicator]:
    """OpenPhish: a flat list of phishing URLs."""
    out: list[ThreatIndicator] = []
    for u in urls or []:
        host = _host(str(u or ""))
        if host:
            out.append(ThreatIndicator(
                kind=IndicatorKind.DOMAIN, value=host, source="openphish",
                category=ThreatCategory.PHISHING, confidence=0.85,
                label="phishing"))
    return out


def normalize_phishtank(entries: Iterable[dict[str, Any]]) -> list[ThreatIndicator]:
    """PhishTank: {url, verified, online}."""
    out: list[ThreatIndicator] = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        host = _host(str(e.get("url") or ""))
        if not host:
            continue
        verified = str(e.get("verified", "")).lower() in ("yes", "true", "1")
        conf = 0.9 if verified else 0.6
        out.append(ThreatIndicator(
            kind=IndicatorKind.DOMAIN, value=host, source="phishtank",
            category=ThreatCategory.PHISHING, confidence=conf,
            label="phishing"))
    return out


def normalize_abuseipdb(rows: Iterable[dict[str, Any]]) -> list[ThreatIndicator]:
    """AbuseIPDB: {ipAddress, abuseConfidenceScore}."""
    out: list[ThreatIndicator] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        ip = str(r.get("ipAddress") or "").strip()
        if not ip:
            continue
        try:
            score = float(r.get("abuseConfidenceScore", 0)) / 100.0
        except (TypeError, ValueError):
            score = 0.0
        if score <= 0:
            continue
        out.append(ThreatIndicator(
            kind=IndicatorKind.IP, value=ip, source="abuseipdb",
            category=ThreatCategory.ABUSE, confidence=round(score, 3),
            label="abuse"))
    return out


def normalize_virustotal(domain: str, payload: dict[str, Any]) -> list[ThreatIndicator]:
    """VirusTotal v3 domain object: data.attributes.last_analysis_stats."""
    host = _host(domain)
    if not host or not isinstance(payload, dict):
        return []
    stats = (((payload.get("data") or {}).get("attributes") or {})
             .get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 1
    if malicious == 0 and suspicious == 0:
        return []
    conf = min(0.98, (malicious * 1.0 + suspicious * 0.5) / total + 0.4)
    return [ThreatIndicator(
        kind=IndicatorKind.DOMAIN, value=host, source="virustotal",
        category=ThreatCategory.MALWARE if malicious else ThreatCategory.SUSPICIOUS,
        confidence=round(conf, 3),
        label=f"{malicious} malicious / {suspicious} suspicious vendors")]


def normalize_script_feed(rows: Iterable[dict[str, Any]]) -> list[ThreatIndicator]:
    """Generic malicious-script feed: {hash|sha256, label?}."""
    out: list[ThreatIndicator] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        h = str(r.get("sha256") or r.get("hash") or "").strip().lower()
        if not h:
            continue
        label = r.get("label") or r.get("threat")
        out.append(ThreatIndicator(
            kind=IndicatorKind.SCRIPT_HASH, value=h, source="script_feed",
            category=_label_to_category(label), confidence=0.85,
            label=label if isinstance(label, str) else None))
    return out


def dedupe(indicators: Iterable[ThreatIndicator]) -> list[ThreatIndicator]:
    """Collapse duplicate (kind, value) indicators, keeping the highest-
    confidence one and merging sources into its label when they differ."""
    best: dict[tuple[str, str], ThreatIndicator] = {}
    sources: dict[tuple[str, str], set[str]] = {}
    for ind in indicators:
        k = ind.key()
        sources.setdefault(k, set()).add(ind.source)
        cur = best.get(k)
        if cur is None or ind.confidence > cur.confidence:
            best[k] = ind
    out: list[ThreatIndicator] = []
    for k, ind in best.items():
        srcs = sources[k]
        if len(srcs) > 1:
            # Multiple feeds agreeing → bump confidence, note corroboration.
            ind = ThreatIndicator(
                kind=ind.kind, value=ind.value,
                source="+".join(sorted(srcs)),
                category=ind.category,
                confidence=min(0.99, ind.confidence + 0.05 * (len(srcs) - 1)),
                label=ind.label)
        out.append(ind)
    return out
