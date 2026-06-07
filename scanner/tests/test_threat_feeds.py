# WebHound — tests/test_threat_feeds.py
# Phase-13 Task 1: feed normalization, the feed manager, reputation cache.

from __future__ import annotations

from webhound.threat_intel.feed_manager import FeedManager
from webhound.threat_intel.feed_normalizer import (
    IndicatorKind,
    ThreatCategory,
    dedupe,
    normalize_abuseipdb,
    normalize_openphish,
    normalize_phishtank,
    normalize_script_feed,
    normalize_urlhaus,
    normalize_virustotal,
)
from webhound.threat_intel.reputation_cache import ReputationCache


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_urlhaus_online_vs_offline() -> None:
    inds = normalize_urlhaus([
        {"url": "http://evil.test/path", "threat": "malware_download",
         "url_status": "online"},
        {"url": "http://old.test/x", "threat": "malware_download",
         "url_status": "offline"},
    ])
    assert inds[0].value == "evil.test"
    assert inds[0].category == ThreatCategory.MALWARE
    assert inds[0].confidence > inds[1].confidence    # online > offline


def test_normalize_openphish_and_phishtank() -> None:
    op = normalize_openphish(["https://phish.test/login"])
    assert op[0].category == ThreatCategory.PHISHING
    assert op[0].value == "phish.test"
    pt = normalize_phishtank([{"url": "https://pt.test/x", "verified": "yes"}])
    assert pt[0].confidence == 0.9


def test_normalize_abuseipdb_scales_confidence() -> None:
    inds = normalize_abuseipdb([
        {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100},
        {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 0},   # dropped
    ])
    assert len(inds) == 1
    assert inds[0].kind == IndicatorKind.IP
    assert inds[0].confidence == 1.0


def test_normalize_virustotal_only_when_malicious() -> None:
    clean = normalize_virustotal("good.test", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                "harmless": 80}}}})
    assert clean == []
    bad = normalize_virustotal("bad.test", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 10, "suspicious": 2,
                                "harmless": 60}}}})
    assert bad[0].category == ThreatCategory.MALWARE
    assert bad[0].confidence > 0.4


def test_normalize_script_feed_hash() -> None:
    inds = normalize_script_feed([{"sha256": "ABC123", "label": "magecart"}])
    assert inds[0].kind == IndicatorKind.SCRIPT_HASH
    assert inds[0].value == "abc123"
    assert inds[0].category == ThreatCategory.SKIMMER


def test_dedupe_merges_and_corroborates() -> None:
    a = normalize_openphish(["https://x.test/a"])
    b = normalize_phishtank([{"url": "https://x.test/b", "verified": "yes"}])
    merged = dedupe(a + b)
    assert len(merged) == 1
    assert "+" in merged[0].source            # corroborated
    assert merged[0].confidence >= 0.9


# ---------------------------------------------------------------------------
# Feed manager
# ---------------------------------------------------------------------------


def test_feed_manager_lookup_domain_and_subdomain() -> None:
    fm = FeedManager()
    fm.ingest(normalize_urlhaus([
        {"url": "http://evil.com/x", "threat": "skimmer",
         "url_status": "online"}]))
    # Exact host matches.
    assert fm.lookup_domain("https://evil.com/page").matched
    # Subdomain inherits the parent-domain hit.
    sub = fm.lookup_domain("https://cdn.evil.com/a.js")
    assert sub.matched
    assert sub.category == ThreatCategory.SKIMMER
    # Unrelated host doesn't match.
    assert not fm.lookup_domain("https://good.test/").matched


def test_feed_manager_ip_and_hash() -> None:
    fm = FeedManager()
    fm.ingest(normalize_abuseipdb([
        {"ipAddress": "9.9.9.9", "abuseConfidenceScore": 80}]))
    fm.ingest(normalize_script_feed([{"sha256": "deadbeef", "label": "trojan"}]))
    assert fm.lookup_ip("9.9.9.9").matched
    assert fm.lookup_script_hash("DEADBEEF").matched
    assert set(fm.feeds) >= {"abuseipdb", "script_feed"}


def test_feed_manager_dedup_across_ingests() -> None:
    fm = FeedManager()
    fm.ingest(normalize_openphish(["https://dup.test/a"]))
    fm.ingest(normalize_phishtank([{"url": "https://dup.test/b",
                                    "verified": "yes"}]))
    m = fm.lookup_domain("dup.test")
    assert m.matched
    assert len(m.sources) >= 2                # both feeds attributed


# ---------------------------------------------------------------------------
# Reputation cache
# ---------------------------------------------------------------------------


def test_cache_hit_and_miss() -> None:
    c = ReputationCache(ttl_seconds=100)
    assert c.get("domain:x") is None
    c.put("domain:x", {"v": 1})
    assert c.get("domain:x") == {"v": 1}
    assert c.stats()["hits"] == 1
    assert c.stats()["misses"] == 1


def test_cache_expiry() -> None:
    c = ReputationCache(ttl_seconds=0.0)
    c.put("k", {"v": 1})
    # TTL 0 → already expired on read.
    assert c.get("k") is None


def test_cache_get_or_compute() -> None:
    c = ReputationCache()
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return {"v": 42}

    assert c.get_or_compute("k", compute) == {"v": 42}
    assert c.get_or_compute("k", compute) == {"v": 42}
    assert calls["n"] == 1                     # computed once, then cached


def test_cache_roundtrip_preserves_unexpired() -> None:
    c = ReputationCache(ttl_seconds=100)
    c.put("domain:a", {"v": 1})
    restored = ReputationCache.from_dict(c.to_dict())
    assert restored.get("domain:a") == {"v": 1}
