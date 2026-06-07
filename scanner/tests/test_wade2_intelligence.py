# WebHound — scanner/tests/test_wade2_intelligence.py
# Phase 5 — WADE 2.0 intelligence layer.
#
# Covers the upgrade from "WADE can identify changes" to "WADE understands
# changes": expanded baselines, the broadened diff engine, the change-type
# taxonomy, known-vendor awareness, context-aware scoring, confidence levels,
# alert-fatigue suppression, and the change timeline.

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from webhound.core.crawler import CrawlResult
from webhound.core.extractor import (
    ExtractedIframe,
    ExtractedScript,
    PageArtifacts,
)
from webhound.core.http_client import HttpResponse
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.wade.anomaly_scorer import AnomalyScorer
from webhound.wade.baseline_builder import (
    BaselineBuilder,
    PageSnapshot,
    SiteBaseline,
    _detect_technologies,
    _dom_hash,
    _redirect_chain,
)
from webhound.wade.change_classifier import ChangeClassifier
from webhound.wade.change_types import ChangeBand, WadeChangeType, WadeConfidence
from webhound.wade.classifier import Classifier
from webhound.wade.diff_engine import DiffEngine, DiffItem, DiffType
from webhound.wade.suppression import decide, should_suppress
from webhound.wade.timeline import ChangeTimeline, change_key, update_timeline
from webhound.wade.vendor_intel import VendorIntel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snap(url: str = "https://example.com/", **kw) -> PageSnapshot:
    return PageSnapshot(
        url=url,
        status_code=kw.get("status", 200),
        content_hash="deadbeefdeadbeef",
        headers=kw.get("headers", {}),
        script_sources=kw.get("script_sources", []),
        inline_hashes=kw.get("inline_hashes", []),
        external_domains=kw.get("external_domains", []),
        form_signatures=kw.get("form_signatures", []),
        cookie_signatures=kw.get("cookie_signatures", {}),
        dom_hash=kw.get("dom_hash", ""),
        third_party_domains=kw.get("third_party_domains", []),
        api_endpoints=kw.get("api_endpoints", []),
        iframe_signatures=kw.get("iframe_signatures", []),
        redirect_chain=kw.get("redirect_chain", []),
        technologies=kw.get("technologies", []),
    )


def _diff(diff_type: DiffType, url: str, current_value: str | None,
          baseline_value: str | None = None) -> DiffItem:
    return DiffItem(
        diff_type=diff_type, url=url, detail="t",
        baseline_value=baseline_value, current_value=current_value,
        severity_hint="medium",
    )


def _assess(diff_type: DiffType, url: str, current_value: str | None):
    """Score + classify a single synthetic change."""
    item = _diff(diff_type, url, current_value)
    scored = AnomalyScorer().score([item])[0]
    return item, ChangeClassifier().assess(scored)


def _ext_script(src: str) -> ExtractedScript:
    return ExtractedScript(src=src, content=None, is_inline=False,
                           is_external=True, is_external_domain=True)


def _artifacts(url: str, *, scripts=None, iframes=None,
               js_requests=None, headers=None, body="<html><body>x</body></html>"):
    return PageArtifacts(
        url=url, status_code=200, content_type="text/html", title="T",
        all_links=[], internal_links=[], external_links=[],
        scripts=scripts or [],
        inline_scripts=[], external_script_urls=[s.src for s in (scripts or [])],
        forms=[], cookies=[], response_headers=headers or {},
        meta_tags={}, extracted_at=datetime.now(timezone.utc),
        iframes=iframes or [], inline_js_request_urls=js_requests or [],
    )


def _crawl(url="https://example.com/", **kw) -> CrawlResult:
    resp = HttpResponse(
        request_id=uuid4(), original_url=url, url=url, status_code=200,
        headers=kw.get("headers", {}), body=kw.get("body", "<html><body>x</body></html>"),
        content_type="text/html", elapsed_ms=10.0, redirect_count=0,
        redirect_chain=[], captured_at=datetime.now(timezone.utc), error=None,
    )
    arts = _artifacts(url, scripts=kw.get("scripts"), iframes=kw.get("iframes"),
                      js_requests=kw.get("js_requests"), headers=kw.get("headers", {}),
                      body=kw.get("body", "<html><body>x</body></html>"))
    return CrawlResult(url=url, depth=0, response=resp, artifacts=arts)


def _scan_result(url="https://example.com/") -> ScanResult:
    return ScanResult(target=Target.from_url(url, scan_options=ScanOptions()))


# Known + unknown hosts used across tests.
_GA = "https://www.google-analytics.com/analytics.js"
_STRIPE = "https://js.stripe.com/v3/"
_UNKNOWN_JS = "https://static.acme-widgets-xyz.com/w.js"
_MALICIOUS_DOMAIN = "evil-paypal-login.tk"      # brand+keyword+risky TLD → malicious
_RISKY_DOMAIN = "secure-update-verify.xyz"      # keyword + risky TLD → risky


# ===========================================================================
# Task 1 — Expanded baselines
# ===========================================================================


class TestExpandedBaseline:
    def test_builder_captures_third_party_domains(self) -> None:
        crawls = [_crawl(scripts=[_ext_script("https://cdn.vendor.com/a.js")])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert "cdn.vendor.com" in snap.third_party_domains
        assert "cdn.vendor.com" in bl.all_third_party_domains

    def test_builder_captures_api_endpoints(self) -> None:
        crawls = [_crawl(js_requests=["https://example.com/api/v1/orders"])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert any("api/v1/orders" in e for e in snap.api_endpoints)

    def test_builder_captures_iframe_signatures(self) -> None:
        frame = ExtractedIframe(src_url="https://www.youtube.com/embed/x",
                                is_external_domain=True, is_hidden=False, sandbox=None)
        crawls = [_crawl(iframes=[frame])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert any("youtube.com" in s for s in snap.iframe_signatures)

    def test_builder_captures_technologies(self) -> None:
        crawls = [_crawl(headers={"Server": "nginx/1.25.1"})]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert "nginx" in snap.technologies          # version stripped
        assert "nginx" in bl.all_technologies

    def test_dom_hash_stable_across_content_edits(self) -> None:
        # Same structure, different text → same hash (avoids noisy churn).
        a = _dom_hash("<html><body><h1>Welcome</h1><p>Hello</p></body></html>")
        b = _dom_hash("<html><body><h1>Bienvenue</h1><p>Bonjour</p></body></html>")
        assert a == b

    def test_dom_hash_changes_on_structure_change(self) -> None:
        a = _dom_hash("<html><body><p>Hello</p></body></html>")
        b = _dom_hash("<html><body><p>Hello</p><iframe></iframe></body></html>")
        assert a != b

    def test_detect_technologies_version_stripped(self) -> None:
        arts = _artifacts("https://x/", headers={"x-powered-by": "PHP/8.1.2"})
        assert "php" in _detect_technologies(arts)

    def test_redirect_chain_records_cross_host_hops(self) -> None:
        resp = SimpleNamespace(
            redirect_count=1, original_url="http://example.com/",
            redirect_chain=["http://example.com/go"], url="https://evil.com/landing",
        )
        chain = _redirect_chain(resp)
        assert chain == ["example.com", "evil.com"]

    def test_redirect_chain_ignores_same_host(self) -> None:
        resp = SimpleNamespace(
            redirect_count=1, original_url="http://example.com/",
            redirect_chain=[], url="https://example.com/home",
        )
        assert _redirect_chain(resp) == []

    def test_v1_baseline_dict_still_loads(self) -> None:
        # A WADE 1.x serialized snapshot (no v2 keys) must deserialize.
        legacy = {
            "target_url": "https://example.com",
            "scan_id": "x", "created_at": "2025-01-01T00:00:00+00:00",
            "page_count": 1,
            "all_script_sources": [], "all_external_domains": [],
            "pages": {
                "https://example.com/": {
                    "url": "https://example.com/", "status_code": 200,
                    "content_hash": "abc", "headers": {}, "script_sources": [],
                    "inline_hashes": [], "external_domains": [],
                    "form_signatures": [], "cookie_signatures": {},
                }
            },
        }
        bl = BaselineBuilder().from_dict(legacy)
        assert bl.pages["https://example.com/"].third_party_domains == []
        assert bl.all_technologies == []

    def test_expanded_baseline_round_trips(self) -> None:
        crawls = [_crawl(
            scripts=[_ext_script("https://cdn.vendor.com/a.js")],
            js_requests=["https://example.com/api/data"],
            headers={"Server": "nginx"},
        )]
        builder = BaselineBuilder()
        bl = builder.build(crawls, _scan_result())
        restored = builder.from_dict(builder.to_dict(bl))
        snap = restored.pages["https://example.com/"]
        assert snap.third_party_domains == ["cdn.vendor.com"]
        assert restored.all_technologies == bl.all_technologies


# ===========================================================================
# Task 2 — Improved diff engine
# ===========================================================================


class TestDiffEngineV2:
    engine = DiffEngine()

    def test_removed_script_detected(self) -> None:
        base = _snap(script_sources=["https://cdn.com/a.js"])
        cur = _snap(script_sources=[])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.REMOVED_SCRIPT_SOURCE for i in items)

    def test_new_third_party_domain_detected(self) -> None:
        base = _snap(third_party_domains=["cdn.com"])
        cur = _snap(third_party_domains=["cdn.com", "tracker.io"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.NEW_THIRD_PARTY_DOMAIN
                   and i.current_value == "tracker.io" for i in items)

    def test_new_third_party_deduped_against_new_script(self) -> None:
        # cdn.new.com is new *because* of a new script — don't double-report.
        base = _snap(script_sources=[], third_party_domains=[])
        cur = _snap(script_sources=["https://cdn.new.com/x.js"],
                    third_party_domains=["cdn.new.com"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.NEW_SCRIPT_SOURCE for i in items)
        assert not any(i.diff_type == DiffType.NEW_THIRD_PARTY_DOMAIN for i in items)

    def test_new_api_endpoint_detected(self) -> None:
        base = _snap(api_endpoints=[])
        cur = _snap(api_endpoints=["example.com/api/v1/users"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.NEW_API_ENDPOINT for i in items)

    def test_removed_api_endpoint_detected(self) -> None:
        base = _snap(api_endpoints=["example.com/api/old"])
        cur = _snap(api_endpoints=[])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.REMOVED_API_ENDPOINT for i in items)

    def test_header_added_detected(self) -> None:
        base = _snap(headers={})
        cur = _snap(headers={"content-security-policy": "default-src 'self'"})
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.HEADER_ADDED for i in items)

    def test_cookie_behavior_change_on_new_cookie(self) -> None:
        base = _snap(cookie_signatures={})
        cur = _snap(cookie_signatures={"newsess": "Secure;HttpOnly"})
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.COOKIE_BEHAVIOR_CHANGE for i in items)

    def test_new_iframe_detected(self) -> None:
        base = _snap(iframe_signatures=[])
        cur = _snap(iframe_signatures=["evil.com|hidden|unsandboxed"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.NEW_IFRAME for i in items)

    def test_redirect_change_detected(self) -> None:
        base = _snap(redirect_chain=[])
        cur = _snap(redirect_chain=["example.com", "evil.com"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.REDIRECT_CHANGE for i in items)

    def test_technology_change_detected(self) -> None:
        base = _snap(technologies=["wordpress"])
        cur = _snap(technologies=["wordpress", "shopify"])
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.TECHNOLOGY_CHANGE for i in items)

    def test_dom_structure_change_detected(self) -> None:
        base = _snap(dom_hash="aaaa111122223333")
        cur = _snap(dom_hash="bbbb444455556666")
        items = self.engine.diff_page(cur, base)
        assert any(i.diff_type == DiffType.DOM_STRUCTURE_CHANGE for i in items)

    def test_identical_expanded_snapshot_no_diff(self) -> None:
        snap = _snap(
            script_sources=["https://cdn.com/a.js"], third_party_domains=["cdn.com"],
            api_endpoints=["example.com/api/x"], iframe_signatures=["yt.com|visible|unsandboxed"],
            technologies=["nginx"], dom_hash="aaaa111122223333",
        )
        assert self.engine.diff_page(snap, snap) == []


# ===========================================================================
# Tasks 3, 5, 6 — Change types, vendor awareness, scoring
# ===========================================================================


class TestChangeClassification:
    def test_new_analytics_tool(self) -> None:
        _, a = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _GA)
        assert a.change_type == WadeChangeType.NEW_ANALYTICS_TOOL
        assert a.band == ChangeBand.VERY_LOW
        assert a.vendor_category == "analytics"

    def test_new_payment_provider_stripe(self) -> None:
        _, a = _assess(DiffType.NEW_SCRIPT_SOURCE,
                       "https://example.com/checkout", _STRIPE)
        assert a.change_type == WadeChangeType.NEW_PAYMENT_PROVIDER
        assert a.band.rank <= ChangeBand.MEDIUM.rank        # legit → calm

    def test_unknown_script_on_login_is_suspicious_and_elevated(self) -> None:
        _, a = _assess(DiffType.NEW_SCRIPT_SOURCE,
                       "https://example.com/login", _UNKNOWN_JS)
        assert a.change_type == WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE
        assert a.band.rank >= ChangeBand.HIGH.rank

    def test_unknown_script_on_homepage_is_calmer(self) -> None:
        _, a = _assess(DiffType.NEW_SCRIPT_SOURCE,
                       "https://example.com/", _UNKNOWN_JS)
        assert a.change_type == WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE
        assert a.band.rank <= ChangeBand.LOW.rank           # homepage low concern

    def test_malicious_domain_is_critical(self) -> None:
        _, a = _assess(DiffType.NEW_EXTERNAL_DOMAIN,
                       "https://example.com/", _MALICIOUS_DOMAIN)
        assert a.change_type == WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR
        assert a.band == ChangeBand.CRITICAL
        assert a.threat_intel_hit is True

    def test_risky_domain_is_possible_compromise(self) -> None:
        _, a = _assess(DiffType.NEW_EXTERNAL_DOMAIN,
                       "https://example.com/", _RISKY_DOMAIN)
        assert a.change_type == WadeChangeType.POSSIBLE_COMPROMISE
        assert a.threat_intel_hit is True

    def test_new_iframe_on_checkout_is_high(self) -> None:
        _, a = _assess(DiffType.NEW_IFRAME, "https://example.com/checkout",
                       "evil.com|hidden|unsandboxed")
        assert a.change_type == WadeChangeType.SUSPICIOUS_IFRAME
        assert a.band.rank >= ChangeBand.HIGH.rank

    def test_known_vendor_iframe_is_service(self) -> None:
        _, a = _assess(DiffType.NEW_IFRAME, "https://example.com/",
                       "www.youtube.com|visible|unsandboxed")
        assert a.change_type == WadeChangeType.NEW_THIRD_PARTY_SERVICE

    def test_redirect_to_unknown_is_suspicious(self) -> None:
        _, a = _assess(DiffType.REDIRECT_CHANGE, "https://example.com/",
                       "example.com → sketchy-redirect.top")
        assert a.change_type == WadeChangeType.SUSPICIOUS_REDIRECT

    def test_vendor_intel_known_payment(self) -> None:
        verdict = VendorIntel().assess(_STRIPE)
        assert verdict.is_known_vendor
        assert verdict.vendor_category == "payment"
        assert verdict.change_type == WadeChangeType.NEW_PAYMENT_PROVIDER

    def test_suspicious_script_plus_iframe_both_elevated(self) -> None:
        # Compound: unknown script AND new iframe on a checkout page.
        _, script = _assess(DiffType.NEW_SCRIPT_SOURCE,
                            "https://example.com/checkout", _UNKNOWN_JS)
        _, frame = _assess(DiffType.NEW_IFRAME,
                           "https://example.com/checkout", "evil.com|hidden|unsandboxed")
        assert script.band.rank >= ChangeBand.HIGH.rank
        assert frame.band.rank >= ChangeBand.HIGH.rank


# ===========================================================================
# Task 7 — WADE confidence levels
# ===========================================================================


class TestConfidenceLevels:
    def test_new_script_is_confirmed(self) -> None:
        _, a = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _UNKNOWN_JS)
        assert a.confidence == WadeConfidence.CONFIRMED

    def test_new_api_endpoint_is_low(self) -> None:
        _, a = _assess(DiffType.NEW_API_ENDPOINT, "https://example.com/",
                       "example.com/api/users")
        assert a.confidence == WadeConfidence.LOW

    def test_technology_change_is_heuristic(self) -> None:
        _, a = _assess(DiffType.TECHNOLOGY_CHANGE, "https://example.com/", "shopify")
        assert a.confidence == WadeConfidence.HEURISTIC

    def test_threat_intel_hit_is_confirmed(self) -> None:
        _, a = _assess(DiffType.NEW_EXTERNAL_DOMAIN, "https://example.com/",
                       _MALICIOUS_DOMAIN)
        assert a.confidence == WadeConfidence.CONFIRMED


# ===========================================================================
# Task 8 — Alert-fatigue suppression
# ===========================================================================


class TestSuppression:
    def test_status_code_change_suppressed(self) -> None:
        item, a = _assess(DiffType.STATUS_CODE_CHANGE, "https://example.com/", "404")
        assert should_suppress(a, item.diff_type)

    def test_dom_structure_change_suppressed(self) -> None:
        item, a = _assess(DiffType.DOM_STRUCTURE_CHANGE, "https://example.com/", "x")
        assert should_suppress(a, item.diff_type)

    def test_technology_change_suppressed(self) -> None:
        item, a = _assess(DiffType.TECHNOLOGY_CHANGE, "https://example.com/", "shopify")
        assert should_suppress(a, item.diff_type)

    def test_header_added_suppressed(self) -> None:
        item, a = _assess(DiffType.HEADER_ADDED, "https://example.com/", "nosniff")
        assert should_suppress(a, item.diff_type)

    def test_removed_script_suppressed(self) -> None:
        item, a = _assess(DiffType.REMOVED_SCRIPT_SOURCE, "https://example.com/", None)
        assert should_suppress(a, item.diff_type)

    def test_suspicious_script_not_suppressed(self) -> None:
        item, a = _assess(DiffType.NEW_SCRIPT_SOURCE,
                          "https://example.com/login", _UNKNOWN_JS)
        assert not should_suppress(a, item.diff_type)

    def test_malicious_indicator_not_suppressed(self) -> None:
        item, a = _assess(DiffType.NEW_EXTERNAL_DOMAIN,
                          "https://example.com/", _MALICIOUS_DOMAIN)
        assert not should_suppress(a, item.diff_type)

    def test_header_regression_never_suppressed(self) -> None:
        item, a = _assess(DiffType.HEADER_REGRESSION, "https://example.com/", None)
        assert not should_suppress(a, item.diff_type)

    def test_expected_deployment_reason(self) -> None:
        item, a = _assess(DiffType.STATUS_CODE_CHANGE, "https://example.com/", "503")
        d = decide(a, item.diff_type)
        assert d.suppressed and d.reason


# ===========================================================================
# Task 9 — Change timeline
# ===========================================================================


class TestTimeline:
    def test_first_sighting_records_change(self) -> None:
        item, a = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _UNKNOWN_JS)
        tl = update_timeline(ChangeTimeline(), [(item, a)], scan_timestamp="2025-01-01T00:00:00Z")
        assert tl.total_changes == 1
        rec = tl.records[change_key(item)]
        assert rec.first_seen == rec.last_seen == "2025-01-01T00:00:00Z"
        assert rec.occurrences == 1
        assert not rec.is_recurring

    def test_recurring_change_increments_frequency(self) -> None:
        item, a = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _UNKNOWN_JS)
        tl = ChangeTimeline()
        update_timeline(tl, [(item, a)], scan_timestamp="2025-01-01T00:00:00Z")
        update_timeline(tl, [(item, a)], scan_timestamp="2025-02-01T00:00:00Z")
        rec = tl.records[change_key(item)]
        assert rec.occurrences == 2
        assert rec.is_recurring
        assert rec.first_seen == "2025-01-01T00:00:00Z"
        assert rec.last_seen == "2025-02-01T00:00:00Z"

    def test_histograms_and_serialization(self) -> None:
        i1, a1 = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/login", _UNKNOWN_JS)
        i2, a2 = _assess(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _GA)
        tl = update_timeline(ChangeTimeline(), [(i1, a1), (i2, a2)],
                             scan_timestamp="2025-01-01T00:00:00Z")
        d = tl.to_dict()
        assert d["total_changes"] == 2
        assert sum(d["band_histogram"].values()) == 2
        restored = ChangeTimeline.from_dict(d)
        assert restored.total_changes == 2


# ===========================================================================
# Classifier integration — intelligence reflected on Findings
# ===========================================================================


class TestClassifierIntelligence:
    clf = Classifier()

    def _finding(self, diff_type, url, value):
        item = _diff(diff_type, url, value)
        scored = AnomalyScorer().score([item])
        return self.clf.classify(scored)[0]

    def test_new_analytics_finding_is_info(self) -> None:
        f = self._finding(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/", _GA)
        assert f.severity == Severity.INFO          # "New Google Analytics → Very Low"
        assert "new_analytics_tool" in f.tags

    def test_malicious_domain_finding_is_critical(self) -> None:
        f = self._finding(DiffType.NEW_EXTERNAL_DOMAIN, "https://example.com/",
                          _MALICIOUS_DOMAIN)
        assert f.severity == Severity.CRITICAL
        assert "threat_intel" in f.tags

    def test_finding_carries_change_intelligence(self) -> None:
        f = self._finding(DiffType.NEW_SCRIPT_SOURCE, "https://example.com/login",
                          _UNKNOWN_JS)
        ex = f.evidence[0].extra
        assert ex["wade_change_type"] == "suspicious_script_change"
        assert ex["wade_confidence_level"] == "confirmed"
        assert "wade_change_band" in ex
        assert f.metadata["wade_change_type"] == "suspicious_script_change"

    def test_suppressed_change_is_tagged(self) -> None:
        f = self._finding(DiffType.HEADER_ADDED, "https://example.com/", "nosniff")
        assert "wade_suppressed" in f.tags
        assert f.evidence[0].extra["wade_suppressed"] is True

    def test_new_iframe_checkout_finding_high(self) -> None:
        f = self._finding(DiffType.NEW_IFRAME, "https://example.com/checkout",
                          "evil.com|hidden|unsandboxed")
        assert f.severity.rank >= Severity.HIGH.rank
        assert not _is_suppressed(f)


def _is_suppressed(finding) -> bool:
    return "wade_suppressed" in (finding.tags or [])
