# WebHound — scanner/tests/test_threat_intel.py
# Tests for Phase 9 local threat intelligence and domain classification layer.

from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassification,
    DomainClassifier,
)
from webhound.threat_intel.enrichment_service import (
    EnrichmentResult,
    EnrichmentService,
    ProviderResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def clf():
    """Shared DomainClassifier instance (tldextract cache pre-warmed)."""
    return DomainClassifier()


@pytest.fixture(scope="module")
def service():
    """Shared EnrichmentService with no external providers."""
    return EnrichmentService()


# ---------------------------------------------------------------------------
# DomainClassifier — trusted domains
# ---------------------------------------------------------------------------

class TestDomainClassifierTrusted:
    def test_cloudflare_trusted(self, clf):
        r = clf.classify("cdn.cloudflare.net")
        assert r.classification == DomainClass.TRUSTED
        assert r.score == 0.0
        assert r.confidence >= 0.9

    def test_googleapis_trusted(self, clf):
        r = clf.classify("ajax.googleapis.com")
        assert r.classification == DomainClass.TRUSTED

    def test_cloudfront_trusted(self, clf):
        r = clf.classify("d1abc.cloudfront.net")
        assert r.classification == DomainClass.TRUSTED

    def test_jsdelivr_trusted(self, clf):
        r = clf.classify("cdn.jsdelivr.net")
        assert r.classification == DomainClass.TRUSTED

    def test_trusted_result_has_no_risk_signals(self, clf):
        r = clf.classify("code.jquery.com")
        assert r.classification == DomainClass.TRUSTED
        # Trusted short-circuits — signal list may note "trusted" but no risk signals
        assert r.score == 0.0


# ---------------------------------------------------------------------------
# DomainClassifier — common benign / payment / analytics
# ---------------------------------------------------------------------------

class TestDomainClassifierCommonBenign:
    def test_stripe_common_benign(self, clf):
        r = clf.classify("js.stripe.com")
        assert r.classification == DomainClass.COMMON_BENIGN
        assert r.score < 2.0

    def test_paypal_common_benign(self, clf):
        r = clf.classify("www.paypal.com")
        assert r.classification == DomainClass.COMMON_BENIGN

    def test_google_analytics_common_benign(self, clf):
        r = clf.classify("www.google-analytics.com")
        assert r.classification == DomainClass.COMMON_BENIGN

    def test_facebook_common_benign(self, clf):
        r = clf.classify("connect.facebook.com")
        assert r.classification == DomainClass.COMMON_BENIGN


# ---------------------------------------------------------------------------
# DomainClassifier — risky TLDs
# ---------------------------------------------------------------------------

class TestDomainClassifierRiskyTld:
    def test_tk_tld_is_risky(self, clf):
        r = clf.classify("example.tk")
        assert r.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)
        assert r.score >= 4.0

    def test_xyz_tld_is_risky(self, clf):
        r = clf.classify("randomdomain.xyz")
        assert r.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)

    def test_risky_tld_signal_present(self, clf):
        r = clf.classify("test.ml")
        assert any("tld" in s.lower() or ".ml" in s for s in r.signals)

    def test_com_tld_not_risky_by_tld_alone(self, clf):
        r = clf.classify("legitimate-company.com")
        # .com is not a risky TLD
        assert not any(".com" in s.lower() and "risky" in s.lower() for s in r.signals)


# ---------------------------------------------------------------------------
# DomainClassifier — punycode / IDN
# ---------------------------------------------------------------------------

class TestDomainClassifierPunycode:
    def test_punycode_label_detected(self, clf):
        r = clf.classify("xn--pple-43d.com")  # Homoglyph for apple
        assert r.is_punycode is True
        assert any("punycode" in s.lower() or "idn" in s.lower() for s in r.signals)

    def test_punycode_is_at_least_suspicious(self, clf):
        r = clf.classify("xn--googl-jua.com")
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_plain_ascii_not_punycode(self, clf):
        r = clf.classify("example.com")
        assert r.is_punycode is False


# ---------------------------------------------------------------------------
# DomainClassifier — random / DGA-like domains
# ---------------------------------------------------------------------------

class TestDomainClassifierRandom:
    def test_low_vowel_domain_suspicious(self, clf):
        r = clf.classify("xkzmpqvnt.com")  # No vowels, 9 chars
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )
        assert any("machine" in s.lower() or "dga" in s.lower() or "random" in s.lower() for s in r.signals)

    def test_high_entropy_domain_flagged(self, clf):
        r = clf.classify("qzxwvrtpms.net")  # High consonant density
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_short_label_not_flagged_as_random(self, clf):
        # Short labels are excluded from the random heuristic
        r = clf.classify("xyz.com")
        assert not any("machine" in s.lower() or "dga" in s.lower() for s in r.signals)

    def test_normal_english_domain_not_random(self, clf):
        r = clf.classify("shoponline.com")
        assert not any("machine" in s.lower() or "dga" in s.lower() for s in r.signals)


# ---------------------------------------------------------------------------
# DomainClassifier — URL shorteners
# ---------------------------------------------------------------------------

class TestDomainClassifierUrlShortener:
    def test_bitly_is_shortener(self, clf):
        r = clf.classify("bit.ly")
        assert r.is_url_shortener is True
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_tinyurl_is_shortener(self, clf):
        r = clf.classify("tinyurl.com")
        assert r.is_url_shortener is True

    def test_shortener_signal_present(self, clf):
        r = clf.classify("bit.ly")
        assert any("shortener" in s.lower() for s in r.signals)

    def test_google_com_not_shortener(self, clf):
        r = clf.classify("google.com")
        assert r.is_url_shortener is False


# ---------------------------------------------------------------------------
# DomainClassifier — suspicious keywords
# ---------------------------------------------------------------------------

class TestDomainClassifierSuspiciousKeywords:
    def test_login_keyword_suspicious(self, clf):
        r = clf.classify("login-portal.net")
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_secure_keyword_flagged(self, clf):
        r = clf.classify("secure-banking.online")
        # Risky TLD (.online) + keyword → at least RISKY
        assert r.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)

    def test_brand_lookalike_paypal_flagged(self, clf):
        r = clf.classify("paypal-security.com")
        assert any("paypal" in s for s in r.signals)
        assert r.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_google_lookalike_flagged(self, clf):
        r = clf.classify("google-login-verify.info")
        # risky TLD + brand + keyword → MALICIOUS_INDICATOR
        assert r.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)


# ---------------------------------------------------------------------------
# DomainClassifier — long domains
# ---------------------------------------------------------------------------

class TestDomainClassifierLongDomain:
    def test_very_long_domain_flagged(self, clf):
        long_domain = "a" * 51 + ".com"
        r = clf.classify(long_domain)
        assert any("long" in s.lower() for s in r.signals)

    def test_normal_length_domain_not_flagged_for_length(self, clf):
        r = clf.classify("example.com")
        assert not any("long" in s.lower() for s in r.signals)


# ---------------------------------------------------------------------------
# DomainClassifier — result structure
# ---------------------------------------------------------------------------

class TestDomainClassifierStructure:
    def test_unknown_domain_returns_unknown_class(self, clf):
        r = clf.classify("perfectly-normal-site.com")
        assert r.classification == DomainClass.UNKNOWN
        assert r.score == 0.0

    def test_empty_domain_returns_unknown(self, clf):
        r = clf.classify("")
        assert r.classification == DomainClass.UNKNOWN
        assert r.confidence == 0.0

    def test_result_has_all_fields(self, clf):
        r = clf.classify("example.tk")
        assert isinstance(r, DomainClassification)
        assert r.domain
        assert isinstance(r.classification, DomainClass)
        assert 0.0 <= r.confidence <= 1.0
        assert 0.0 <= r.score <= 10.0
        assert isinstance(r.signals, list)
        assert isinstance(r.is_punycode, bool)
        assert isinstance(r.is_url_shortener, bool)

    def test_score_bounded(self, clf):
        # Combine many signals — score must not exceed 10.0
        # paypal brand + risky TLD (.tk) + random-looking chars
        r = clf.classify("xkzmpqvnt-paypal.tk")
        assert r.score <= 10.0


# ---------------------------------------------------------------------------
# EnrichmentService — local-only
# ---------------------------------------------------------------------------

class TestEnrichmentServiceLocal:
    def test_no_providers_by_default(self, service):
        assert service.has_external_providers is False

    def test_provider_names_empty_by_default(self, service):
        assert service.provider_names() == []

    def test_classify_domain_delegates_to_classifier(self, service):
        r = service.classify_domain("cloudflare.net")
        assert r.classification == DomainClass.TRUSTED

    def test_classify_url_extracts_hostname(self, service):
        r = service.classify_url("https://bit.ly/abc123")
        assert r.is_url_shortener is True
        assert r.classification in (DomainClass.SUSPICIOUS, DomainClass.RISKY)

    def test_score_domain_returns_float(self, service):
        score = service.score_domain("example.tk")
        assert isinstance(score, float)
        assert score >= 4.0  # risky TLD

    def test_explain_classification_contains_key_fields(self, service):
        result = service.classify_domain("paypal-secure.info")
        explanation = service.explain_classification(result)
        assert "Domain:" in explanation
        assert "Classification:" in explanation
        assert "Score:" in explanation
        assert "Confidence:" in explanation

    def test_explain_classification_lists_signals(self, service):
        result = service.classify_domain("bit.ly")
        explanation = service.explain_classification(result)
        assert "•" in explanation  # bullet for each signal


# ---------------------------------------------------------------------------
# EnrichmentService — merge_local_and_external_results
# ---------------------------------------------------------------------------

class TestEnrichmentServiceMerge:
    def _local(self) -> DomainClassification:
        return DomainClassifier().classify("unknown-site.com")

    def _provider_result(
        self,
        is_malicious: bool | None = None,
        is_suspicious: bool | None = None,
        reputation_score: float | None = None,
        error: str | None = None,
    ) -> ProviderResult:
        return ProviderResult(
            provider="test_provider",
            domain="unknown-site.com",
            reputation_score=reputation_score,
            confidence=0.8,
            categories=[],
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            raw={},
            checked_at=datetime.now(timezone.utc),
            error=error,
        )

    def test_no_external_returns_local(self, service):
        local = self._local()
        result = service.merge_local_and_external_results(local, [])
        assert isinstance(result, EnrichmentResult)
        assert result.final_classification == local.classification
        assert result.final_score == local.score
        assert result.external == []

    def test_malicious_verdict_elevates_to_malicious_indicator(self, service):
        local = self._local()
        ext = [self._provider_result(is_malicious=True, reputation_score=9.0)]
        result = service.merge_local_and_external_results(local, ext)
        assert result.final_classification == DomainClass.MALICIOUS_INDICATOR

    def test_suspicious_verdict_elevates_unknown(self, service):
        local = self._local()
        assert local.classification == DomainClass.UNKNOWN
        ext = [self._provider_result(is_suspicious=True, reputation_score=5.5)]
        result = service.merge_local_and_external_results(local, ext)
        assert result.final_classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_high_external_score_raises_classification(self, service):
        local = self._local()  # UNKNOWN, score=0.0
        ext = [self._provider_result(reputation_score=8.5)]
        result = service.merge_local_and_external_results(local, ext)
        assert result.final_score >= 8.0
        assert result.final_classification in (
            DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_error_result_does_not_escalate(self, service):
        local = self._local()
        ext = [self._provider_result(error="connection timeout")]
        result = service.merge_local_and_external_results(local, ext)
        # Error providers are excluded from verdict — local classification stands
        assert result.final_classification == local.classification

    def test_result_structure_complete(self, service):
        local = self._local()
        ext = [self._provider_result(is_suspicious=True, reputation_score=4.0)]
        result = service.merge_local_and_external_results(local, ext)
        assert isinstance(result, EnrichmentResult)
        assert result.domain == local.domain
        assert result.local is local
        assert result.external == ext
        assert isinstance(result.final_classification, DomainClass)
        assert 0.0 <= result.final_score <= 10.0
        assert 0.0 <= result.final_confidence <= 1.0
        assert result.verdict
        assert isinstance(result.checked_at, datetime)

    def test_confidence_boosted_by_multiple_agreeing_providers(self, service):
        local = self._local()
        ext = [
            self._provider_result(is_suspicious=True, reputation_score=5.0),
            self._provider_result(is_suspicious=True, reputation_score=5.5),
        ]
        result_single = service.merge_local_and_external_results(
            local, [self._provider_result(is_suspicious=True, reputation_score=5.0)]
        )
        result_double = service.merge_local_and_external_results(local, ext)
        assert result_double.final_confidence >= result_single.final_confidence


# ---------------------------------------------------------------------------
# No external network calls
# ---------------------------------------------------------------------------

class TestNoNetworkCalls:
    def test_no_providers_registered_by_default(self):
        svc = EnrichmentService()
        assert not svc.has_external_providers

    def test_classify_domain_makes_no_network_calls(self, monkeypatch):
        # Warm up tldextract cache first (it uses a local file cache)
        clf = DomainClassifier()
        clf.classify("warmup.com")

        def _raise(*args, **kwargs):
            raise AssertionError("Unexpected network call during local classification")

        monkeypatch.setattr(socket, "create_connection", _raise)
        svc = EnrichmentService()
        result = svc.classify_domain("evil.tk")
        assert result.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)

    def test_classify_url_makes_no_network_calls(self, monkeypatch):
        clf = DomainClassifier()
        clf.classify("warmup.com")

        def _raise(*args, **kwargs):
            raise AssertionError("Unexpected network call")

        monkeypatch.setattr(socket, "create_connection", _raise)
        svc = EnrichmentService()
        result = svc.classify_url("https://paypal-login.xyz/steal")
        assert result.classification in (
            DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_merge_with_empty_external_is_local_only(self):
        svc = EnrichmentService()
        local = svc.classify_domain("example.com")
        merged = svc.merge_local_and_external_results(local, [])
        assert merged.external == []
        assert merged.final_classification == local.classification
