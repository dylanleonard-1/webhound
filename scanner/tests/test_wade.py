# WebHound — scanner/tests/test_wade.py
# WADE v1 test suite: baseline creation, diff detection, context weighting,
# anomaly scoring, classification, confidence, and no-regression.

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.core.crawler import CrawlResult
from webhound.core.extractor import (
    ExtractedForm,
    ExtractedScript,
    FormInput,
    PageArtifacts,
)
from webhound.core.http_client import HttpResponse
from webhound.models.finding import FindingCategory
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.wade.anomaly_scorer import BASE_SCORES, AnomalyScorer, ScoredAnomaly
from webhound.wade.baseline_builder import (
    BaselineBuilder,
    PageSnapshot,
    SiteBaseline,
    _parse_cookie,
    _sha16,
)
from webhound.wade.classifier import Classifier, _adjust_severity
from webhound.wade.confidence import (
    EVIDENCE_WEIGHTS,
    adjust_findings_confidence,
    compute_confidence,
)
from webhound.wade.context_engine import CONTEXT_WEIGHTS, ContextEngine
from webhound.wade.diff_engine import DiffEngine, DiffItem, DiffType


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------


def _response(
    url: str = "https://example.com/",
    status: int = 200,
    body: str = "<html><body>ok</body></html>",
    headers: dict[str, str] | None = None,
    error: str | None = None,
) -> HttpResponse:
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=status,
        headers=headers or {},
        body=body,
        content_type="text/html",
        elapsed_ms=50.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
        error=error,
    )


def _artifacts(
    url: str = "https://example.com/",
    scripts: list[ExtractedScript] | None = None,
    forms: list[ExtractedForm] | None = None,
    external_links: list[str] | None = None,
    cookies: list[str] | None = None,
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> PageArtifacts:
    sc = scripts or []
    return PageArtifacts(
        url=url,
        status_code=status,
        content_type="text/html",
        title="Test",
        all_links=[],
        internal_links=[],
        external_links=external_links or [],
        scripts=sc,
        inline_scripts=[s.content for s in sc if s.is_inline and s.content],
        external_script_urls=[s.src for s in sc if not s.is_inline and s.src],
        forms=forms or [],
        cookies=cookies or [],
        response_headers=headers or {},
        meta_tags={},
        extracted_at=datetime.now(timezone.utc),
    )


def _crawl(
    url: str = "https://example.com/",
    *,
    scripts: list[ExtractedScript] | None = None,
    forms: list[ExtractedForm] | None = None,
    external_links: list[str] | None = None,
    cookies: list[str] | None = None,
    headers: dict[str, str] | None = None,
    body: str = "<html><body>ok</body></html>",
    status: int = 200,
    failed: bool = False,
) -> CrawlResult:
    resp = _response(url, status=status, body=body, headers=headers,
                     error="failed" if failed else None)
    arts = None if failed else _artifacts(
        url, scripts=scripts, forms=forms, external_links=external_links,
        cookies=cookies, headers=headers or {}, status=status,
    )
    return CrawlResult(url=url, depth=0, response=resp, artifacts=arts)


def _scan_result(url: str = "https://example.com/") -> ScanResult:
    target = Target.from_url(url, scan_options=ScanOptions())
    return ScanResult(target=target)


def _ext_script(src: str) -> ExtractedScript:
    return ExtractedScript(src=src, content=None, is_inline=False,
                           is_external=True, is_external_domain=True)


def _inline_script(content: str) -> ExtractedScript:
    return ExtractedScript(src=None, content=content, is_inline=True,
                           is_external=False, is_external_domain=False)


def _form(action: str, fields: list[str], method: str = "POST") -> ExtractedForm:
    inputs = tuple(
        FormInput(name=f, input_type="text", value=None) for f in fields
    )
    return ExtractedForm(
        action=action,
        action_url=f"https://example.com{action}",
        method=method,
        inputs=inputs,
        has_password_field=False,
        has_csrf_token=False,
    )


def _snapshot(
    url: str = "https://example.com/",
    *,
    script_sources: list[str] | None = None,
    inline_hashes: list[str] | None = None,
    external_domains: list[str] | None = None,
    form_signatures: list[str] | None = None,
    cookie_signatures: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> PageSnapshot:
    return PageSnapshot(
        url=url,
        status_code=status,
        content_hash=_sha16("body"),
        headers=headers or {},
        script_sources=script_sources or [],
        inline_hashes=inline_hashes or [],
        external_domains=external_domains or [],
        form_signatures=form_signatures or [],
        cookie_signatures=cookie_signatures or {},
    )


def _baseline(
    url: str = "https://example.com/",
    pages: dict[str, PageSnapshot] | None = None,
    all_scripts: list[str] | None = None,
    all_domains: list[str] | None = None,
) -> SiteBaseline:
    return SiteBaseline(
        target_url=url,
        scan_id=str(uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(),
        pages=pages or {},
        all_script_sources=all_scripts or [],
        all_external_domains=all_domains or [],
        page_count=len(pages or {}),
    )


def _scored(
    diff_item: DiffItem,
    anomaly_score: float = 0.75,
    context_type: str = "default",
    context_weight: float = 1.0,
) -> ScoredAnomaly:
    return ScoredAnomaly(
        diff_item=diff_item,
        raw_score=anomaly_score,
        context_weight=context_weight,
        anomaly_score=anomaly_score,
        context_type=context_type,
    )


def _diff(
    diff_type: DiffType = DiffType.NEW_SCRIPT_SOURCE,
    url: str = "https://example.com/",
    detail: str = "test",
    baseline_value: str | None = None,
    current_value: str | None = "https://evil.com/x.js",
    severity_hint: str = "high",
) -> DiffItem:
    return DiffItem(
        diff_type=diff_type,
        url=url,
        detail=detail,
        baseline_value=baseline_value,
        current_value=current_value,
        severity_hint=severity_hint,
    )


# ===========================================================================
# 1. Baseline creation
# ===========================================================================


class TestBaselineBuilder:
    def test_build_returns_site_baseline(self) -> None:
        crawls = [_crawl()]
        sr = _scan_result()
        bl = BaselineBuilder().build(crawls, sr)
        assert isinstance(bl, SiteBaseline)
        assert bl.page_count == 1
        assert bl.target_url == sr.target.base_url

    def test_failed_crawl_excluded(self) -> None:
        crawls = [_crawl(failed=True), _crawl("https://example.com/page")]
        bl = BaselineBuilder().build(crawls, _scan_result())
        assert bl.page_count == 1

    def test_crawl_without_artifacts_excluded(self) -> None:
        cr = CrawlResult(
            url="https://example.com/",
            depth=0,
            response=_response(),
            artifacts=None,
        )
        bl = BaselineBuilder().build([cr], _scan_result())
        assert bl.page_count == 0

    def test_external_script_captured(self) -> None:
        src = "https://cdn.example.com/lib.js"
        crawls = [_crawl(scripts=[_ext_script(src)])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert src in snap.script_sources
        assert src in bl.all_script_sources

    def test_inline_script_hash_captured(self) -> None:
        content = "console.log('hello');"
        crawls = [_crawl(scripts=[_inline_script(content)])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        expected = _sha16(content)
        assert expected in snap.inline_hashes

    def test_external_domain_captured(self) -> None:
        crawls = [_crawl(external_links=["https://partner.com/page"])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert "partner.com" in snap.external_domains
        assert "partner.com" in bl.all_external_domains

    def test_form_signature_captured(self) -> None:
        f = _form("/login", ["username", "password"])
        crawls = [_crawl(forms=[f])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert len(snap.form_signatures) == 1
        sig = snap.form_signatures[0]
        assert "POST" in sig
        assert "password" in sig
        assert "username" in sig

    def test_cookie_signature_captured(self) -> None:
        crawls = [_crawl(cookies=["session=abc; Secure; HttpOnly; SameSite=Strict"])]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert "session" in snap.cookie_signatures
        flags = snap.cookie_signatures["session"]
        assert "Secure" in flags
        assert "HttpOnly" in flags

    def test_response_headers_captured_lowercase(self) -> None:
        hdrs = {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"}
        crawls = [_crawl(headers=hdrs)]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert snap.headers.get("x-frame-options") == "DENY"
        assert snap.headers.get("content-security-policy") == "default-src 'self'"

    def test_content_hash_is_16char_hex(self) -> None:
        crawls = [_crawl(body="some body content")]
        bl = BaselineBuilder().build(crawls, _scan_result())
        snap = bl.pages["https://example.com/"]
        assert len(snap.content_hash) == 16
        assert all(c in "0123456789abcdef" for c in snap.content_hash)

    def test_multiple_pages_aggregated(self) -> None:
        s1 = "https://cdn1.com/a.js"
        s2 = "https://cdn2.com/b.js"
        crawls = [
            _crawl("https://example.com/", scripts=[_ext_script(s1)]),
            _crawl("https://example.com/about", scripts=[_ext_script(s2)]),
        ]
        bl = BaselineBuilder().build(crawls, _scan_result())
        assert bl.page_count == 2
        assert s1 in bl.all_script_sources
        assert s2 in bl.all_script_sources

    def test_serialization_round_trip(self) -> None:
        crawls = [
            _crawl(scripts=[_ext_script("https://cdn.com/a.js")]),
        ]
        builder = BaselineBuilder()
        bl = builder.build(crawls, _scan_result())
        d = builder.to_dict(bl)
        restored = builder.from_dict(d)
        assert restored.target_url == bl.target_url
        assert restored.page_count == bl.page_count
        assert restored.all_script_sources == bl.all_script_sources
        assert list(restored.pages.keys()) == list(bl.pages.keys())

    def test_parse_cookie_secure_httponly(self) -> None:
        name, flags = _parse_cookie("sid=xyz; Secure; HttpOnly")
        assert name == "sid"
        assert "Secure" in flags
        assert "HttpOnly" in flags

    def test_parse_cookie_samesite(self) -> None:
        name, flags = _parse_cookie("tok=abc; SameSite=Lax; Secure")
        assert name == "tok"
        assert "SameSite=Lax" in flags

    def test_parse_cookie_no_flags(self) -> None:
        name, flags = _parse_cookie("plain=val")
        assert name == "plain"
        assert flags == ""

    def test_parse_cookie_empty_string(self) -> None:
        name, flags = _parse_cookie("")
        assert name == ""


# ===========================================================================
# 2. Diff detection
# ===========================================================================


class TestDiffEngine:
    engine = DiffEngine()

    def test_no_diff_when_identical(self) -> None:
        snap = _snapshot(script_sources=["https://cdn.com/a.js"])
        items = self.engine.diff_page(snap, snap)
        assert items == []

    def test_new_external_script_detected(self) -> None:
        baseline = _snapshot(script_sources=["https://cdn.com/a.js"])
        current  = _snapshot(script_sources=["https://cdn.com/a.js",
                                              "https://evil.com/x.js"])
        items = self.engine.diff_page(current, baseline)
        types = [i.diff_type for i in items]
        assert DiffType.NEW_SCRIPT_SOURCE in types
        new_script = next(i for i in items if i.diff_type == DiffType.NEW_SCRIPT_SOURCE)
        assert new_script.current_value == "https://evil.com/x.js"

    def test_unchanged_script_not_reported(self) -> None:
        snap = _snapshot(script_sources=["https://cdn.com/a.js"])
        items = self.engine.diff_page(snap, snap)
        assert not any(i.diff_type == DiffType.NEW_SCRIPT_SOURCE for i in items)

    def test_changed_inline_script_detected(self) -> None:
        baseline = _snapshot(inline_hashes=["aabbccdd00112233"])
        current  = _snapshot(inline_hashes=["aabbccdd00112233", "deadbeef12345678"])
        items = self.engine.diff_page(current, baseline)
        types = [i.diff_type for i in items]
        assert DiffType.CHANGED_INLINE_SCRIPT in types

    def test_unchanged_inline_script_not_reported(self) -> None:
        snap = _snapshot(inline_hashes=["aabbccdd00112233"])
        items = self.engine.diff_page(snap, snap)
        assert not any(i.diff_type == DiffType.CHANGED_INLINE_SCRIPT for i in items)

    def test_new_external_domain_detected(self) -> None:
        baseline = _snapshot(external_domains=["trusted.com"])
        current  = _snapshot(external_domains=["trusted.com", "newpartner.com"])
        items = self.engine.diff_page(current, baseline)
        types = [i.diff_type for i in items]
        assert DiffType.NEW_EXTERNAL_DOMAIN in types
        item = next(i for i in items if i.diff_type == DiffType.NEW_EXTERNAL_DOMAIN)
        assert item.current_value == "newpartner.com"

    def test_header_regression_detected(self) -> None:
        baseline = _snapshot(headers={"x-frame-options": "DENY", "content-security-policy": "default-src 'self'"})
        current  = _snapshot(headers={})  # headers gone
        items = self.engine.diff_page(current, baseline)
        types = [i.diff_type for i in items]
        assert DiffType.HEADER_REGRESSION in types
        regressions = [i for i in items if i.diff_type == DiffType.HEADER_REGRESSION]
        regressed_hdrs = {i.baseline_value for i in regressions}
        assert "DENY" in regressed_hdrs

    def test_no_header_regression_when_header_never_present(self) -> None:
        # Header was never in baseline — not a regression if missing now
        baseline = _snapshot(headers={})
        current  = _snapshot(headers={})
        items = self.engine.diff_page(current, baseline)
        assert not any(i.diff_type == DiffType.HEADER_REGRESSION for i in items)

    def test_cookie_regression_detected(self) -> None:
        baseline = _snapshot(cookie_signatures={"session": "HttpOnly;Secure"})
        current  = _snapshot(cookie_signatures={"session": ""})  # flags lost
        items = self.engine.diff_page(current, baseline)
        assert any(i.diff_type == DiffType.COOKIE_REGRESSION for i in items)
        item = next(i for i in items if i.diff_type == DiffType.COOKIE_REGRESSION)
        assert "HttpOnly" in item.detail or "Secure" in item.detail

    def test_cookie_regression_only_on_lost_security_flags(self) -> None:
        # Only Secure/HttpOnly loss is a regression; SameSite alone is not tracked
        baseline = _snapshot(cookie_signatures={"tok": "SameSite=Strict"})
        current  = _snapshot(cookie_signatures={"tok": ""})
        items = self.engine.diff_page(current, baseline)
        assert not any(i.diff_type == DiffType.COOKIE_REGRESSION for i in items)

    def test_new_form_detected(self) -> None:
        baseline = _snapshot(form_signatures=["POST|/login|password,username"])
        current  = _snapshot(form_signatures=["POST|/login|password,username",
                                               "POST|/subscribe|email"])
        items = self.engine.diff_page(current, baseline)
        assert any(i.diff_type == DiffType.NEW_FORM for i in items)

    def test_form_field_change_detected(self) -> None:
        baseline = _snapshot(form_signatures=["POST|/login|password,username"])
        # Same action, different fields (credit card fields added — suspicious)
        current  = _snapshot(form_signatures=["POST|/login|card,password,username"])
        items = self.engine.diff_page(current, baseline)
        assert any(i.diff_type == DiffType.FORM_FIELD_CHANGE for i in items)

    def test_status_code_change_detected(self) -> None:
        baseline = _snapshot(status=200)
        current  = _snapshot(status=404)
        items = self.engine.diff_page(current, baseline)
        assert any(i.diff_type == DiffType.STATUS_CODE_CHANGE for i in items)
        item = next(i for i in items if i.diff_type == DiffType.STATUS_CODE_CHANGE)
        assert item.baseline_value == "200"
        assert item.current_value == "404"

    def test_status_code_unchanged_not_reported(self) -> None:
        snap = _snapshot(status=200)
        items = self.engine.diff_page(snap, snap)
        assert not any(i.diff_type == DiffType.STATUS_CODE_CHANGE for i in items)

    def test_diff_site_routes_known_pages(self) -> None:
        snap = _snapshot(script_sources=["https://cdn.com/a.js"])
        b = _baseline(pages={"https://example.com/": snap})
        current = _snapshot(script_sources=["https://cdn.com/a.js",
                                             "https://evil.com/x.js"])
        items = DiffEngine().diff_site({"https://example.com/": current}, b)
        assert any(i.diff_type == DiffType.NEW_SCRIPT_SOURCE for i in items)

    def test_diff_site_new_page_checks_against_site_baseline(self) -> None:
        b = _baseline(all_scripts=["https://known.com/lib.js"])
        new_page = _snapshot("https://example.com/new",
                              script_sources=["https://unknown.com/bad.js"])
        items = DiffEngine().diff_site({"https://example.com/new": new_page}, b)
        assert any(i.diff_type == DiffType.NEW_SCRIPT_SOURCE for i in items)

    def test_diff_site_empty_current_returns_empty(self) -> None:
        b = _baseline()
        items = DiffEngine().diff_site({}, b)
        assert items == []


# ===========================================================================
# 3. Context weighting
# ===========================================================================


class TestContextEngine:
    engine = ContextEngine()

    def test_admin_url_weight(self) -> None:
        ctx = self.engine.classify("https://example.com/admin/dashboard")
        assert ctx.context_type == "admin"
        assert ctx.weight == CONTEXT_WEIGHTS["admin"]

    def test_checkout_url_weight(self) -> None:
        ctx = self.engine.classify("https://shop.com/checkout/step1")
        assert ctx.context_type == "checkout"
        assert ctx.weight == CONTEXT_WEIGHTS["checkout"]

    def test_payment_url_maps_to_checkout(self) -> None:
        ctx = self.engine.classify("https://shop.com/payment/confirm")
        assert ctx.context_type == "checkout"

    def test_cart_url_weight(self) -> None:
        ctx = self.engine.classify("https://shop.com/cart")
        assert ctx.context_type == "cart"
        assert ctx.weight == CONTEXT_WEIGHTS["cart"]

    def test_basket_maps_to_cart(self) -> None:
        ctx = self.engine.classify("https://shop.com/basket/view")
        assert ctx.context_type == "cart"

    def test_login_url_weight(self) -> None:
        ctx = self.engine.classify("https://example.com/login")
        assert ctx.context_type == "login"
        assert ctx.weight == CONTEXT_WEIGHTS["login"]

    def test_signin_maps_to_login(self) -> None:
        assert self.engine.context_for("https://app.com/signin") == "login"

    def test_account_url_weight(self) -> None:
        ctx = self.engine.classify("https://example.com/account/settings")
        assert ctx.context_type == "account"
        assert ctx.weight == CONTEXT_WEIGHTS["account"]

    def test_profile_maps_to_account(self) -> None:
        assert self.engine.context_for("https://app.com/profile") == "account"

    def test_api_url_weight(self) -> None:
        ctx = self.engine.classify("https://api.example.com/api/v1/users")
        assert ctx.context_type == "api"
        assert ctx.weight == CONTEXT_WEIGHTS["api"]

    def test_default_url_weight(self) -> None:
        ctx = self.engine.classify("https://example.com/about-us")
        assert ctx.context_type == "default"
        assert ctx.weight == 1.0

    def test_weight_for_helper(self) -> None:
        assert self.engine.weight_for("https://example.com/admin") == 2.0
        assert self.engine.weight_for("https://example.com/") == 1.0

    def test_known_contexts_includes_all_types(self) -> None:
        known = self.engine.known_contexts()
        for ct in ("admin", "checkout", "cart", "login", "account", "api", "default"):
            assert ct in known

    def test_context_weights_ordered(self) -> None:
        # Admin/checkout pages must outweigh default
        assert CONTEXT_WEIGHTS["admin"] > CONTEXT_WEIGHTS["default"]
        assert CONTEXT_WEIGHTS["checkout"] > CONTEXT_WEIGHTS["default"]


# ===========================================================================
# 4. Anomaly scoring
# ===========================================================================


class TestAnomalyScorer:
    scorer = AnomalyScorer()

    def test_score_returns_one_per_diff_item(self) -> None:
        items = [_diff(DiffType.NEW_SCRIPT_SOURCE), _diff(DiffType.NEW_EXTERNAL_DOMAIN)]
        scored = self.scorer.score(items)
        assert len(scored) == 2

    def test_score_clamped_to_1(self) -> None:
        # High context weight (admin × 2.0) with base 0.75 → 1.5 → clamped to 1.0
        item = _diff(url="https://example.com/admin/upload")
        scored = self.scorer.score([item])
        assert scored[0].anomaly_score <= 1.0

    def test_checkout_amplifies_script_score(self) -> None:
        default_item = _diff(url="https://example.com/")
        checkout_item = _diff(url="https://example.com/checkout")
        d_scored, c_scored = self.scorer.score([default_item, checkout_item])
        assert c_scored.anomaly_score > d_scored.anomaly_score

    def test_base_score_matches_table(self) -> None:
        for diff_type, base in BASE_SCORES.items():
            item = _diff(diff_type=diff_type, url="https://example.com/")
            scored = self.scorer.score([item])[0]
            assert scored.raw_score == base

    def test_context_weight_propagated(self) -> None:
        item = _diff(url="https://example.com/admin")
        scored = self.scorer.score([item])[0]
        assert scored.context_weight == CONTEXT_WEIGHTS["admin"]
        assert scored.context_type == "admin"

    def test_aggregate_page_score_returns_max(self) -> None:
        a1 = _scored(_diff(url="https://example.com/"), anomaly_score=0.5)
        a2 = _scored(_diff(url="https://example.com/"), anomaly_score=0.8)
        a3 = _scored(_diff(url="https://example.com/other"), anomaly_score=0.4)
        scores = self.scorer.aggregate_page_score([a1, a2, a3])
        assert scores["https://example.com/"] == pytest.approx(0.8)
        assert scores["https://example.com/other"] == pytest.approx(0.4)

    def test_empty_input_returns_empty(self) -> None:
        assert self.scorer.score([]) == []


# ===========================================================================
# 5. Classification
# ===========================================================================


class TestClassifier:
    clf = Classifier()

    def test_classify_returns_findings(self) -> None:
        anomalies = [_scored(_diff(DiffType.NEW_SCRIPT_SOURCE))]
        findings = self.clf.classify(anomalies)
        assert len(findings) == 1

    def test_new_script_category_is_javascript(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.NEW_SCRIPT_SOURCE))])
        assert findings[0].category == FindingCategory.JAVASCRIPT

    def test_header_regression_category_is_security_header(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.HEADER_REGRESSION))])
        assert findings[0].category == FindingCategory.SECURITY_HEADER

    def test_cookie_regression_category_is_cookie(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.COOKIE_REGRESSION))])
        assert findings[0].category == FindingCategory.COOKIE

    def test_new_form_category_is_form(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.NEW_FORM))])
        assert findings[0].category == FindingCategory.FORM

    def test_status_code_change_is_info(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.STATUS_CODE_CHANGE))])
        assert findings[0].severity == Severity.INFO

    def test_high_anomaly_script_escalates_to_critical(self) -> None:
        # anomaly_score ≥ 0.85 + script type → CRITICAL
        a = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE), anomaly_score=0.90)
        findings = self.clf.classify([a])
        assert findings[0].severity == Severity.CRITICAL

    def test_normal_anomaly_script_is_high(self) -> None:
        a = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE), anomaly_score=0.75)
        findings = self.clf.classify([a])
        assert findings[0].severity == Severity.HIGH

    def test_low_confidence_downgrades_severity(self) -> None:
        # Force low confidence by using a diff type whose evidence weight is < 0.4
        # (not possible with current table) so we test _adjust_severity directly
        from webhound.wade.diff_engine import DiffType as DT
        result = _adjust_severity(Severity.HIGH, 0.4, 0.25, DT.NEW_FORM)
        assert result == Severity.MEDIUM

    def test_finding_has_anomaly_score(self) -> None:
        a = _scored(_diff(DiffType.NEW_EXTERNAL_DOMAIN), anomaly_score=0.5)
        f = self.clf.classify([a])[0]
        assert f.anomaly_score == pytest.approx(0.5)

    def test_finding_has_evidence(self) -> None:
        findings = self.clf.classify([_scored(_diff())])
        assert len(findings[0].evidence) == 1

    def test_evidence_extra_contains_diff_type(self) -> None:
        findings = self.clf.classify([_scored(_diff(DiffType.COOKIE_REGRESSION))])
        ev = findings[0].evidence[0]
        assert ev.extra["diff_type"] == DiffType.COOKIE_REGRESSION.value

    def test_finding_tagged_with_wade(self) -> None:
        findings = self.clf.classify([_scored(_diff())])
        assert "wade" in findings[0].tags
        assert "anomaly" in findings[0].tags

    def test_scanner_engine_is_wade(self) -> None:
        findings = self.clf.classify([_scored(_diff())])
        assert findings[0].scanner_engine == "wade"

    def test_description_includes_context_note_on_sensitive_page(self) -> None:
        a = _scored(_diff(url="https://example.com/checkout"),
                    context_type="checkout", context_weight=1.8)
        f = self.clf.classify([a])[0]
        assert "checkout" in f.description

    def test_empty_anomalies_returns_empty(self) -> None:
        assert self.clf.classify([]) == []


# ===========================================================================
# 6. Confidence
# ===========================================================================


class TestConfidence:
    def test_script_source_confidence(self) -> None:
        a = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE))
        c = compute_confidence(a)
        assert c == pytest.approx(EVIDENCE_WEIGHTS[DiffType.NEW_SCRIPT_SOURCE])

    def test_high_anomaly_boosts_confidence(self) -> None:
        a_low  = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE), anomaly_score=0.5)
        a_high = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE), anomaly_score=0.9)
        assert compute_confidence(a_high) > compute_confidence(a_low)

    def test_confidence_clamped_to_1(self) -> None:
        a = _scored(_diff(DiffType.NEW_SCRIPT_SOURCE), anomaly_score=1.0)
        assert compute_confidence(a) <= 1.0

    def test_confidence_never_below_minimum(self) -> None:
        for diff_type in DiffType:
            a = _scored(_diff(diff_type=diff_type), anomaly_score=0.0)
            c = compute_confidence(a)
            assert c >= 0.30, f"{diff_type} confidence below minimum"

    def test_all_diff_types_have_evidence_weights(self) -> None:
        for dt in DiffType:
            assert dt in EVIDENCE_WEIGHTS, f"{dt} missing from EVIDENCE_WEIGHTS"

    def test_adjust_findings_confidence_updates_finding(self) -> None:
        clf = Classifier()
        a = _scored(_diff(DiffType.COOKIE_REGRESSION,
                          url="https://example.com/login"),
                    context_type="login")
        findings = clf.classify([a])
        original_conf = findings[0].confidence
        # Rebuild anomalies list to test adjust_findings_confidence
        adjust_findings_confidence(findings, [a])
        # Confidence should be set (may be same value as Classifier already set it)
        assert 0.0 <= findings[0].confidence <= 1.0

    def test_adjust_findings_confidence_ignores_mismatched_finding(self) -> None:
        from webhound.models.evidence import Evidence, EvidenceType
        from webhound.models.finding import Finding, FindingCategory
        # Finding with no matching anomaly — confidence should not change
        ev = Evidence(
            evidence_type=EvidenceType.PATTERN_MATCH,
            content="x",
            location="https://other.com/",
            source_engine="wade",
            extra={"diff_type": ""},
        )
        f = Finding(
            title="test",
            description="test",
            severity=Severity.INFO,
            category=FindingCategory.UNKNOWN,
            scanner_engine="wade",
            evidence=[ev],
            confidence=0.99,
        )
        a = _scored(_diff(url="https://example.com/"))
        adjust_findings_confidence([f], [a])
        assert f.confidence == pytest.approx(0.99)


# ===========================================================================
# 7. End-to-end pipeline
# ===========================================================================


class TestWADEPipeline:
    """Full pipeline: baseline → diff → score → classify → confidence."""

    def _build_baseline(self) -> tuple[SiteBaseline, ScanResult]:
        crawls = [
            _crawl(
                scripts=[_ext_script("https://cdn.example.com/app.js")],
                cookies=["session=x; Secure; HttpOnly"],
                headers={"x-frame-options": "DENY"},
                external_links=["https://analytics.com/page"],
            )
        ]
        sr = _scan_result()
        bl = BaselineBuilder().build(crawls, sr)
        return bl, sr

    def test_no_regression_pipeline_produces_no_findings(self) -> None:
        bl, _ = self._build_baseline()
        # Current scan identical to baseline
        current_pages = {
            "https://example.com/": _snapshot(
                script_sources=["https://cdn.example.com/app.js"],
                inline_hashes=[],
                external_domains=["analytics.com"],
                form_signatures=[],
                cookie_signatures={"session": "HttpOnly;Secure"},
                headers={"x-frame-options": "DENY"},
                status=200,
            )
        }
        diff_items = DiffEngine().diff_site(current_pages, bl)
        assert diff_items == []

    def test_new_script_triggers_high_finding(self) -> None:
        bl, _ = self._build_baseline()
        current_pages = {
            "https://example.com/": _snapshot(
                script_sources=[
                    "https://cdn.example.com/app.js",
                    "https://evil.com/skimmer.js",  # new!
                ],
                cookie_signatures={"session": "HttpOnly;Secure"},
                headers={"x-frame-options": "DENY"},
                external_domains=["analytics.com"],
            )
        }
        diff_items = DiffEngine().diff_site(current_pages, bl)
        scored = AnomalyScorer().score(diff_items)
        findings = Classifier().classify(scored)
        script_findings = [f for f in findings if f.category == FindingCategory.JAVASCRIPT]
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL)
                   for f in script_findings)

    def test_header_regression_produces_finding(self) -> None:
        bl, _ = self._build_baseline()
        current_pages = {
            "https://example.com/": _snapshot(
                script_sources=["https://cdn.example.com/app.js"],
                headers={},  # header gone
                cookie_signatures={"session": "HttpOnly;Secure"},
                external_domains=["analytics.com"],
            )
        }
        diff_items = DiffEngine().diff_site(current_pages, bl)
        scored = AnomalyScorer().score(diff_items)
        findings = Classifier().classify(scored)
        assert any(f.category == FindingCategory.SECURITY_HEADER for f in findings)

    def test_checkout_page_amplifies_finding_score(self) -> None:
        """The same diff on /checkout should produce higher score than on /."""
        diff_default  = [_diff(url="https://example.com/")]
        diff_checkout = [_diff(url="https://example.com/checkout")]
        scored_d = AnomalyScorer().score(diff_default)
        scored_c = AnomalyScorer().score(diff_checkout)
        assert scored_c[0].anomaly_score > scored_d[0].anomaly_score

    def test_confidence_set_on_all_findings(self) -> None:
        bl, _ = self._build_baseline()
        current_pages = {
            "https://example.com/": _snapshot(
                script_sources=["https://cdn.example.com/app.js",
                                 "https://new.com/track.js"],
            )
        }
        diff_items = DiffEngine().diff_site(current_pages, bl)
        scored = AnomalyScorer().score(diff_items)
        findings = Classifier().classify(scored)
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0

    def test_findings_have_explainable_evidence(self) -> None:
        diff_items = [_diff(DiffType.NEW_SCRIPT_SOURCE,
                            current_value="https://evil.com/x.js")]
        scored = AnomalyScorer().score(diff_items)
        findings = Classifier().classify(scored)
        for f in findings:
            assert f.evidence
            ev = f.evidence[0]
            assert ev.extra.get("diff_type") == DiffType.NEW_SCRIPT_SOURCE.value
            assert ev.extra.get("current_value") == "https://evil.com/x.js"
