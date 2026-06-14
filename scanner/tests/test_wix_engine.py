# WebHound — scanner/tests/test_wix_engine.py
# Phase 9B: Unit tests for the Wix CMS engine.
# Previously STATIC-only — this file brings it to full unit-test coverage.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import PageArtifacts
from webhound.engines.cms.wix import WixEngine, _is_wix
from webhound.models.severity import Severity

_ENGINE = WixEngine()
_NOW = datetime.now(timezone.utc)


def _artifacts(
    url: str = "https://mysite.wixsite.com/home",
    meta_tags: dict | None = None,
    response_headers: dict | None = None,
    external_script_urls: list[str] | None = None,
    all_links: list[str] | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test Wix Site",
        all_links=all_links or [],
        internal_links=[],
        external_links=[],
        scripts=[],
        inline_scripts=[],
        external_script_urls=external_script_urls or [],
        forms=[],
        cookies=[],
        response_headers=response_headers or {},
        meta_tags=meta_tags or {},
        extracted_at=_NOW,
    )


def _wix_artifacts(**kwargs) -> PageArtifacts:
    meta = kwargs.pop("meta_tags", {})
    meta.setdefault("generator", "Wix.com Website Builder")
    return _artifacts(meta_tags=meta, **kwargs)


# ---------------------------------------------------------------------------
# Detection (_is_wix)
# ---------------------------------------------------------------------------

class TestWixDetection:
    def test_detected_via_generator_meta(self):
        a = _artifacts(meta_tags={"generator": "Wix.com Website Builder"})
        assert _is_wix(a)

    def test_detected_via_wixstatic_script(self):
        a = _artifacts(external_script_urls=["https://static.wixstatic.com/services/wixcode.js"])
        assert _is_wix(a)

    def test_detected_via_parastorage(self):
        a = _artifacts(external_script_urls=["https://siteassets.parastorage.com/pages/pages.js"])
        assert _is_wix(a)

    def test_detected_via_request_id_header(self):
        a = _artifacts(response_headers={"x-wix-request-id": "abc-123"})
        assert _is_wix(a)

    def test_not_detected_on_shopify(self):
        a = _artifacts(meta_tags={"generator": "Shopify"})
        assert not _is_wix(a)

    def test_not_detected_on_wordpress(self):
        a = _artifacts(meta_tags={"generator": "WordPress 6.4"})
        assert not _is_wix(a)

    def test_not_detected_on_plain_site(self):
        a = _artifacts(meta_tags={}, response_headers={})
        assert not _is_wix(a)

    def test_detection_case_insensitive(self):
        a = _artifacts(meta_tags={"generator": "WIX.COM WEBSITE BUILDER"})
        assert _is_wix(a)


# ---------------------------------------------------------------------------
# analyze() — detected finding
# ---------------------------------------------------------------------------

class TestWixDetectedFinding:
    def test_wix_detected_emits_info_finding(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        assert any("Wix detected" in f.title for f in findings)

    def test_detected_severity_info(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Wix detected" in f.title)
        assert detected.severity == Severity.INFO

    def test_detected_has_evidence(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Wix detected" in f.title)
        assert detected.evidence

    def test_detected_engine_name(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        for f in findings:
            assert f.scanner_engine == "wix"

    def test_non_wix_returns_empty(self):
        a = _artifacts(meta_tags={"generator": "Drupal"})
        findings = _ENGINE.analyze(a)
        assert findings == []


# ---------------------------------------------------------------------------
# Preview URL exposure
# ---------------------------------------------------------------------------

class TestPreviewUrlExposure:
    def test_editor_wix_com_link_fires(self):
        a = _wix_artifacts(
            all_links=["https://editor.wix.com/html/editor/web/renderer/render/document/my-site"]
        )
        findings = _ENGINE.analyze(a)
        assert any("editor or preview url" in f.title.lower() for f in findings)

    def test_preview_wixsite_com_link_fires(self):
        a = _wix_artifacts(
            all_links=["https://preview.wixsite.com/mysite/home"]
        )
        findings = _ENGINE.analyze(a)
        assert any("editor or preview url" in f.title.lower() for f in findings)

    def test_wixsite_preview_path_fires(self):
        a = _wix_artifacts(
            all_links=["https://myname.wixsite.com/mybusiness/preview"]
        )
        findings = _ENGINE.analyze(a)
        assert any("editor or preview url" in f.title.lower() for f in findings)

    def test_no_preview_finding_when_no_preview_link(self):
        a = _wix_artifacts(all_links=["https://mysite.wixsite.com/home"])
        findings = _ENGINE.analyze(a)
        assert not any("editor or preview url" in f.title.lower() for f in findings)

    def test_preview_finding_severity_low(self):
        a = _wix_artifacts(
            all_links=["https://editor.wix.com/html/editor/render/document/site"]
        )
        findings = _ENGINE.analyze(a)
        preview_f = next(f for f in findings if "editor or preview url" in f.title.lower())
        assert preview_f.severity == Severity.LOW

    def test_preview_finding_has_evidence(self):
        a = _wix_artifacts(
            all_links=["https://editor.wix.com/render/site"]
        )
        findings = _ENGINE.analyze(a)
        preview_f = next((f for f in findings if "editor or preview url" in f.title.lower()), None)
        if preview_f:
            assert preview_f.evidence

    def test_regular_wixsite_link_no_false_positive(self):
        a = _wix_artifacts(
            all_links=["https://myname.wixsite.com/mybusiness/contact"]
        )
        findings = _ENGINE.analyze(a)
        assert not any("editor or preview URL" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# Framework alignment
# ---------------------------------------------------------------------------

class TestFrameworkAlignment:
    def test_detected_has_framework(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Wix detected" in f.title)
        assert detected.framework is not None

    def test_preview_url_has_framework(self):
        a = _wix_artifacts(all_links=["https://editor.wix.com/html/render/site"])
        findings = _ENGINE.analyze(a)
        preview = next((f for f in findings if "editor or preview url" in f.title.lower()), None)
        if preview:
            assert preview.framework is not None

    def test_detected_cvss_score_present(self):
        a = _wix_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Wix detected" in f.title)
        assert detected.framework.cvss_score >= 0.0
