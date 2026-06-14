# WebHound — scanner/tests/test_vulnerable_libs_engine.py
# Phase 9B: Unit tests for the vulnerable_libs engine.
# Previously STATIC-only — this file brings it to full unit-test coverage.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import ExtractedScript, PageArtifacts
from webhound.engines.javascript.vulnerable_libs import (
    VulnerableLibsEngine,
    _parse_cdn_url,
    _v,
)
from webhound.models.severity import Severity

_ENGINE = VulnerableLibsEngine()
_NOW = datetime.now(timezone.utc)


def _artifacts(
    url: str = "https://example.com/",
    external_script_urls: list[str] | None = None,
    scripts: list | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test",
        all_links=[],
        internal_links=[],
        external_links=[],
        scripts=scripts or [],
        inline_scripts=[],
        external_script_urls=external_script_urls or [],
        forms=[],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=_NOW,
    )


def _ext_script(src: str) -> ExtractedScript:
    return ExtractedScript(src=src, content=None, is_inline=False, is_external=True, is_external_domain=True)


# ---------------------------------------------------------------------------
# _parse_cdn_url
# ---------------------------------------------------------------------------

class TestParseCdnUrl:
    def test_jsdelivr_npm_style(self):
        result = _parse_cdn_url("https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js")
        assert result == ("jquery", "3.4.1")

    def test_unpkg_style(self):
        result = _parse_cdn_url("https://unpkg.com/lodash@4.17.20/lodash.min.js")
        assert result == ("lodash", "4.17.20")

    def test_cdnjs_style(self):
        result = _parse_cdn_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js")
        assert result == ("jquery", "3.4.1")

    def test_googleapis_style(self):
        result = _parse_cdn_url("https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js")
        assert result == ("jquery", "3.4.1")

    def test_bootstrapcdn_style(self):
        result = _parse_cdn_url("https://maxcdn.bootstrapcdn.com/bootstrap/4.2.0/js/bootstrap.min.js")
        assert result == ("bootstrap", "4.2.0")

    def test_jquery_filename_style(self):
        result = _parse_cdn_url("https://code.jquery.com/jquery-3.4.1.min.js")
        assert result is not None
        lib, ver = result
        assert "jquery" in lib
        assert ver == "3.4.1"

    def test_angularjs_alias(self):
        result = _parse_cdn_url("https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js")
        assert result is not None
        lib, _ = result
        assert lib == "angularjs"

    def test_non_cdn_url_returns_none(self):
        assert _parse_cdn_url("https://example.com/static/app.js") is None

    def test_unversioned_url_returns_none(self):
        assert _parse_cdn_url("https://cdn.example.com/jquery/dist/jquery.min.js") is None

    def test_empty_url_returns_none(self):
        assert _parse_cdn_url("") is None

    def test_lodash_alias(self):
        result = _parse_cdn_url("https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/lodash.min.js")
        assert result is not None
        lib, _ = result
        assert lib == "lodash"


# ---------------------------------------------------------------------------
# _v (version parsing)
# ---------------------------------------------------------------------------

class TestVersionParsing:
    def test_simple_semver(self):
        assert _v("3.4.1") == (3, 4, 1)

    def test_two_part(self):
        assert _v("3.4") == (3, 4)

    def test_one_part(self):
        assert _v("3") == (3,)

    def test_version_comparison(self):
        assert _v("3.5.0") > _v("3.4.1")
        assert _v("3.4.1") < _v("3.5.0")
        assert _v("4.17.21") == _v("4.17.21")


# ---------------------------------------------------------------------------
# analyze_script_urls — jQuery
# ---------------------------------------------------------------------------

class TestJqueryDetection:
    def test_vulnerable_jquery_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://code.jquery.com/jquery-3.4.1.min.js"],
            page_url="https://example.com/",
        )
        assert len(findings) == 1
        assert "jQuery" in findings[0].title

    def test_jquery_below_threshold_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"]
        )
        assert len(findings) == 1

    def test_safe_jquery_no_finding(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://code.jquery.com/jquery-3.5.0.min.js"]
        )
        assert findings == []

    def test_very_old_jquery_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"]
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_jquery_dedup_same_version(self):
        findings = _ENGINE.analyze_script_urls([
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js",
            "https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js",
        ])
        assert len(findings) == 1  # same (jQuery, 3.4.1) — deduped


# ---------------------------------------------------------------------------
# analyze_script_urls — lodash
# ---------------------------------------------------------------------------

class TestLodashDetection:
    def test_vulnerable_lodash_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/lodash@4.17.20/lodash.min.js"]
        )
        assert len(findings) == 1
        assert "lodash" in findings[0].title.lower()

    def test_safe_lodash_no_finding(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"]
        )
        assert findings == []


# ---------------------------------------------------------------------------
# analyze_script_urls — angularjs (EOL)
# ---------------------------------------------------------------------------

class TestAngularJsDetection:
    def test_any_angularjs_1x_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"]
        )
        assert len(findings) == 1
        assert "AngularJS" in findings[0].title

    def test_angularjs_severity_high(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.0/angular.min.js"]
        )
        assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# analyze_script_urls — bootstrap
# ---------------------------------------------------------------------------

class TestBootstrapDetection:
    def test_vulnerable_bootstrap_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://maxcdn.bootstrapcdn.com/bootstrap/4.2.0/js/bootstrap.min.js"]
        )
        assert len(findings) == 1

    def test_bootstrap_5_no_finding(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"]
        )
        assert findings == []


# ---------------------------------------------------------------------------
# analyze_script_urls — dompurify
# ---------------------------------------------------------------------------

class TestDomPurifyDetection:
    def test_vulnerable_dompurify_fires(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/dompurify@2.4.0/dist/purify.min.js"]
        )
        assert len(findings) == 1
        assert "DOMPurify" in findings[0].title

    def test_safe_dompurify_no_finding(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/dompurify@3.0.6/dist/purify.min.js"]
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Evidence and framework
# ---------------------------------------------------------------------------

class TestEvidenceAndFramework:
    def test_finding_has_evidence(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"],
            page_url="https://example.com/",
        )
        assert findings[0].evidence

    def test_finding_has_framework(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"]
        )
        assert findings[0].framework is not None

    def test_finding_engine_name(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"]
        )
        assert findings[0].scanner_engine == "vulnerable_libs"

    def test_finding_has_cves_in_metadata(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"]
        )
        assert findings[0].evidence[0].extra.get("cves")


# ---------------------------------------------------------------------------
# analyze() via PageArtifacts
# ---------------------------------------------------------------------------

class TestAnalyzeViaArtifacts:
    def test_via_artifacts_script_object(self):
        scripts = [_ext_script("https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js")]
        a = _artifacts(scripts=scripts)
        findings = _ENGINE.analyze(a)
        assert len(findings) == 1

    def test_no_findings_for_internal_scripts(self):
        scripts = [ExtractedScript(src=None, content="var x=1", is_inline=True, is_external=False, is_external_domain=False)]
        a = _artifacts(scripts=scripts)
        findings = _ENGINE.analyze(a)
        assert findings == []

    def test_empty_artifacts_no_findings(self):
        a = _artifacts()
        findings = _ENGINE.analyze(a)
        assert findings == []


# ---------------------------------------------------------------------------
# FP guard — minified scripts that are NOT from CDN
# ---------------------------------------------------------------------------

class TestFalsePositiveGuard:
    def test_non_cdn_url_ignored(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.myapp.com/static/vendor.min.js"]
        )
        assert findings == []

    def test_bundled_script_no_version_ignored(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://example.com/assets/app-bundle.min.js"]
        )
        assert findings == []

    def test_unknown_library_ignored(self):
        findings = _ENGINE.analyze_script_urls(
            ["https://cdn.jsdelivr.net/npm/some-random-lib@1.2.3/dist/lib.js"]
        )
        assert findings == []
