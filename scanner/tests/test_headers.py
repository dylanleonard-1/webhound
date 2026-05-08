# WebHound — scanner/tests/test_headers.py
# Tests for CspEngine — deep Content-Security-Policy structural analysis.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.core.http_client import HttpResponse
from webhound.engines.headers.csp_engine import CspEngine, _parse_csp
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URL = "https://example.com/"
_ENGINE = CspEngine()


def _resp(
    csp: str | None = None,
    csp_ro: str | None = None,
    url: str = _URL,
) -> HttpResponse:
    headers: dict[str, str] = {"content-type": "text/html"}
    if csp is not None:
        headers["content-security-policy"] = csp
    if csp_ro is not None:
        headers["content-security-policy-report-only"] = csp_ro
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=200,
        headers=headers,
        body="<html></html>",
        content_type="text/html",
        elapsed_ms=50.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _has(findings, fragment: str) -> bool:
    return any(fragment.lower() in t.lower() for t in _titles(findings))


# ---------------------------------------------------------------------------
# _parse_csp helper
# ---------------------------------------------------------------------------


class TestParseCsp:
    def test_parses_single_directive(self):
        d = _parse_csp("default-src 'self'")
        assert "default-src" in d
        assert "'self'" in d["default-src"]

    def test_parses_multiple_directives(self):
        d = _parse_csp("default-src 'self'; script-src 'none'; object-src 'none'")
        assert "default-src" in d
        assert "script-src" in d
        assert "object-src" in d

    def test_directive_name_is_lowercase(self):
        d = _parse_csp("Default-Src 'self'")
        assert "default-src" in d

    def test_multiple_source_values(self):
        d = _parse_csp("script-src 'self' cdn.example.com")
        assert "'self'" in d["script-src"]
        assert "cdn.example.com" in d["script-src"]

    def test_empty_string_returns_empty_dict(self):
        d = _parse_csp("")
        assert d == {}

    def test_trailing_semicolon_ignored(self):
        d = _parse_csp("default-src 'self';")
        assert "default-src" in d


# ---------------------------------------------------------------------------
# No CSP at all — engine defers to SecurityHeadersEngine
# ---------------------------------------------------------------------------


def test_no_csp_no_findings():
    """Engine produces no findings when there is no CSP — that's SecurityHeadersEngine's job."""
    findings = _ENGINE.analyze(_resp())
    assert findings == []


# ---------------------------------------------------------------------------
# Report-only without enforcement
# ---------------------------------------------------------------------------


class TestReportOnly:
    def test_report_only_without_enforcement_is_medium(self):
        findings = _ENGINE.analyze(_resp(csp_ro="default-src 'self'"))
        assert _has(findings, "report-only")
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_both_headers_present_no_report_only_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'", csp_ro="default-src 'self'")
        )
        assert not _has(findings, "report-only")

    def test_report_only_finding_has_evidence(self):
        findings = _ENGINE.analyze(_resp(csp_ro="default-src 'self'"))
        ro_findings = [f for f in findings if "report-only" in f.title.lower()]
        assert all(f.evidence for f in ro_findings)


# ---------------------------------------------------------------------------
# object-src 'none'
# ---------------------------------------------------------------------------


class TestObjectSrc:
    def test_missing_object_src_is_high(self):
        findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
        obj = [f for f in findings if "object-src" in f.title.lower()]
        assert obj, "Expected object-src finding"
        assert obj[0].severity == Severity.HIGH

    def test_object_src_none_suppresses_finding(self):
        findings = _ENGINE.analyze(_resp(csp="default-src 'self'; object-src 'none'"))
        obj = [f for f in findings if "object-src" in f.title.lower()]
        assert not obj

    def test_default_src_none_counts_as_restricting_object_src(self):
        # default-src 'none' covers object-src when no explicit object-src
        findings = _ENGINE.analyze(_resp(csp="default-src 'none'"))
        obj = [f for f in findings if "object-src" in f.title.lower()]
        assert not obj

    def test_finding_category_is_security_header(self):
        findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
        for f in findings:
            assert f.category == FindingCategory.SECURITY_HEADER


# ---------------------------------------------------------------------------
# base-uri
# ---------------------------------------------------------------------------


class TestBaseUri:
    def test_missing_base_uri_produces_medium_finding(self):
        findings = _ENGINE.analyze(_resp(csp="default-src 'self'; object-src 'none'"))
        base = [f for f in findings if "base-uri" in f.title.lower()]
        assert base
        assert base[0].severity == Severity.MEDIUM

    def test_base_uri_self_suppresses_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; object-src 'none'; base-uri 'self'")
        )
        base = [f for f in findings if "base-uri" in f.title.lower()]
        assert not base

    def test_base_uri_none_suppresses_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; object-src 'none'; base-uri 'none'")
        )
        base = [f for f in findings if "base-uri" in f.title.lower()]
        assert not base

    def test_base_uri_wildcard_is_medium(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; object-src 'none'; base-uri *")
        )
        base = [f for f in findings if "base-uri" in f.title.lower()]
        assert base
        assert base[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# form-action
# ---------------------------------------------------------------------------


class TestFormAction:
    def test_missing_form_action_is_medium(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; object-src 'none'; base-uri 'self'")
        )
        fa = [f for f in findings if "form-action" in f.title.lower()]
        assert fa
        assert fa[0].severity == Severity.MEDIUM

    def test_form_action_self_suppresses_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp=(
                "default-src 'self'; object-src 'none'; "
                "base-uri 'self'; form-action 'self'"
            ))
        )
        fa = [f for f in findings if "form-action" in f.title.lower()]
        assert not fa

    def test_form_action_wildcard_is_medium(self):
        findings = _ENGINE.analyze(
            _resp(csp=(
                "default-src 'self'; object-src 'none'; "
                "base-uri 'self'; form-action *"
            ))
        )
        fa = [f for f in findings if "form-action" in f.title.lower()]
        assert fa
        assert fa[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# script-src data: / blob:
# ---------------------------------------------------------------------------


class TestScriptSrcDataBlob:
    def test_data_in_script_src_is_high(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src 'self' data:")
        )
        data_f = [f for f in findings if "data:" in f.title.lower()]
        assert data_f
        assert data_f[0].severity == Severity.HIGH

    def test_blob_in_script_src_is_high(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src 'self' blob:")
        )
        blob_f = [f for f in findings if "blob:" in f.title.lower()]
        assert blob_f
        assert blob_f[0].severity == Severity.HIGH

    def test_no_data_in_script_src_no_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src 'self' https://cdn.example.com")
        )
        data_f = [f for f in findings if "data:" in f.title.lower()]
        assert not data_f

    def test_data_in_default_src_fallback_is_high(self):
        # When script-src is absent, default-src is the fallback
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self' data:")
        )
        data_f = [f for f in findings if "data:" in f.title.lower()]
        assert data_f
        assert data_f[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# script-src http:
# ---------------------------------------------------------------------------


class TestScriptSrcHttp:
    def test_http_in_script_src_is_high(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src 'self' http:")
        )
        http_f = [f for f in findings if "http:" in f.title.lower()]
        assert http_f
        assert http_f[0].severity == Severity.HIGH

    def test_https_in_script_src_not_flagged(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src 'self' https:")
        )
        http_f = [f for f in findings if "http:" in f.title.lower()]
        assert not http_f

    def test_https_domain_not_flagged(self):
        findings = _ENGINE.analyze(
            _resp(csp="default-src 'self'; script-src https://cdn.example.com")
        )
        http_f = [f for f in findings if "http:" in f.title.lower()]
        assert not http_f


# ---------------------------------------------------------------------------
# frame-ancestors
# ---------------------------------------------------------------------------


class TestFrameAncestors:
    def test_missing_frame_ancestors_is_low(self):
        findings = _ENGINE.analyze(_resp(csp="default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"))
        fa = [f for f in findings if "frame-ancestors" in f.title.lower()]
        assert fa
        assert fa[0].severity == Severity.LOW

    def test_frame_ancestors_self_suppresses_finding(self):
        findings = _ENGINE.analyze(
            _resp(csp=(
                "default-src 'self'; object-src 'none'; "
                "base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
            ))
        )
        fa = [f for f in findings if "frame-ancestors" in f.title.lower()]
        assert not fa

    def test_frame_ancestors_wildcard_is_medium(self):
        findings = _ENGINE.analyze(
            _resp(csp=(
                "default-src 'self'; object-src 'none'; "
                "base-uri 'self'; form-action 'self'; frame-ancestors *"
            ))
        )
        fa = [f for f in findings if "frame-ancestors" in f.title.lower()]
        assert fa
        assert fa[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Strict CSP — no findings
# ---------------------------------------------------------------------------


def test_strict_csp_produces_no_findings():
    strict = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    findings = _ENGINE.analyze(_resp(csp=strict))
    # A strict policy covering all critical directives should produce zero findings.
    assert findings == [], f"Unexpected findings: {_titles(findings)}"


# ---------------------------------------------------------------------------
# Findings have evidence and remediation
# ---------------------------------------------------------------------------


def test_all_findings_have_evidence():
    findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
    assert all(f.evidence for f in findings)


def test_all_findings_have_remediation():
    findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
    assert all(f.remediation for f in findings)


def test_all_findings_have_owasp_alignment():
    findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
    assert all(f.framework.owasp_top10 for f in findings)


def test_scanner_engine_name():
    findings = _ENGINE.analyze(_resp(csp="default-src 'self'"))
    assert all(f.scanner_engine == "csp_engine" for f in findings)
