# WebHound — tests/test_browser_coverage_report.py
# Surfacing Browser Yield & Challenge Detection in reports. Presentation only.

from __future__ import annotations

from webhound.reporting.browser_coverage import (
    CUSTOMER_NOTE,
    build_browser_coverage,
)


def _md(challenge):
    """Build a metadata dict with a yield_assessment in the given state."""
    if challenge == "challenge":
        ya = {
            "rendered_real_app": False, "challenge_detected": True,
            "challenge_provider": "vercel", "confidence": 97,
            "reason": "vercel bot/security challenge served instead of the site",
            "recommended_action": "configure verified scanner access",
            "evidence": [
                "vercel: challenge endpoint 'challenge.v2.wasm'",
                "vercel: challenge endpoint '/request-challenge'",
                "vercel: challenge marker 'vercel security checkpoint'",
                "blocking HTTP status: [403]"],
            "rendered_links_count": 1, "rendered_scripts_count": 1,
            "api_requests_count": 2, "console_error_count": 1,
            "note": "internal note",
        }
    else:  # clean
        ya = {
            "rendered_real_app": True, "challenge_detected": False,
            "challenge_provider": "unknown", "confidence": 88,
            "reason": "healthy render", "recommended_action": "none",
            "evidence": [], "rendered_links_count": 34,
            "rendered_scripts_count": 12, "api_requests_count": 8,
            "console_error_count": 0,
        }
    return {"browser_pass": {"deferred": False, "yield_assessment": ya}}


def test_no_browser_pass_returns_none():
    assert build_browser_coverage({}) is None
    assert build_browser_coverage({"browser_pass": {"deferred": True}}) is None
    # Defensive: a non-dict / None metadata (off-normal JSON column) must
    # return None, never raise — the customer router call site is unguarded.
    assert build_browser_coverage(None) is None
    assert build_browser_coverage("oops") is None  # type: ignore[arg-type]
    assert build_browser_coverage([1, 2]) is None  # type: ignore[arg-type]


def test_customer_view_challenge_has_note():
    cov = build_browser_coverage(_md("challenge"))
    assert cov["limited"] is True
    assert cov["challenge_detected"] is True
    assert cov["challenge_provider"] == "vercel"
    assert cov["confidence"] == 97
    assert cov["rendered_real_app"] is False
    assert cov["note"] == CUSTOMER_NOTE
    assert cov["recommended_action"]


def test_customer_view_redacts_technical_evidence():
    cov = build_browser_coverage(_md("challenge"))
    # No raw URLs / .wasm / endpoint paths leak to the customer view.
    blob = repr(cov)
    assert ".wasm" not in blob
    assert "request-challenge" not in blob
    assert "evidence" not in cov  # only the summary, never raw evidence
    assert cov["evidence_summary"]  # human categories present
    assert any("challenge" in s.lower() for s in cov["evidence_summary"])


def test_customer_view_clean_has_no_note():
    cov = build_browser_coverage(_md("clean"))
    assert cov["limited"] is False
    assert cov["challenge_detected"] is False
    assert cov["note"] is None


def test_internal_view_keeps_evidence_and_counts():
    cov = build_browser_coverage(_md("challenge"), internal=True)
    assert "evidence" in cov and len(cov["evidence"]) == 4
    assert any(".wasm" in e for e in cov["evidence"])  # full evidence for admin
    assert cov["counts"]["rendered_links"] == 1
    assert "evidence_summary" not in cov


def test_json_report_includes_browser_coverage_when_challenged():
    from webhound.reporting.json_report import JsonReport
    from webhound.models.scan_result import ScanResult
    r = ScanResult(target=_dummy_target())
    r.metadata.update(_md("challenge"))
    out = JsonReport().build(r, profile_name="deep")
    cov = out["browser_coverage"]
    assert cov["limited"] is True
    assert cov["note"] == CUSTOMER_NOTE
    assert ".wasm" not in repr(cov)


def test_markdown_warns_only_when_challenged():
    from webhound.reporting.markdown_report import MarkdownReport
    from webhound.models.scan_result import ScanResult

    challenged = ScanResult(target=_dummy_target())
    challenged.metadata.update(_md("challenge"))
    md = MarkdownReport().build(challenged, profile_name="deep")
    assert "## Browser Coverage" in md
    assert "bot/security challenge" in md

    clean = ScanResult(target=_dummy_target())
    clean.metadata.update(_md("clean"))
    md2 = MarkdownReport().build(clean, profile_name="deep")
    assert "## Browser Coverage" not in md2


def _dummy_target():
    from webhound.models.target import ScanOptions, Target
    return Target.from_url("https://t.test", scan_options=ScanOptions())
