# WebHound — tests/test_challenge_detection.py
# Browser Yield & Challenge Detection. Detection/reporting only — these tests
# assert classification, NOT any bypass behaviour (there is none).

from __future__ import annotations

from types import SimpleNamespace

from webhound.browser.challenge_detection import (
    BrowserYieldSignals,
    assess_browser_yield,
    build_signals,
)


def _clean(**over) -> BrowserYieldSignals:
    base = dict(pages_rendered=1, rendered_links_count=30,
                rendered_scripts_count=12, api_requests_count=8,
                rendered_html="<html><body>real app</body></html>",
                rendered_html_size=200_000, static_html_size=210_000)
    base.update(over)
    return BrowserYieldSignals(**base)


def test_clean_real_app():
    a = assess_browser_yield(_clean())
    assert a["rendered_real_app"] is True
    assert a["challenge_detected"] is False
    assert a["challenge_provider"] == "unknown"
    assert a["confidence"] >= 80
    assert a["recommended_action"] == "none"


def test_vercel_challenge():
    a = assess_browser_yield(_clean(
        rendered_links_count=1, rendered_scripts_count=1,
        rendered_html_size=4000, static_html_size=4000,
        network_urls=[
            "https://x.com/.well-known/vercel/security/static/challenge.v2.wasm",
            "https://x.com/.well-known/vercel/security/request-challenge"]))
    assert a["rendered_real_app"] is False
    assert a["challenge_detected"] is True
    assert a["challenge_provider"] == "vercel"
    assert a["confidence"] >= 60
    assert any("vercel" in e for e in a["evidence"])
    assert "note" in a


def test_cloudflare_challenge():
    a = assess_browser_yield(_clean(
        rendered_links_count=0, rendered_scripts_count=1,
        rendered_html="checking your browser before accessing the site",
        network_urls=["https://x.com/cdn-cgi/challenge-platform/h/b/orchestrate"]))
    assert a["challenge_detected"] is True
    assert a["challenge_provider"] == "cloudflare"


def test_aws_waf_block_with_403():
    a = assess_browser_yield(_clean(
        rendered_links_count=0, rendered_scripts_count=0,
        rendered_html="request blocked",
        network_urls=["https://token.awswaf.com/abc/"],
        status_codes=[403]))
    assert a["challenge_detected"] is True
    assert a["challenge_provider"] == "aws_waf"
    assert any("403" in e for e in a["evidence"])


def test_captcha_generic_provider_unknown():
    a = assess_browser_yield(_clean(
        rendered_links_count=1, rendered_scripts_count=1,
        rendered_html="please complete the recaptcha to continue"))
    assert a["challenge_detected"] is True
    # recaptcha (35) + phrase? 'recaptcha' is captcha marker only → score 35 <50
    # so it lands ambiguous unless paired; assert at least flagged suspicious.
    assert a["challenge_detected"] in (True, "unknown")


def test_low_yield_no_signature_is_unknown():
    a = assess_browser_yield(_clean(
        rendered_links_count=1, rendered_scripts_count=1,
        rendered_html="<html><body>tiny</body></html>",
        rendered_html_size=500, static_html_size=600))
    assert a["rendered_real_app"] == "unknown"
    assert a["challenge_detected"] == "unknown"
    assert "manual review" in a["recommended_action"] or "verified" in a["recommended_action"]


def test_deferred_is_unknown():
    a = assess_browser_yield(BrowserYieldSignals(deferred=True, pages_rendered=0))
    assert a["rendered_real_app"] == "unknown"
    assert a["challenge_detected"] == "unknown"
    assert "verify domain" in a["recommended_action"]


def test_login_wall_recommends_auth():
    a = assess_browser_yield(_clean(
        rendered_links_count=8, rendered_scripts_count=5,
        rendered_html="<html><body>please log in to access your dashboard</body></html>"))
    assert a["challenge_detected"] is False
    assert a["recommended_action"] == "authenticated scan needed"


def test_dom_shrink_mismatch_flagged():
    a = assess_browser_yield(_clean(
        rendered_links_count=0, rendered_scripts_count=1,
        rendered_html_size=1000, static_html_size=200_000))
    # big shrink (20 pts) + low yield → at least suspicious/unknown
    assert a["challenge_detected"] in ("unknown", True)
    assert a["rendered_real_app"] in ("unknown", False)


def test_build_signals_from_telemetries():
    art = SimpleNamespace(url="https://x.com/api/data", initiator_kind="fetch")
    scr = SimpleNamespace(src="https://x.com/app.js")
    tel = SimpleNamespace(
        page_url="https://x.com/", final_url="https://x.com/",
        status_code=200, rendered_html="<html>" + "x" * 5000 + "</html>",
        rendered_links=["/a", "/b", "/c"], rendered_scripts=[scr],
        artifacts=[art], console_messages=["error: boom"], page_errors=[])
    sig = build_signals([tel], static_html_size=6000, deferred=False)
    assert sig.pages_rendered == 1
    assert sig.rendered_links_count == 3
    assert sig.rendered_scripts_count == 1
    assert sig.api_requests_count == 1
    assert sig.console_error_count == 1
    assert sig.status_codes == [200]
    a = assess_browser_yield(sig)
    assert a["challenge_detected"] is False  # clean-ish, no markers
