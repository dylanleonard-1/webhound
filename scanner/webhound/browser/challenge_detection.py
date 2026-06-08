# WebHound — scanner/webhound/browser/challenge_detection.py
# Browser Yield & Challenge Detection (Phase-2 observability extension).
#
# DETECTION AND REPORTING ONLY. This module NEVER evades, bypasses, or spoofs
# anything. It reads the browser pass's own telemetry (rendered DOM, network
# URLs, scripts, console errors, status codes) and classifies whether the
# headless browser rendered the REAL site or a bot/security challenge / block
# page from a CDN/WAF. The output is advisory metadata so operators (and the
# report) know when browser coverage was limited and why.
#
# Providers covered generically: Cloudflare, Vercel, Akamai, Fastly, AWS WAF,
# Netlify, plus provider-agnostic challenge/captcha/login/rate-limit signals.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- Provider challenge signatures -----------------------------------------
# URL/script signatures are the strongest attribution signal (a real site
# rarely loads these unless it is being challenged). HTML phrases are
# challenge-specific wording (NOT bare brand names, to avoid false positives
# on sites that merely mention a CDN).
_PROVIDER_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "cloudflare": {
        "url": ["/cdn-cgi/challenge-platform/", "challenges.cloudflare.com",
                "/cdn-cgi/l/chk_jschl", "__cf_chl", "cf_chl_"],
        "html": ["checking your browser before accessing",
                 "cf-browser-verification", "__cf_chl_opt",
                 "attention required! | cloudflare", "cf-challenge-running"],
    },
    "vercel": {
        "url": [".well-known/vercel/security", "challenge.v2.wasm",
                "/request-challenge", "/_vercel/security"],
        "html": ["vercel security checkpoint"],
    },
    "akamai": {
        "url": ["/_bm/", "/akam/", "bm-verify", "/_sec/cp_challenge"],
        "html": ["akamai bot manager", "errors.edgesuite.net",
                 "reference&#32;#", "access denied", "you don't have permission to access"],
    },
    "fastly": {
        "url": [],
        "html": ["request blocked", "fastly error", "varnish cache server",
                 "error 503 service unavailable"],
    },
    "aws_waf": {
        "url": ["token.awswaf.com", "captcha.awswaf.com",
                ".well-known/awswaf", "awswaf"],
        "html": ["aws waf", "request blocked"],
    },
    "netlify": {
        "url": [],
        "html": ["netlify security", "site temporarily unavailable"],
    },
}

_CHALLENGE_PHRASES = [
    "checking your browser", "verify you are human", "verify you're human",
    "are you a human", "bot detected", "security challenge",
    "complete the security check", "human verification", "ddos protection by",
    "unusual traffic", "automated request", "i'm not a robot",
    "please enable javascript and cookies", "enable javascript to continue",
    "verifying you are human", "additional verification required",
]
_CAPTCHA_MARKERS = [
    "recaptcha", "g-recaptcha", "www.google.com/recaptcha", "hcaptcha",
    "h-captcha", "cf-turnstile", "challenges.cloudflare.com/turnstile",
    "captcha-delivery.com", "geo.captcha-delivery",
]
# Login walls are NOT challenges, but they also cap browser yield → flagged
# separately so the recommendation can be "authenticated scan needed".
_LOGIN_MARKERS = [
    "sign in to continue", "please log in to", "log in to access",
    "you must be logged in", "login required to view",
]
_BLOCK_STATUS = {401, 403, 429, 503}
_CHALLENGE_URL_HINTS = ("challenge", "captcha", "/cdn-cgi/", "blocked",
                        "access-denied", "/_sec/", "awswaf")

# Heuristic thresholds.
_HEALTHY_LINKS = 5          # >= this many rendered links → looks like a real app
_LOW_LINKS = 1              # <= this → very low yield
_DOM_SHRINK_RATIO = 0.4     # rendered DOM < 40% of static → abnormal shrink

_CHALLENGE_NOTE = (
    "Browser analysis was limited because the site served a bot/security "
    "challenge. Some JavaScript-rendered routes and APIs may not have been "
    "visible. To improve coverage, allowlist WebHound or configure verified "
    "scanner access.")


@dataclass
class BrowserYieldSignals:
    """Provider-agnostic inputs distilled from the browser telemetry."""
    rendered_html: str = ""
    network_urls: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    final_url: str | None = None
    requested_url: str | None = None
    rendered_links_count: int = 0
    rendered_scripts_count: int = 0
    api_requests_count: int = 0
    console_error_count: int = 0
    static_html_size: int | None = None
    rendered_html_size: int | None = None
    deferred: bool = False
    pages_rendered: int = 0
    render_failures: int = 0


def _base(signals: BrowserYieldSignals, **over: Any) -> dict[str, Any]:
    out = {
        "rendered_real_app": "unknown",
        "challenge_detected": "unknown",
        "challenge_provider": "unknown",
        "confidence": 0,
        "reason": "",
        "evidence": [],
        "rendered_links_count": signals.rendered_links_count,
        "rendered_scripts_count": signals.rendered_scripts_count,
        "api_requests_count": signals.api_requests_count,
        "console_error_count": signals.console_error_count,
        "recommended_action": "manual review",
    }
    out.update(over)
    return out


def assess_browser_yield(s: BrowserYieldSignals) -> dict[str, Any]:
    """Classify the browser pass output. Pure function — no I/O, no network,
    no evasion. Returns the browser_yield_assessment dict."""
    # Nothing rendered (disabled/deferred/all failures) → can't judge content.
    if s.deferred or s.pages_rendered == 0:
        return _base(
            s, reason=("browser pass did not render any page "
                       "(disabled/deferred/failed) — yield cannot be assessed"),
            recommended_action="verify domain / configure verified scanner access")

    hay_html = (s.rendered_html or "").lower()
    hay_net = " ".join(s.network_urls).lower()
    hay_scripts = " ".join(s.script_srcs).lower()
    blob = f"{hay_html} {hay_net} {hay_scripts}"

    evidence: list[str] = []
    provider = "unknown"
    score = 0
    low_yield = (s.rendered_links_count <= _LOW_LINKS
                 and s.rendered_scripts_count <= 1)

    # Pass 1 — URL/script signatures (strongest, most reliable attribution).
    for prov, sig in _PROVIDER_SIGNATURES.items():
        for pat in sig.get("url", []):
            if pat in hay_net or pat in hay_scripts:
                if provider == "unknown":
                    provider = prov
                score += 50
                evidence.append(f"{prov}: challenge endpoint '{pat}'")
    # Pass 2 — HTML challenge markers (weaker; only attribute if still unknown).
    for prov, sig in _PROVIDER_SIGNATURES.items():
        for pat in sig.get("html", []):
            if pat in hay_html:
                if provider == "unknown":
                    provider = prov
                score += 25
                evidence.append(f"{prov}: challenge marker '{pat}'")

    for ph in _CHALLENGE_PHRASES:
        if ph in hay_html:
            score += 30
            evidence.append(f"challenge phrase: '{ph}'")
    captcha_hit = next((cm for cm in _CAPTCHA_MARKERS if cm in blob), None)
    if captcha_hit:
        # A captcha that REPLACED the page (low yield) is a block; a captcha
        # widget embedded in an otherwise-real page is not.
        score += 50 if low_yield else 15
        evidence.append(f"captcha indicator: '{captcha_hit}'"
                        + ("" if low_yield else " (embedded — page still rendered)"))

    blocking = sorted({c for c in s.status_codes if c in _BLOCK_STATUS})
    if blocking:
        score += 25
        evidence.append(f"blocking HTTP status: {blocking}")

    if s.final_url and any(h in s.final_url.lower() for h in _CHALLENGE_URL_HINTS):
        score += 20
        evidence.append(f"navigation ended on challenge URL: {s.final_url}")

    mismatch = (s.static_html_size and s.rendered_html_size
                and s.rendered_html_size < _DOM_SHRINK_RATIO * s.static_html_size)
    if mismatch:
        score += 20
        evidence.append(
            f"rendered DOM far smaller than static HTML "
            f"({s.rendered_html_size} vs {s.static_html_size} bytes)")

    login_wall = any(m in hay_html for m in _LOGIN_MARKERS)

    # ---- Decision ---------------------------------------------------------
    if score >= 50:
        confidence = min(97, 45 + score // 2)
        action = "configure verified scanner access (allowlist / official " \
                 "automation-bypass token for owned domains; request " \
                 "allowlisting or run an authenticated scan for customer domains)"
        if blocking and {429, 503} & set(blocking) and provider == "unknown" \
                and not any("phrase" in e or "endpoint" in e for e in evidence):
            action = "retry later"
        return _base(
            s, rendered_real_app=False, challenge_detected=True,
            challenge_provider=provider, confidence=confidence,
            reason=(f"{provider if provider!='unknown' else 'a'} "
                    f"bot/security challenge or block page was served instead "
                    f"of the site (score {score})"),
            evidence=evidence, recommended_action=action,
            note=_CHALLENGE_NOTE)

    if score >= 25:
        ev = list(evidence)
        if low_yield:
            ev.append("very low rendered yield (links<=1, scripts<=1)")
        return _base(
            s, rendered_real_app="unknown", challenge_detected="unknown",
            challenge_provider=provider, confidence=55,
            reason=("partial challenge/block indicators without a definitive "
                    "signature — coverage may be limited"),
            evidence=ev,
            recommended_action="manual review / configure verified scanner access")

    # No challenge signatures.
    if login_wall:
        return _base(
            s, rendered_real_app=True, challenge_detected=False,
            challenge_provider="unknown", confidence=70,
            reason="login wall detected — public content rendered but gated areas require auth",
            evidence=["login wall markers in DOM"],
            recommended_action="authenticated scan needed")

    if low_yield or mismatch:
        ev = []
        if low_yield:
            ev.append("very low rendered yield (links<=1, scripts<=1)")
        if mismatch:
            ev.append("rendered DOM far smaller than static HTML")
        return _base(
            s, rendered_real_app="unknown", challenge_detected="unknown",
            challenge_provider="unknown", confidence=45,
            reason=("low browser yield with no challenge signature — could be a "
                    "genuinely sparse page or an undetected block"),
            evidence=ev,
            recommended_action="manual review / consider authenticated or verified scan")

    confidence = 88 if s.rendered_links_count >= _HEALTHY_LINKS else 72
    return _base(
        s, rendered_real_app=True, challenge_detected=False,
        challenge_provider="unknown", confidence=confidence,
        reason=(f"healthy render: {s.rendered_links_count} links, "
                f"{s.rendered_scripts_count} scripts, no challenge signatures"),
        evidence=[], recommended_action="none")


def build_signals(
    telemetries: list[Any],
    *,
    static_html_size: int | None = None,
    deferred: bool = False,
) -> BrowserYieldSignals:
    """Adapter: distil a list of BrowserTelemetry into yield signals. Caps the
    HTML sample so the assessment stays bounded; reads counts/urls/status."""
    htmls, net, scripts, statuses = [], [], [], []
    links = forms_scripts = api = console_err = pages_rendered = render_fail = 0
    final_url = requested_url = None
    rendered_size = 0
    _API_KINDS = {"fetch", "xhr", "eventsource", "websocket"}
    for t in telemetries or []:
        if requested_url is None:
            requested_url = getattr(t, "page_url", None)
        final_url = getattr(t, "final_url", None) or final_url
        sc = getattr(t, "status_code", None)
        if sc is not None:
            statuses.append(sc)
        html = getattr(t, "rendered_html", None)
        if html:
            pages_rendered += 1
            rendered_size += len(html)
            if len(" ".join(htmls)) < 60_000:
                htmls.append(html[:30_000])
        else:
            render_fail += 1
        links += len(getattr(t, "rendered_links", None) or [])
        rs = getattr(t, "rendered_scripts", None) or []
        forms_scripts += len(rs)
        for s in rs:
            src = getattr(s, "src", None)
            if src:
                scripts.append(src)
        for art in getattr(t, "artifacts", None) or []:
            u = getattr(art, "url", None)
            if u:
                net.append(u)
            if (getattr(art, "initiator_kind", "") or "").lower() in _API_KINDS:
                api += 1
        console_err += sum(
            1 for m in (getattr(t, "console_messages", None) or [])
            if "error" in str(m).lower())
        console_err += len(getattr(t, "page_errors", None) or [])
    return BrowserYieldSignals(
        rendered_html=" ".join(htmls),
        network_urls=net, script_srcs=scripts, status_codes=statuses,
        final_url=final_url, requested_url=requested_url,
        rendered_links_count=links, rendered_scripts_count=forms_scripts,
        api_requests_count=api, console_error_count=console_err,
        static_html_size=static_html_size,
        rendered_html_size=rendered_size or None,
        deferred=deferred, pages_rendered=pages_rendered,
        render_failures=render_fail)
