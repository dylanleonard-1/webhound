# WebHound — scanner/webhound/reporting/browser_coverage.py
# Presentation helper: turn the browser-pass yield_assessment (produced by
# browser/challenge_detection.py) into a customer-safe coverage note and a
# fuller internal/admin view. Reporting only — no scanner logic, no bypass.
#
# Customer projection redacts overly technical evidence (challenge URLs, .wasm
# names) into plain-English categories. Internal projection keeps the raw
# evidence for diagnostics.

from __future__ import annotations

from typing import Any

# Professional, non-alarming customer wording.
CUSTOMER_NOTE = (
    "Browser-based analysis was limited because the site served a bot/security "
    "challenge instead of the full application. Some JavaScript-rendered "
    "routes, APIs, and forms may not have been visible. To improve scan "
    "coverage, configure verified scanner access or allowlist WebHound for "
    "this domain.")


def _summarize_evidence(evidence: list[Any]) -> list[str]:
    """Map raw evidence strings to customer-safe categories — no URLs/.wasm."""
    cats: list[str] = []
    seen: set[str] = set()

    def add(c: str) -> None:
        if c not in seen:
            seen.add(c)
            cats.append(c)

    for e in evidence or []:
        el = str(e).lower()
        if "endpoint" in el:
            add("bot-protection challenge endpoints were loaded")
        elif "marker" in el or "checkpoint" in el:
            add("a security-checkpoint page was shown")
        elif "phrase" in el:
            add("the page asked to verify the visitor / enable JavaScript")
        elif "captcha" in el:
            add("a CAPTCHA challenge was presented")
        elif "status" in el:
            add("the server returned a blocking HTTP status")
        elif "smaller than static" in el:
            add("the rendered page was abnormally small")
        elif "challenge url" in el:
            add("navigation was redirected to a challenge page")
    return cats


def build_browser_coverage(
    metadata: dict | None, *, internal: bool = False,
) -> dict[str, Any] | None:
    """Build the browser-coverage view from ``metadata.browser_pass``.

    Returns None when the scan had no browser pass / no yield assessment.
    ``internal=True`` includes raw evidence + counts (admin diagnostics);
    otherwise evidence is summarised into safe categories (customer view).
    """
    # Defensive: scanner_metadata is a JSON column; tolerate non-dict/None at
    # the source so unguarded call sites (e.g. the customer scan-result router)
    # can never 500 on an off-normal value.
    if not isinstance(metadata, dict):
        return None
    bp = metadata.get("browser_pass")
    if not isinstance(bp, dict):
        return None
    ya = bp.get("yield_assessment")
    if not isinstance(ya, dict):
        return None

    challenge = ya.get("challenge_detected")
    limited = challenge is True
    out: dict[str, Any] = {
        "limited": limited,
        "challenge_detected": challenge,
        "challenge_provider": ya.get("challenge_provider"),
        "confidence": ya.get("confidence"),
        "rendered_real_app": ya.get("rendered_real_app"),
        "reason": ya.get("reason"),
        "recommended_action": ya.get("recommended_action"),
        # The customer-facing note only appears when coverage was limited.
        "note": CUSTOMER_NOTE if limited else None,
    }
    if internal:
        out["evidence"] = list(ya.get("evidence") or [])
        out["counts"] = {
            "rendered_links": ya.get("rendered_links_count"),
            "rendered_scripts": ya.get("rendered_scripts_count"),
            "api_requests": ya.get("api_requests_count"),
            "console_errors": ya.get("console_error_count"),
        }
    else:
        # Redacted: categories only, never raw challenge URLs / .wasm names.
        out["evidence_summary"] = _summarize_evidence(ya.get("evidence") or [])
    return out
