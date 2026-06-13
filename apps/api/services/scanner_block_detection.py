# WebHound — apps/api/services/scanner_block_detection.py
# Phase 3.4 scanner-access — classify WHICH provider layer blocked the scan, so the
# dashboard can be honest about where the blocker actually is (and never fake a
# Cloudflare "active" when Vercel is the real wall). Pure + side-effect-free so it's
# trivially testable; consumes the scan's browser_pass.yield_assessment signal plus
# whether a Cloudflare zone is connected/in front.
#
# Classification (blocker):
#   none                  - no challenge detected
#   cloudflare_challenge  - the active block is a Cloudflare challenge
#   vercel_challenge      - the active block is a Vercel challenge (no CF in front)
#   both                  - Cloudflare is in front (connected/proxy) AND Vercel is the
#                           FINAL blocker -> "Vercel blocking; Cloudflare connected"
#   generic_bot_challenge - a challenge we can't attribute to CF or Vercel
#
# Provider-layer diagnosis (diagnosis): cloudflare | vercel | both | unknown

from __future__ import annotations

# Substrings (lower-cased) that attribute a challenge to each provider. cf-cache-status
# ALONE is deliberately NOT here — caching does not imply a challenge.
_CLOUDFLARE_MARKERS = (
    "cloudflare", "cf-ray", "cf-mitigated", "challenge-platform", "cf_chl", "__cf_chl",
    "cf-chl", "turnstile", "attention required", "/cdn-cgi/challenge",
)
_VERCEL_MARKERS = (
    "vercel", "vercel security checkpoint", "x-vercel-id", ".well-known/vercel/security",
    "challenge.v2.wasm", "/request-challenge",
)

BLOCKER_NONE = "none"
BLOCKER_CLOUDFLARE = "cloudflare_challenge"
BLOCKER_VERCEL = "vercel_challenge"
BLOCKER_BOTH = "both"
BLOCKER_GENERIC = "generic_bot_challenge"


def _haystack(ya: dict) -> str:
    parts = [str(ya.get("reason") or ""), str(ya.get("challenge_provider") or "")]
    ev = ya.get("evidence")
    if isinstance(ev, list):
        parts.extend(str(x) for x in ev)
    return " ".join(parts).lower()


def _matches(text: str, provider_field: str, markers: tuple[str, ...], name: str) -> bool:
    if provider_field == name:
        return True
    return any(m in text for m in markers)


def classify_scan_blocker(
    yield_assessment: dict | None, *, cloudflare_connected: bool = False,
) -> dict:
    """Classify the scan blocker into a provider layer. `cloudflare_connected` means a
    Cloudflare zone is connected / in front (proxy or DNS). Returns a structured,
    non-secret diagnosis dict."""
    ya = yield_assessment or {}
    challenge = ya.get("challenge_detected") is True
    provider_field = str(ya.get("challenge_provider") or "").strip().lower()
    text = _haystack(ya)
    # Detection confidence (0-100) from the scan's yield assessment, when present.
    conf = ya.get("confidence")
    confidence = int(conf) if isinstance(conf, (int, float)) else None

    cf = _matches(text, provider_field, _CLOUDFLARE_MARKERS, "cloudflare")
    vercel = _matches(text, provider_field, _VERCEL_MARKERS, "vercel")

    if not challenge:
        return {
            "blocker": BLOCKER_NONE,
            "diagnosis": "cloudflare" if cloudflare_connected else "unknown",
            "active_blocker_provider": None,
            "next_action": None,
            "confidence": confidence,
        }

    # Vercel is the final blocker; Cloudflare may be connected in front of it.
    if vercel and (cloudflare_connected or cf):
        return {
            "blocker": BLOCKER_BOTH,
            "diagnosis": "both",
            "active_blocker_provider": "vercel",
            "next_action": "Set up Vercel scanner access",
            "confidence": confidence,
        }
    if vercel:
        return {
            "blocker": BLOCKER_VERCEL,
            "diagnosis": "vercel",
            "active_blocker_provider": "vercel",
            "next_action": "Set up Vercel scanner access",
            "confidence": confidence,
        }
    if cf:
        return {
            "blocker": BLOCKER_CLOUDFLARE,
            "diagnosis": "cloudflare",
            "active_blocker_provider": "cloudflare",
            "next_action": "Set up Cloudflare scanner access",
            "confidence": confidence,
        }
    return {
        "blocker": BLOCKER_GENERIC,
        "diagnosis": "unknown",
        "active_blocker_provider": None,
        "next_action": "Review scanner access — challenge source is unrecognized",
        "confidence": confidence,
    }


def detect_blocking_provider(
    yield_assessment: dict | None,
    *,
    headers: dict | None = None,
    cloudflare_connected: bool = False,
) -> dict:
    """Phase-2 multi-provider blocker detection — consumes the provider registry
    so all 10 CDN/WAF providers are attributed (not just Cloudflare/Vercel).

    Reuses the legacy ``classify_scan_blocker`` for the back-compatible
    blocker/diagnosis fields, then layers registry attribution on top:
      1. trust the scan's own ``challenge_provider`` when it's a registry provider
         (it comes from challenge_detection, which already fingerprints 6),
      2. else run the registry's signal detector over the response
         headers + the yield-assessment text.

    Output (superset of the legacy shape): ``provider``, ``name``, ``confidence``,
    ``reason``, ``challenge_detected``, ``access_required``, ``automation_capable``,
    ``allowlist_method`` + the legacy ``blocker``/``diagnosis``/``next_action``."""
    from apps.api.services import provider_access_registry as _reg

    legacy = classify_scan_blocker(
        yield_assessment, cloudflare_connected=cloudflare_connected)
    ya = yield_assessment or {}
    challenge = ya.get("challenge_detected") is True
    cp = str(ya.get("challenge_provider") or "").strip().lower()
    text = _haystack(ya)
    conf = ya.get("confidence")
    scan_conf = int(conf) if isinstance(conf, (int, float)) else None

    detected: dict | None = None
    # 1. The scan already named a provider that's in the registry.
    if cp:
        p = _reg.get_provider(cp)
        if p is not None:
            detected = {
                "provider": p.key, "name": p.name,
                "confidence": scan_conf if scan_conf is not None else 85,
                "reason": f"scan challenge_provider={cp}",
                "automation_capable": p.automation_capable,
                "allowlist_method": p.allowlist_method,
            }
    # 2. Registry signal detection over headers + the yield-assessment text.
    if detected is None:
        detected = _reg.detect_provider(headers=headers, body=text, url_chain=text)

    return {
        "provider": detected["provider"] if detected else None,
        "name": detected.get("name") if detected else None,
        "confidence": (detected.get("confidence")
                       if detected else legacy.get("confidence")),
        "reason": (detected.get("reason") if detected
                   else legacy.get("next_action")),
        "challenge_detected": challenge,
        # A challenge means the scanner needs access regardless of attribution.
        "access_required": bool(challenge),
        "automation_capable": bool(detected.get("automation_capable")) if detected else False,
        "allowlist_method": detected.get("allowlist_method") if detected else "manual",
        # --- legacy fields (unchanged behaviour) ---
        "blocker": legacy["blocker"],
        "diagnosis": legacy["diagnosis"],
        "active_blocker_provider": legacy["active_blocker_provider"],
        "next_action": legacy["next_action"],
    }
