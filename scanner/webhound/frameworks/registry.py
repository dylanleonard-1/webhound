# WebHound — scanner/webhound/frameworks/registry.py
# Phase-9: detect frameworks across a scan and build the coverage view.
#
# Entry points:
#   detect_from_artifacts(...)  — score profiles against one page
#   detect_scan(...)            — aggregate across all pages + telemetry
#   build_coverage(...)         — the metadata.frameworks payload
#   is_normal_framework_change  — WADE context: is this change routine?

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse

from webhound.frameworks.base import (
    DetectionContext,
    FrameworkDetection,
    FrameworkProfile,
    merge_surface,
    score_profile,
)
from webhound.frameworks.profiles import ALL_PROFILES

# A profile must clear this to count as "detected" (filters noise — a
# lone generic script substring shouldn't claim a framework).
_MIN_CONFIDENCE = 0.4

_PROFILE_BY_NAME = {p.name: p for p in ALL_PROFILES}


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def context_from_artifacts(
    artifacts: Any, *, html: str = "", global_vars: Iterable[str] = (),
) -> DetectionContext:
    """Build a DetectionContext from a PageArtifacts (duck-typed)."""
    headers = {k.lower(): v for k, v in
               (getattr(artifacts, "response_headers", None) or {}).items()}
    meta = getattr(artifacts, "meta_tags", None) or {}
    script_urls = list(getattr(artifacts, "external_script_urls", None) or [])
    inline = list(getattr(artifacts, "inline_scripts", None) or [])
    links = list(getattr(artifacts, "all_links", None) or [])
    page_url = getattr(artifacts, "url", "") or ""
    page_host = _host(page_url)
    hosts = sorted({
        h for h in (_host(u) for u in script_urls + links)
        if h and h != page_host
    })
    return DetectionContext(
        url=page_url,
        headers=headers,
        meta_generator=meta.get("generator", "") or meta.get("Generator", ""),
        script_urls=script_urls,
        inline_scripts=inline,
        link_urls=links,
        html=html or "",
        global_vars=list(global_vars),
        hosts=hosts,
    )


def detect_from_context(ctx: DetectionContext) -> list[FrameworkDetection]:
    """Score every profile against one context; return those above the
    detection floor, strongest first."""
    out = [score_profile(p, ctx) for p in ALL_PROFILES]
    detected = [d for d in out if d.confidence >= _MIN_CONFIDENCE]
    detected.sort(key=lambda d: d.confidence, reverse=True)
    return detected


@dataclass
class ScanFrameworkResult:
    """Scan-wide framework detection + merged known surface."""

    detections: dict[str, FrameworkDetection] = field(default_factory=dict)
    pages_analyzed: int = 0

    @property
    def primary(self) -> FrameworkDetection | None:
        if not self.detections:
            return None
        # Most specific category wins ties; otherwise highest confidence.
        order = {"cms": 5, "commerce": 5, "site_builder": 5,
                 "meta_framework": 4, "spa_framework": 2}
        return max(
            self.detections.values(),
            key=lambda d: (d.confidence, order.get(d.category, 0)),
        )

    def profiles(self) -> list[FrameworkProfile]:
        return [_PROFILE_BY_NAME[n] for n in self.detections
                if n in _PROFILE_BY_NAME]


def detect_scan(
    page_contexts: Iterable[DetectionContext],
) -> ScanFrameworkResult:
    """Aggregate detection across every page. A framework's scan-wide
    confidence is the max it reached on any single page."""
    result = ScanFrameworkResult()
    for ctx in page_contexts:
        result.pages_analyzed += 1
        for det in detect_from_context(ctx):
            prev = result.detections.get(det.name)
            if prev is None or det.confidence > prev.confidence:
                result.detections[det.name] = det
            elif prev is not None:
                # keep the richer matched-signal set
                merged = sorted(set(prev.matched_signals)
                                | set(det.matched_signals))
                prev.matched_signals = merged
    return result


def build_coverage(
    result: ScanFrameworkResult,
    *,
    observed_routes: Iterable[str] = (),
    observed_apis: Iterable[str] = (),
    observed_assets: Iterable[str] = (),
    observed_forms: int = 0,
) -> dict[str, Any]:
    """The metadata.frameworks payload (Task 10). Merges what the scan
    OBSERVED with the detected platforms' KNOWN surface (candidates)."""
    profiles = result.profiles()
    surface = merge_surface(profiles)
    primary = result.primary
    return {
        "detected": [d.to_dict() for d in sorted(
            result.detections.values(),
            key=lambda d: d.confidence, reverse=True)],
        "primary_framework": primary.name if primary else None,
        "primary_confidence": round(primary.confidence, 3) if primary else 0.0,
        "primary_confidence_label": (
            primary.confidence_label if primary else "none"),
        "pages_analyzed": result.pages_analyzed,
        # Observed-on-this-scan counts.
        "routes_observed": len(set(observed_routes)),
        "apis_observed": len(set(observed_apis)),
        "assets_observed": len(set(observed_assets)),
        "forms_observed": observed_forms,
        # Platform known-surface candidates (inventory — not probed).
        "known_surface": {
            "routes": list(surface.routes),
            "assets": list(surface.assets),
            "apis": list(surface.apis),
            "admin_paths": list(surface.admin_paths),
            "forms": list(surface.forms),
            "third_parties": list(surface.third_parties),
        },
    }


# ---------------------------------------------------------------------------
# WADE framework context (Task 9)
# ---------------------------------------------------------------------------


def normal_change_matchers(
    result: ScanFrameworkResult,
) -> list[re.Pattern[str]]:
    """Compiled 'this is routine for the detected platform' patterns."""
    pats: list[re.Pattern[str]] = []
    for profile in result.profiles():
        pats.extend(profile.normal_change_regexes())
    return pats


def is_normal_framework_change(
    value: str, matchers: list[re.Pattern[str]],
) -> bool:
    """True when *value* (a changed URL/asset) matches a detected
    platform's normal-deployment pattern — a new hashed Next.js chunk, a
    Shopify theme asset version bump, a WordPress plugin update, etc.
    WADE uses this to avoid alerting on routine framework behaviour."""
    if not value:
        return False
    return any(p.search(value) for p in matchers)
