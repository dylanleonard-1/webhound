# WebHound — scanner/webhound/frameworks/base.py
# Phase-9 framework-aware discovery: the profile model + detection
# inputs/outputs shared by every platform profile.
#
# A FrameworkProfile is PURE DATA: detection signals (how to recognise
# the platform from already-fetched artifacts) plus the platform's
# known surface (routes / assets / APIs / admin paths / forms / vendors
# it typically exposes). Nothing here fetches anything — the scanner is
# passive. Known surface is emitted as DISCOVERY CANDIDATES (inventory),
# never auto-probed, so safe-mode is preserved.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# Detection-signal weights. Strong signals (a platform-unique header or
# global var) are near-conclusive; soft signals (a generic script name)
# corroborate. Confidence is the summed weight, capped at 0.98.
_WEIGHTS = {
    "header": 0.55,
    "meta_generator": 0.55,
    "global_var": 0.50,
    "path": 0.35,
    "dom": 0.40,
    "script": 0.30,
    "third_party": 0.25,
}


@dataclass(frozen=True)
class DetectionSignals:
    """How to recognise a platform from passive artifacts.

    All signals are matched case-insensitively. ``header_signals`` are
    (header_name, value_substring); a header is a match when present
    (empty value_substring) or when its value contains the substring.
    """

    header_signals: tuple[tuple[str, str], ...] = ()
    meta_generator_signals: tuple[str, ...] = ()     # substrings of <meta generator>
    script_signals: tuple[str, ...] = ()             # regex vs script src/inline
    path_signals: tuple[str, ...] = ()               # substrings vs any URL path
    global_var_signals: tuple[str, ...] = ()         # window.__X__ names (rendered)
    dom_signals: tuple[str, ...] = ()                # regex vs rendered/static HTML
    third_party_signals: tuple[str, ...] = ()        # host substrings


@dataclass(frozen=True)
class KnownSurface:
    """The surface a platform typically exposes. Discovery CANDIDATES —
    surfaced as inventory, never auto-fetched."""

    routes: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()
    apis: tuple[str, ...] = ()
    admin_paths: tuple[str, ...] = ()
    forms: tuple[str, ...] = ()
    third_parties: tuple[str, ...] = ()


@dataclass(frozen=True)
class FrameworkProfile:
    """One platform's detection signals + known surface + WADE context."""

    name: str
    category: str                 # cms | commerce | meta_framework | spa_framework | site_builder
    signals: DetectionSignals
    surface: KnownSurface = field(default_factory=KnownSurface)
    # Regexes (as strings) describing changes that are NORMAL for this
    # platform — used by WADE to avoid alerting on routine framework
    # behaviour (new hashed chunk, plugin asset version bump, etc.).
    normal_change_patterns: tuple[str, ...] = ()

    def normal_change_regexes(self) -> list[re.Pattern[str]]:
        return [re.compile(p, re.IGNORECASE) for p in self.normal_change_patterns]


@dataclass
class FrameworkDetection:
    """The result of scoring one profile against a page's artifacts."""

    name: str
    category: str
    confidence: float                       # 0..1
    matched_signals: list[str] = field(default_factory=list)

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.9:
            return "confirmed"
        if self.confidence >= 0.75:
            return "high"
        if self.confidence >= 0.55:
            return "medium"
        if self.confidence >= 0.4:
            return "low"
        return "heuristic"

    def to_dict(self) -> dict:
        return {
            "framework": self.name,
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "confidence_label": self.confidence_label,
            "matched_signals": list(self.matched_signals),
        }


@dataclass
class DetectionContext:
    """Everything the detector reads — assembled from PageArtifacts and
    (optionally) browser telemetry. Plain strings/lists so profiles
    never touch engine models directly and stay trivially testable."""

    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)     # lowercased keys
    meta_generator: str = ""
    script_urls: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    link_urls: list[str] = field(default_factory=list)
    html: str = ""
    global_vars: list[str] = field(default_factory=list)      # window.__X__ names seen
    hosts: list[str] = field(default_factory=list)            # external hosts observed

    # --- assembled all-URL view for path matching ---------------------
    def all_paths(self) -> list[str]:
        return list(self.script_urls) + list(self.link_urls) + (
            [self.url] if self.url else []
        )


def _ci(s: str) -> str:
    return (s or "").lower()


def score_profile(
    profile: FrameworkProfile, ctx: DetectionContext,
) -> FrameworkDetection:
    """Score one profile against a detection context. Confidence is the
    summed weight of distinct matched signal *kinds* + soft signals,
    capped. Records which signals fired for transparency."""
    matched: list[str] = []
    score = 0.0
    sig = profile.signals

    headers = {k.lower(): _ci(v) for k, v in (ctx.headers or {}).items()}
    for name, needle in sig.header_signals:
        hv = headers.get(name.lower())
        if hv is not None and (not needle or needle.lower() in hv):
            matched.append(f"header:{name}")
            score += _WEIGHTS["header"]
            break

    gen = _ci(ctx.meta_generator)
    for needle in sig.meta_generator_signals:
        if needle.lower() in gen:
            matched.append(f"meta:{needle}")
            score += _WEIGHTS["meta_generator"]
            break

    gvars = {_ci(v) for v in (ctx.global_vars or [])}
    for needle in sig.global_var_signals:
        if needle.lower() in gvars:
            matched.append(f"global:{needle}")
            score += _WEIGHTS["global_var"]
            break

    paths = " ".join(_ci(p) for p in ctx.all_paths())
    for needle in sig.path_signals:
        if needle.lower() in paths:
            matched.append(f"path:{needle}")
            score += _WEIGHTS["path"]
            break

    html = _ci(ctx.html)
    for pat in sig.dom_signals:
        if re.search(pat, html, re.IGNORECASE):
            matched.append(f"dom:{pat}")
            score += _WEIGHTS["dom"]
            break

    blob = " ".join(_ci(s) for s in
                    (ctx.script_urls + ctx.inline_scripts))
    for pat in sig.script_signals:
        if re.search(pat, blob, re.IGNORECASE):
            matched.append(f"script:{pat}")
            score += _WEIGHTS["script"]
            break

    hostblob = " ".join(_ci(h) for h in ctx.hosts)
    for needle in sig.third_party_signals:
        if needle.lower() in hostblob:
            matched.append(f"vendor:{needle}")
            score += _WEIGHTS["third_party"]
            break

    return FrameworkDetection(
        name=profile.name,
        category=profile.category,
        confidence=min(0.98, round(score, 3)),
        matched_signals=matched,
    )


def merge_surface(profiles: Iterable[FrameworkProfile]) -> KnownSurface:
    """Union the known surface of several detected profiles."""
    routes: set[str] = set()
    assets: set[str] = set()
    apis: set[str] = set()
    admin: set[str] = set()
    forms: set[str] = set()
    vendors: set[str] = set()
    for p in profiles:
        routes.update(p.surface.routes)
        assets.update(p.surface.assets)
        apis.update(p.surface.apis)
        admin.update(p.surface.admin_paths)
        forms.update(p.surface.forms)
        vendors.update(p.surface.third_parties)
    return KnownSurface(
        routes=tuple(sorted(routes)),
        assets=tuple(sorted(assets)),
        apis=tuple(sorted(apis)),
        admin_paths=tuple(sorted(admin)),
        forms=tuple(sorted(forms)),
        third_parties=tuple(sorted(vendors)),
    )
