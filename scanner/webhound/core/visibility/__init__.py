# WebHound — scanner/webhound/core/visibility/
# Crawler VISIBILITY layer: maximum discovery of every public / customer-
# approved page, route, form, API endpoint, script, asset, and hidden entry
# point, producing a site graph + visibility/coverage score.
#
# This is DISCOVERY / VISIBILITY, not exploit scanning. It is built AROUND the
# existing scanner and (when enabled) runs BEFORE the security engines, feeding
# them more in-scope pages. The whole layer is gated behind
# ScanOptions.visibility_enabled (default OFF → behaviour identical to today).
#
# Design rule: REUSE the existing extraction substrate (UrlNormalizer,
# extractor, route_extractor, url_discovery, form_discovery, endpoint_discovery,
# asm, graph, auth). This package adds orchestration + a canonical model +
# a score + persistence — it does NOT re-implement extraction.

from __future__ import annotations

from webhound.core.visibility.discovered_url import (
    DiscoveredUrl,
    UrlSource,
    UrlStatus,
    canonicalize,
    normalize_url,
)

__all__ = [
    "DiscoveredUrl",
    "UrlSource",
    "UrlStatus",
    "canonicalize",
    "normalize_url",
]
