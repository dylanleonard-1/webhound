# WebHound — scanner/webhound/utils/fingerprints.py
# Asset fingerprinting used by WADE baseline storage.
#
# A "fingerprint" is a stable identifier for an asset (a script, a stylesheet,
# a form, a host) that survives cosmetic changes (whitespace, cache-busting
# query strings) but flips when the underlying content meaningfully changes.

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from .hashing import content_fingerprint, sha256_hex, short_hash

# Query-string parameters universally used for cache-busting; they're stripped
# before fingerprinting so a `?ver=1.2.3` bump doesn't flip the asset ID.
_CACHE_BUST_PARAMS = frozenset({
    "v", "ver", "version", "t", "ts", "rev", "_", "cache",
    "cb", "build", "hash",
})


def script_url_fingerprint(url: str) -> str:
    """Stable short fingerprint of a script URL, ignoring cache-busters.

    Used by WADE so a vendor's cache-busted CDN URL doesn't show as a
    new script every time they bump their build hash.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return short_hash(url)
    # Strip cache-bust params from the query string.
    if parsed.query:
        kept = []
        for part in parsed.query.split("&"):
            if "=" in part:
                k = part.split("=", 1)[0].lower()
            else:
                k = part.lower()
            if k not in _CACHE_BUST_PARAMS:
                kept.append(part)
        clean_query = "&".join(kept)
    else:
        clean_query = ""
    cleaned = urlunparse((
        parsed.scheme.lower(), (parsed.hostname or "").lower(),
        parsed.path, "", clean_query, "",
    ))
    return short_hash(cleaned)


def inline_script_hash(body: str) -> str:
    """Whitespace-normalised SHA-256 of an inline script body."""
    return content_fingerprint(body or "")


def host_fingerprint(host: str) -> str:
    """Stable identifier for a host — lowercase short hash."""
    return short_hash((host or "").strip().lower())


def form_signature(method: str, action: str, field_names: list[str]) -> str:
    """Pipe-delimited form signature: method|action|sorted-fields.

    Matches the existing WADE format so callers can rebuild without
    re-implementing the algorithm.
    """
    fields = "+".join(sorted(set(n for n in field_names if n)))
    return f"{(method or 'GET').upper()}|{action or ''}|{fields}"


def form_fingerprint(method: str, action: str, field_names: list[str]) -> str:
    """Short hash of `form_signature(...)` — for compact ID columns."""
    return short_hash(form_signature(method, action, field_names))


# Re-export sha256_hex for callers that want a canonical "long" fingerprint.
__all__ = [
    "script_url_fingerprint", "inline_script_hash", "host_fingerprint",
    "form_signature", "form_fingerprint", "sha256_hex",
]
