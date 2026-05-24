# WebHound — scanner/webhound/utils/hashing.py
# Stable content-fingerprinting helpers shared across scanner modules.
#
# All hashes are SHA-256 in hex form. Inputs are encoded as UTF-8 with
# `errors="replace"` so binary or partially-decoded payloads never raise
# from the scanner hot path.

from __future__ import annotations

import hashlib
import re
from typing import Iterable

_WHITESPACE_RE = re.compile(r"\s+")


def sha256_hex(text: str) -> str:
    """SHA-256 hex digest of *text* (encoded as UTF-8, replace errors)."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def short_hash(text: str, n: int = 12) -> str:
    """First *n* hex chars of the SHA-256 of *text* — for short ID display."""
    if n < 1 or n > 64:
        raise ValueError(f"short_hash length must be 1..64, got {n}")
    return sha256_hex(text)[:n]


def content_fingerprint(text: str) -> str:
    """Whitespace-normalised SHA-256 — stable across reformatting.

    Two inputs that differ only in whitespace (line endings, indentation,
    trailing spaces) hash to the same value. Used by WADE so cosmetic
    bundler-output changes don't generate false-positive script diffs.
    """
    normalised = _WHITESPACE_RE.sub(" ", text).strip()
    return sha256_hex(normalised)


def combine_hashes(parts: Iterable[str]) -> str:
    """Stable hash of multiple already-hashed components, in given order."""
    joined = "|".join(p for p in parts if p)
    return sha256_hex(joined)
