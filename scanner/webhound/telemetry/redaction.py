# WebHound — scanner/webhound/telemetry/redaction.py
# Phase-2 telemetry redaction. The scanner is the foundation layer and
# cannot import apps.api, so this is the canonical home for the secret
# patterns (the Phase-17 apps/api structured_logging.redact uses the same
# set; it may import from here later to dedupe).
#
# Two layers:
#   1. redact(dict)        — drop secret-looking KEYS + secret-VALUE
#                            patterns recursively (same as Phase-17).
#   2. safe_payload(dict)  — telemetry allowlist: keep only count/duration/
#                            id/enum/hostname/hash-shaped values; anything
#                            else is summarised, never stored verbatim.

from __future__ import annotations

import re
from typing import Any

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|"
    r"session|bearer|credential|private[_-]?key|access[_-]?key|"
    r"webhook[_-]?secret|stripe[_-]?secret|client[_-]?secret)",
    re.IGNORECASE)

_SECRET_VALUE_RES = (
    re.compile(r"^sk_(live|test)_[A-Za-z0-9]+"),          # Stripe secret key
    re.compile(r"^whsec_[A-Za-z0-9]+"),                   # Stripe webhook secret
    re.compile(r"^Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\."),  # JWT
    re.compile(r"^re_[A-Za-z0-9]+"),                      # Resend key
)

REDACTED = "<redacted>"
_MAX_STR = 256


def _redact_value(key: str, value: Any) -> Any:
    if _SECRET_KEY_RE.search(key or ""):
        return REDACTED
    if isinstance(value, str):
        for pat in _SECRET_VALUE_RES:
            if pat.match(value):
                return REDACTED
        return value[:_MAX_STR]
    if isinstance(value, dict):
        return redact(value)
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, v) for v in value]
    return value


def redact(record: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact secret-looking keys/values from a dict."""
    return {k: _redact_value(k, v) for k, v in (record or {}).items()}


# ---------------------------------------------------------------------------
# Telemetry allowlist — inputs/outputs/metadata must be counts + safe scalars.
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
_SAFE_STR_KEYS = frozenset({
    "status", "stage", "engine", "band", "category", "change_type",
    "confidence_label", "finding_type", "framework", "decision", "reason",
    "correlation_type", "profile", "severity", "host", "domain", "path",
})


def _safe_scalar(key: str, value: Any) -> Any:
    """Coerce a value to a telemetry-safe form, or None to drop it."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        k = key.lower()
        # Allow short enum/category strings + hostnames; strip query strings
        # from anything path/url-shaped (store path only).
        if k in ("path", "url"):
            return value.split("?", 1)[0][:_MAX_STR]
        if k in _SAFE_STR_KEYS or _HOSTNAME_RE.match(value):
            return value[:_MAX_STR]
        # Unknown free string → keep only its length (never the content).
        return {"len": len(value)}
    return None


def safe_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Reduce an inputs/outputs/metadata dict to telemetry-safe values.
    Counts + durations + enum strings + hostnames pass; lists become
    counts; unknown strings become length-only; secrets are redacted."""
    if not payload:
        return {}
    out: dict[str, Any] = {}
    red = redact(payload)
    for k, v in red.items():
        if v == REDACTED:
            out[k] = REDACTED
        elif isinstance(v, dict):
            out[k] = safe_payload(v)
        elif isinstance(v, (list, tuple)):
            out[k] = {"count": len(v)}
        else:
            sv = _safe_scalar(k, v)
            if sv is not None:
                out[k] = sv
    return out
