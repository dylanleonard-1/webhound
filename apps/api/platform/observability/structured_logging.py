# WebHound API — apps/api/platform/observability/structured_logging.py
# Phase-19 Task 3: standardized structured log records for scans/jobs +
# hard secret redaction. Builds a flat, JSON-safe dict with the standard
# fields (scan_id, job_id, domain, engine, duration, status, error_type)
# and recursively redacts anything that looks like a secret BEFORE it can
# be emitted. Pure — produces dicts; the caller hands them to its logger.

from __future__ import annotations

import re
from typing import Any

# Keys whose VALUES must never be logged (case-insensitive substring).
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|"
    r"session|bearer|credential|private[_-]?key|access[_-]?key|"
    r"webhook[_-]?secret|stripe[_-]?secret|client[_-]?secret)",
    re.IGNORECASE)

# Value patterns that look like secrets even under an innocuous key.
_SECRET_VALUE_RES = (
    re.compile(r"^sk_(live|test)_[A-Za-z0-9]+"),       # Stripe secret key
    re.compile(r"^whsec_[A-Za-z0-9]+"),                # Stripe webhook secret
    re.compile(r"^Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\."),  # JWT
    re.compile(r"^re_[A-Za-z0-9]+"),                   # Resend key
)

_REDACTED = "<redacted>"
_MAX_STR = 500


def _redact_value(key: str, value: Any) -> Any:
    if _SECRET_KEY_RE.search(key or ""):
        return _REDACTED
    if isinstance(value, str):
        for pat in _SECRET_VALUE_RES:
            if pat.match(value):
                return _REDACTED
        return value[:_MAX_STR]
    if isinstance(value, dict):
        return redact(value)
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, v) for v in value]
    return value


def redact(record: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact secret-looking keys/values from a dict."""
    return {k: _redact_value(k, v) for k, v in (record or {}).items()}


def scan_log_record(
    *,
    event: str,
    scan_id: str | None = None,
    job_id: str | None = None,
    user_id: str | None = None,
    domain: str | None = None,
    worker_id: str | None = None,
    engine: str | None = None,
    duration_ms: float | None = None,
    status: str | None = None,
    error_type: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build the standard scan/job log record (Task 3). user_id is
    included only as an opaque id (never email/PII), and every field —
    including ``extra`` — passes through secret redaction."""
    record: dict[str, Any] = {
        "event": event,
        "scan_id": scan_id,
        "job_id": job_id,
        "user_id": user_id,
        "domain": domain,
        "worker_id": worker_id,
        "engine": engine,
        "duration_ms": duration_ms,
        "status": status,
        "error_type": error_type,
    }
    record.update(extra)
    # Drop Nones for compactness, then redact.
    return redact({k: v for k, v in record.items() if v is not None})
