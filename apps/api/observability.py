# WebHound — apps/api/observability.py
# Sentry error monitoring for the FastAPI backend.
#
# Environment-aware: only initializes when SENTRY_DSN is set AND app_env is not
# "development". Local dev and unconfigured environments are no-ops, and
# sentry_sdk.capture_exception() is itself a no-op when uninitialized, so call
# sites never need to guard.
#
# Request context is captured, but secrets are scrubbed in before_send /
# before_send_transaction: send_default_pii stays off, and Authorization /
# Cookie headers plus token/password-like fields are redacted.

from __future__ import annotations

import logging

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

_REDACT = "[redacted]"
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "stripe-signature"}
_SENSITIVE_KEYS = ("password", "token", "secret", "api_key", "card", "cvv", "authorization")


def _scrub(event, _hint):
    """Redact secrets from outgoing Sentry events (defense in depth)."""
    try:
        req = event.get("request")
        if isinstance(req, dict):
            headers = req.get("headers")
            if isinstance(headers, dict):
                for h in list(headers):
                    if h.lower() in _SENSITIVE_HEADERS:
                        headers[h] = _REDACT
            # Never ship raw request bodies (may carry credentials/payment data).
            if "data" in req:
                req["data"] = _REDACT
            req.pop("cookies", None)
        # Scrub obvious secret-looking keys anywhere in extra/contexts.
        for section in ("extra", "contexts"):
            data = event.get(section)
            if isinstance(data, dict):
                for k in list(data):
                    if any(s in k.lower() for s in _SENSITIVE_KEYS):
                        data[k] = _REDACT
    except Exception:  # noqa: BLE001 — scrubbing must never break error reporting
        pass
    return event


def init_sentry() -> bool:
    """Initialize Sentry for the API if configured. Returns True if enabled."""
    settings = get_settings()
    if not settings.sentry_dsn or settings.app_env == "development":
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.app_env,
            integrations=[StarletteIntegration(), FastApiIntegration()],
            traces_sample_rate=settings.sentry_traces_sample_rate,
            send_default_pii=False,
            before_send=_scrub,
            before_send_transaction=_scrub,
        )
        logger.info("Sentry initialized (env=%s)", settings.app_env)
        return True
    except Exception:  # noqa: BLE001 — never let monitoring setup crash startup
        logger.exception("Sentry init failed; continuing without it")
        return False
