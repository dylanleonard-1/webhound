# WebHound API — apps/api/platform/security/env_validator.py
# Phase-19 Task 2/14: startup environment validation. Enumerates the env
# vars each feature needs, checks presence (never logs VALUES), and in
# production fails fast on missing CRITICAL vars; in development it warns.
#
# Pure over an env mapping (defaults to os.environ) so it's unit-testable
# without touching the real process environment.

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class EnvRequirement:
    name: str
    critical: bool                  # missing → fail fast in production
    feature: str                    # which subsystem needs it
    enabled_by: str | None = None   # only required when this flag is truthy


# Core requirements + feature-gated ones. Critical = the app can't run
# safely in production without it.
_REQUIREMENTS: tuple[EnvRequirement, ...] = (
    EnvRequirement("DATABASE_URL", True, "core"),
    EnvRequirement("REDIS_URL", True, "core"),
    EnvRequirement("APP_ENV", True, "core"),
    EnvRequirement("SECRET_KEY", True, "core"),
    EnvRequirement("API_BASE_URL", False, "core"),
    EnvRequirement("FRONTEND_URL", False, "core"),
    # Billing — critical only when Stripe is enabled.
    EnvRequirement("STRIPE_SECRET_KEY", True, "billing", "BILLING_ENABLED"),
    EnvRequirement("STRIPE_WEBHOOK_SECRET", True, "billing", "BILLING_ENABLED"),
    # Email — critical only when transactional email is enabled.
    EnvRequirement("RESEND_API_KEY", True, "email", "EMAIL_ENABLED"),
    # OAuth — critical only when OAuth login is enabled.
    EnvRequirement("GOOGLE_CLIENT_ID", True, "oauth", "OAUTH_ENABLED"),
    EnvRequirement("GOOGLE_CLIENT_SECRET", True, "oauth", "OAUTH_ENABLED"),
)

_INSECURE_DEFAULTS = {
    "SECRET_KEY": {"dev-secret-key-change-in-production",
                   "change-me-in-production", ""},
}


def _truthy(env: Mapping[str, str], key: str) -> bool:
    return str(env.get(key, "")).lower() in ("1", "true", "yes", "on")


@dataclass
class EnvValidationResult:
    app_env: str
    ok: bool
    missing_critical: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    insecure_defaults: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_env": self.app_env,
            "ok": self.ok,
            "missing_critical": list(self.missing_critical),
            "missing_optional": list(self.missing_optional),
            "insecure_defaults": list(self.insecure_defaults),
            "warnings": list(self.warnings),
        }


def validate_env(
    env: Mapping[str, str] | None = None,
) -> EnvValidationResult:
    """Validate the environment. Never reads or returns secret values —
    only names + presence."""
    env = env if env is not None else os.environ
    app_env = str(env.get("APP_ENV", "development")).lower()
    is_prod = app_env == "production"

    res = EnvValidationResult(app_env=app_env, ok=True)
    for req in _REQUIREMENTS:
        if req.enabled_by and not _truthy(env, req.enabled_by):
            continue                          # feature off → not required
        present = bool(str(env.get(req.name, "")).strip())
        if present:
            # Insecure-default check (e.g. dev SECRET_KEY in prod).
            bad = _INSECURE_DEFAULTS.get(req.name)
            if bad is not None and env.get(req.name, "") in bad:
                res.insecure_defaults.append(req.name)
                if is_prod:
                    res.ok = False
            continue
        if req.critical:
            res.missing_critical.append(req.name)
            if is_prod:
                res.ok = False
            else:
                res.warnings.append(
                    f"{req.name} not set (required for {req.feature} in "
                    "production)")
        else:
            res.missing_optional.append(req.name)
    return res


class EnvValidationError(RuntimeError):
    """Raised at startup when production is missing critical env vars."""


def enforce_env(env: Mapping[str, str] | None = None) -> EnvValidationResult:
    """Validate + FAIL FAST in production. In development, returns the
    result (warnings only)."""
    res = validate_env(env)
    if not res.ok:
        raise EnvValidationError(
            "Production environment is not safe to start. "
            f"Missing critical: {res.missing_critical}; "
            f"insecure defaults: {res.insecure_defaults}.")
    return res
