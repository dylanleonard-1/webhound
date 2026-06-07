# WebHound API — apps/api/tests/test_platform.py
# Phase-19 production hardening: env validation, structured logging +
# secret redaction, job retry policy, onboarding state, production
# readiness. All pure — no DB, no Redis.

from __future__ import annotations

from apps.api.platform.health.production_readiness import build_readiness_report
from apps.api.platform.jobs.retry_policy import (
    FailureClass,
    classify_failure,
    decide_retry,
    job_timeout_seconds,
)
from apps.api.platform.observability.structured_logging import (
    redact,
    scan_log_record,
)
from apps.api.platform.onboarding.onboarding_state import (
    OnboardingFacts,
    derive_onboarding_state,
)
from apps.api.platform.security.env_validator import (
    EnvValidationError,
    enforce_env,
    validate_env,
)

_PROD_BASE = {
    "APP_ENV": "production", "DATABASE_URL": "postgres://x",
    "REDIS_URL": "redis://x", "SECRET_KEY": "a-real-strong-secret-value",
}


# ---------------------------------------------------------------------------
# Env validation (Task 2/14)
# ---------------------------------------------------------------------------


def test_prod_missing_critical_fails() -> None:
    res = validate_env({"APP_ENV": "production", "SECRET_KEY": "x"})
    assert not res.ok
    assert "DATABASE_URL" in res.missing_critical
    assert "REDIS_URL" in res.missing_critical


def test_dev_missing_critical_warns_only() -> None:
    res = validate_env({"APP_ENV": "development"})
    assert res.ok                                # dev never blocks
    assert res.warnings


def test_prod_insecure_secret_key_blocks() -> None:
    res = validate_env({**_PROD_BASE,
                        "SECRET_KEY": "dev-secret-key-change-in-production"})
    assert not res.ok
    assert "SECRET_KEY" in res.insecure_defaults


def test_feature_gated_env_only_required_when_enabled() -> None:
    # Billing off → Stripe keys not required.
    assert validate_env(_PROD_BASE).ok
    # Billing on → Stripe keys required.
    res = validate_env({**_PROD_BASE, "BILLING_ENABLED": "true"})
    assert not res.ok
    assert "STRIPE_SECRET_KEY" in res.missing_critical


def test_enforce_env_raises_in_prod() -> None:
    try:
        enforce_env({"APP_ENV": "production"})
        assert False, "expected EnvValidationError"
    except EnvValidationError:
        pass


def test_enforce_env_ok_returns_result() -> None:
    res = enforce_env(_PROD_BASE)
    assert res.ok


# ---------------------------------------------------------------------------
# Structured logging + secret redaction (Task 3)
# ---------------------------------------------------------------------------


def test_redact_secret_keys() -> None:
    out = redact({"domain": "x.com", "password": "hunter2",
                  "api_key": "abc", "session_cookie": "s=1"})
    assert out["domain"] == "x.com"
    assert out["password"] == "<redacted>"
    assert out["api_key"] == "<redacted>"
    assert out["session_cookie"] == "<redacted>"


def test_redact_secret_value_patterns() -> None:
    out = redact({"note": "sk_live_ABCDEF123456",
                  "auth": "Bearer abc.def.ghi",
                  "k": "whsec_xyz123", "ok": "normal"})
    assert out["note"] == "<redacted>"
    assert out["auth"] == "<redacted>"
    assert out["k"] == "<redacted>"
    assert out["ok"] == "normal"


def test_redact_nested() -> None:
    out = redact({"meta": {"token": "t", "host": "h"}})
    assert out["meta"]["token"] == "<redacted>"
    assert out["meta"]["host"] == "h"


def test_scan_log_record_standard_fields() -> None:
    rec = scan_log_record(event="scan_complete", scan_id="s1", job_id="j1",
                          domain="x.com", engine="headers", status="completed",
                          duration_ms=1200.0, api_key="leak")
    assert rec["event"] == "scan_complete"
    assert rec["scan_id"] == "s1"
    assert rec["domain"] == "x.com"
    assert rec["api_key"] == "<redacted>"        # extra is redacted too
    assert "error_type" not in rec               # Nones dropped


# ---------------------------------------------------------------------------
# Job retry policy (Task 4)
# ---------------------------------------------------------------------------


def test_transient_error_retries_with_backoff() -> None:
    d = decide_retry("Connection timed out", attempt=1)
    assert d.should_retry
    assert d.failure_class == FailureClass.TRANSIENT
    assert d.backoff_seconds == 30
    assert not d.dead_letter


def test_transient_backoff_grows() -> None:
    assert decide_retry("network error", attempt=2).backoff_seconds == 60


def test_permanent_error_dead_letters() -> None:
    d = decide_retry("ValidationError: invalid target", attempt=1)
    assert not d.should_retry
    assert d.failure_class == FailureClass.PERMANENT
    assert d.dead_letter


def test_exhausted_retries_dead_letter() -> None:
    d = decide_retry("timeout", attempt=3, max_retries=3)
    assert not d.should_retry
    assert d.dead_letter


def test_browser_failure_is_degraded_not_failure() -> None:
    d = decide_retry("browser pass failed; static scan succeeded", attempt=1)
    assert d.failure_class == FailureClass.DEGRADED
    assert not d.should_retry
    assert not d.dead_letter                     # the job still succeeds


def test_unverified_domain_is_permanent() -> None:
    assert classify_failure("domain unverified") == FailureClass.PERMANENT


def test_job_timeout_per_profile() -> None:
    assert job_timeout_seconds("quick") == 180
    assert job_timeout_seconds("deep") == 1800
    assert job_timeout_seconds(None) == 900


# ---------------------------------------------------------------------------
# Onboarding state (Task 9)
# ---------------------------------------------------------------------------


def test_fresh_account_next_step_is_email() -> None:
    st = derive_onboarding_state(OnboardingFacts())
    assert not st.is_complete
    assert st.next_step["key"] == "email_verified"


def test_onboarding_progress() -> None:
    st = derive_onboarding_state(OnboardingFacts(
        email_verified=True, domain_added=True, domain_verified=True,
        first_scan_started=True))
    assert st.is_complete                        # all REQUIRED (free) done
    assert st.next_step["key"] == "first_report_viewed"  # optional remains


def test_paid_plan_requires_billing() -> None:
    facts = OnboardingFacts(
        email_verified=True, domain_added=True, domain_verified=True,
        first_scan_started=True, is_paid_plan=True, billing_active=False)
    st = derive_onboarding_state(facts)
    assert not st.is_complete                    # billing step gates it
    assert any(s["key"] == "billing_active" for s in st.steps)


def test_free_plan_has_no_billing_step() -> None:
    st = derive_onboarding_state(OnboardingFacts(is_paid_plan=False))
    assert not any(s["key"] == "billing_active" for s in st.steps)


# ---------------------------------------------------------------------------
# Production readiness (Task 14)
# ---------------------------------------------------------------------------


def test_readiness_all_green() -> None:
    rep = build_readiness_report(env=_PROD_BASE, db_ok=True, redis_ok=True,
                                 worker_ok=True, migrations_current=True)
    assert rep.ready
    assert rep.failing_critical == []


def test_readiness_blocks_on_db_down() -> None:
    rep = build_readiness_report(env=_PROD_BASE, db_ok=False, redis_ok=True)
    assert not rep.ready
    assert "database" in rep.failing_critical


def test_readiness_includes_scanner_import() -> None:
    rep = build_readiness_report(env=_PROD_BASE, db_ok=True, redis_ok=True)
    names = {c.name for c in rep.checks}
    assert "scanner_importable" in names
    assert "env" in names
