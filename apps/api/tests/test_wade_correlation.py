# WebHound — apps/api/tests/test_wade_correlation.py
# Phase-4 slice 4: WADE behavioural-correlation tests.
#
# All rules tested with pure-function fingerprint sequences. Validates:
#   * each rule fires on its target pattern
#   * each rule abstains when the pattern isn't strong enough
#   * empty / single-scan histories never crash

from __future__ import annotations

import uuid

import pytest

from apps.api.models.enums import DriftSeverity
from apps.api.services.scan_delta import ScanFingerprint
from apps.api.services.wade_correlation import analyse_history


def _fp(
    *,
    tech: set | None = None,
    domains: set | None = None,
    tls: dict | None = None,
    headers: dict | None = None,
    forms: list | None = None,
) -> ScanFingerprint:
    return ScanFingerprint(
        scan_job_id=uuid.uuid4(),
        website_id=uuid.uuid4(),
        org_id=None,
        risk_score=50,
        external_domains=set(domains or set()),
        technologies=set(tech or set()),
        security_headers=dict(headers or {}),
        tls_summary=dict(tls or {}),
        forms=list(forms or []),
        apis=[],
        finding_severity_counts={},
    )


# ---------------------------------------------------------------------------
# Empty / too-short histories must not crash
# ---------------------------------------------------------------------------


def test_analyse_history_empty_returns_empty() -> None:
    assert analyse_history([]) == []


def test_analyse_history_single_scan_returns_empty() -> None:
    assert analyse_history([_fp()]) == []


# ---------------------------------------------------------------------------
# Tech-stack churn
# ---------------------------------------------------------------------------


def test_tech_churn_fires_on_multiple_changes() -> None:
    history = [
        _fp(tech={"React", "Next.js"}),
        _fp(tech={"React", "Vue.js"}),         # 1 swap: -Next.js, +Vue.js
        _fp(tech={"React", "Svelte"}),          # 1 swap: -Vue.js, +Svelte
        _fp(tech={"React", "Angular"}),         # 1 swap: -Svelte, +Angular
    ]
    out = analyse_history(history)
    pats = {a.pattern for a in out}
    assert "tech_stack_churn" in pats


def test_tech_churn_silent_when_stable() -> None:
    history = [_fp(tech={"React", "Next.js"})] * 4
    out = analyse_history(history)
    assert "tech_stack_churn" not in {a.pattern for a in out}


# ---------------------------------------------------------------------------
# TLS instability
# ---------------------------------------------------------------------------


def test_tls_instability_fires_on_repeated_changes() -> None:
    history = [
        _fp(tls={"min_tls_version": "TLSv1.3"}),
        _fp(tls={"min_tls_version": "TLSv1.2"}),
        _fp(tls={"min_tls_version": "TLSv1.3"}),
    ]
    out = analyse_history(history)
    pats = {a.pattern for a in out}
    assert "tls_instability" in pats
    # Pattern severity is HIGH.
    anomaly = next(a for a in out if a.pattern == "tls_instability")
    assert anomaly.severity == DriftSeverity.HIGH


def test_tls_instability_silent_when_stable() -> None:
    history = [_fp(tls={"min_tls_version": "TLSv1.3"})] * 5
    out = analyse_history(history)
    assert "tls_instability" not in {a.pattern for a in out}


# ---------------------------------------------------------------------------
# Third-party explosion
# ---------------------------------------------------------------------------


def test_third_party_explosion_fires_on_3x_jump() -> None:
    history = [
        _fp(domains={"a.test", "b.test"}),
        _fp(domains={"a.test", "b.test"}),
        _fp(domains={"a.test", "b.test"}),
        _fp(domains={f"x{i}.test" for i in range(7)}),  # 2 → 7 ≥ 3×
    ]
    out = analyse_history(history)
    pats = {a.pattern for a in out}
    assert "third_party_explosion" in pats


def test_third_party_explosion_silent_on_normal_growth() -> None:
    history = [
        _fp(domains={"a.test"}),
        _fp(domains={"a.test", "b.test"}),
        _fp(domains={"a.test", "b.test", "c.test"}),
    ]
    out = analyse_history(history)
    assert "third_party_explosion" not in {a.pattern for a in out}


def test_third_party_explosion_silent_with_zero_baseline() -> None:
    """When prior median was 0, the rule must NOT fire — that's first-
    scan noise, not behavioural drift."""
    history = [
        _fp(domains=set()),
        _fp(domains=set()),
        _fp(domains={f"x{i}.test" for i in range(10)}),
    ]
    out = analyse_history(history)
    assert "third_party_explosion" not in {a.pattern for a in out}


# ---------------------------------------------------------------------------
# Persistent header regression
# ---------------------------------------------------------------------------


def test_persistent_header_regression_fires_when_headers_disappear() -> None:
    history = [
        _fp(headers={"Content-Security-Policy": "default-src 'self'",
                     "Strict-Transport-Security": "max-age=63072000"}),
        _fp(headers={"Content-Security-Policy": "default-src 'self'",
                     "Strict-Transport-Security": "max-age=63072000"}),
        _fp(headers={}),
        _fp(headers={}),
    ]
    out = analyse_history(history)
    pats = {a.pattern for a in out}
    assert "persistent_header_regression" in pats


def test_persistent_header_regression_silent_on_intermittent() -> None:
    """One scan with a missing header isn't a sustained regression."""
    history = [
        _fp(headers={"Content-Security-Policy": "x"}),
        _fp(headers={"Content-Security-Policy": "x"}),
        _fp(headers={}),
        _fp(headers={"Content-Security-Policy": "x"}),
    ]
    out = analyse_history(history)
    assert "persistent_header_regression" not in {a.pattern for a in out}


# ---------------------------------------------------------------------------
# Login form flapping
# ---------------------------------------------------------------------------


def test_login_form_flapping_fires_on_2plus_flips() -> None:
    history = [
        _fp(forms=["https://target/admin/login"]),
        _fp(forms=[]),
        _fp(forms=["https://target/admin/login"]),
        _fp(forms=[]),
    ]
    out = analyse_history(history)
    pats = {a.pattern for a in out}
    assert "login_form_flapping" in pats


def test_login_form_flapping_silent_on_one_transition() -> None:
    """A single appear-or-disappear isn't flapping — could be a real
    feature rollout."""
    history = [
        _fp(forms=[]),
        _fp(forms=[]),
        _fp(forms=["https://target/admin/login"]),
        _fp(forms=["https://target/admin/login"]),
    ]
    out = analyse_history(history)
    assert "login_form_flapping" not in {a.pattern for a in out}


# ---------------------------------------------------------------------------
# Evidence + explainability invariants
# ---------------------------------------------------------------------------


def test_every_anomaly_includes_evidence_scan_ids() -> None:
    history = [
        _fp(tls={"min_tls_version": "TLSv1.3"}),
        _fp(tls={"min_tls_version": "TLSv1.2"}),
        _fp(tls={"min_tls_version": "TLSv1.3"}),
    ]
    out = analyse_history(history)
    assert out
    for a in out:
        assert a.evidence_scan_job_ids
        assert a.title
        assert a.description
        assert a.pattern
