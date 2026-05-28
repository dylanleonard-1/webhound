# WebHound — scanner/tests/test_scanner_quality_phase3.py
# Phase-3 scanner-audit tests. Focuses on cross-engine correlation: chains
# must fire only when ≥2 independent signals converge, must never lower an
# existing finding's confidence, and the cluster finding must carry a clear
# audit trail back to its constituents.

from __future__ import annotations

import pytest

from webhound.core.correlation import (
    apply_correlation,
    correlate_findings,
)
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Tiny fixture helpers — keep these inline so each test is self-explanatory
# ---------------------------------------------------------------------------


def _f(title: str, engine: str, *, severity=Severity.MEDIUM,
       confidence: float = 0.7, metadata: dict | None = None) -> Finding:
    return Finding(
        title=title,
        description=f"fixture finding for {engine}",
        severity=severity,
        category=FindingCategory.UNKNOWN,
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW,
            content="test",
            location="https://example.com/",
            source_engine=engine,
        )],
        confidence=confidence,
        scanner_engine=engine,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Chain firing — supply-chain compromise
# ---------------------------------------------------------------------------


def test_supply_chain_chain_fires_on_three_signals() -> None:
    findings = [
        _f("Missing Content-Security-Policy header",
           "security_headers", severity=Severity.LOW, confidence=0.7),
        _f("Suspicious third-party domain detected: punycode label",
           "threat_intel", severity=Severity.MEDIUM, confidence=0.7),
        _f("Inline script uses base64 decoder",
           "obfuscation_detector", severity=Severity.MEDIUM, confidence=0.6),
    ]
    result = correlate_findings(findings)
    assert len(result.cluster_findings) == 1
    cluster = result.cluster_findings[0]
    assert cluster.severity == Severity.HIGH
    assert "supply_chain_compromise_risk" in cluster.tags
    assert cluster.metadata["signal_count"] == 3
    # Constituent IDs are recorded so the UI can backlink.
    assert len(cluster.metadata["constituent_finding_ids"]) == 3


def test_supply_chain_chain_fires_on_two_signals_minimum() -> None:
    """Two converging signals is enough — the rule shouldn't insist on all
    three. (User policy: heightened concern when ≥2 signals agree.)"""
    findings = [
        _f("Weak Content-Security-Policy: unsafe-inline allowed",
           "security_headers", severity=Severity.MEDIUM, confidence=0.7),
        _f("Inline script contains long base64 blob",
           "obfuscation_detector", severity=Severity.LOW, confidence=0.4),
    ]
    result = correlate_findings(findings)
    assert len(result.cluster_findings) == 1
    cluster = result.cluster_findings[0]
    assert cluster.metadata["signal_count"] == 2


def test_supply_chain_chain_does_not_fire_on_one_signal() -> None:
    """One signal in isolation must NOT produce a cluster — that would just
    be noise on top of the original finding."""
    findings = [
        _f("Missing Content-Security-Policy header",
           "security_headers", severity=Severity.LOW, confidence=0.6),
    ]
    result = correlate_findings(findings)
    assert result.cluster_findings == []
    assert result.boosted_finding_ids == {}


# ---------------------------------------------------------------------------
# Chain firing — exposed admin surface
# ---------------------------------------------------------------------------


def test_exposed_admin_chain_fires_on_admin_path_plus_weak_headers() -> None:
    findings = [
        _f("Sensitive path exposed: /admin returned 200",
           "sensitive_paths", severity=Severity.MEDIUM, confidence=0.8,
           metadata={"path": "/admin"}),
        _f("Missing Strict-Transport-Security (HSTS) header",
           "security_headers", severity=Severity.LOW, confidence=0.7),
    ]
    result = correlate_findings(findings)
    assert len(result.cluster_findings) == 1
    assert result.cluster_findings[0].metadata["chain_name"] == \
        "exposed_admin_attack_surface"


def test_exposed_admin_chain_inspects_metadata_path() -> None:
    """The rule must look at metadata.path (where sensitive_paths puts the
    path), not just at the title — titles vary across engine versions but
    metadata.path is canonical."""
    findings = [
        _f("Recon path probe returned 200",
           "sensitive_paths", severity=Severity.MEDIUM, confidence=0.8,
           metadata={"path": "/login"}),
        _f("Login form found without CSRF token",
           "form_risk", severity=Severity.MEDIUM, confidence=0.7),
    ]
    result = correlate_findings(findings)
    assert len(result.cluster_findings) == 1


# ---------------------------------------------------------------------------
# Chain firing — credential exfiltration
# ---------------------------------------------------------------------------


def test_credential_exfil_chain_is_critical_severity() -> None:
    """The credential-exfil cluster is the most serious chain — when all
    three signals converge it MUST surface as CRITICAL or the dashboard
    risk-scoring won't escalate it correctly."""
    findings = [
        _f("Inline script uses eval and atob",
           "obfuscation_detector", severity=Severity.MEDIUM, confidence=0.6),
        _f("High-risk third-party domain referenced",
           "threat_intel", severity=Severity.MEDIUM, confidence=0.7),
        _f("Possible API token pattern in inline JS",
           "secret_scanner", severity=Severity.HIGH, confidence=0.8),
    ]
    result = correlate_findings(findings)
    assert len(result.cluster_findings) == 1
    cluster = result.cluster_findings[0]
    assert cluster.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Confidence bumps — only ever up, never down
# ---------------------------------------------------------------------------


def test_confidence_bump_only_raises_never_lowers() -> None:
    """A finding with confidence 0.9 should stay at 0.9 (or go up), never
    drop. The bump is min(1.0, max(current, current + bump))."""
    high_conf_finding = _f(
        "Missing Content-Security-Policy header",
        "security_headers", severity=Severity.MEDIUM, confidence=0.9,
    )
    low_conf_finding = _f(
        "Inline script base64 blob",
        "obfuscation_detector", severity=Severity.LOW, confidence=0.4,
    )
    findings = [high_conf_finding, low_conf_finding]
    corr = correlate_findings(findings)
    updated = apply_correlation(findings, corr)
    # Find the original two by id
    by_id = {f.id: f for f in updated if f.scanner_engine != "correlation"}
    assert by_id[high_conf_finding.id].confidence >= 0.9
    assert by_id[low_conf_finding.id].confidence > 0.4


def test_apply_correlation_tags_corroborated_findings() -> None:
    findings = [
        _f("Missing CSP", "security_headers", confidence=0.7),
        _f("base64 inline blob", "obfuscation_detector", confidence=0.5),
    ]
    corr = correlate_findings(findings)
    updated = apply_correlation(findings, corr)
    per_engine = [f for f in updated if f.scanner_engine != "correlation"]
    for f in per_engine:
        assert "corroborated" in f.tags
        assert f.metadata.get("corroborated_by")  # non-empty


def test_apply_correlation_is_idempotent() -> None:
    """Re-applying the same CorrelationResult should not stack confidence
    or duplicate tags. This matters when a re-run hits the cache or the
    UI re-renders without rescanning."""
    findings = [
        _f("Missing CSP", "security_headers", confidence=0.7),
        _f("base64 inline blob", "obfuscation_detector", confidence=0.5),
    ]
    corr = correlate_findings(findings)
    first_pass = apply_correlation(findings, corr)
    # Exclude the cluster from re-application (it's not a constituent)
    per_engine = [f for f in first_pass if f.scanner_engine != "correlation"]
    second_pass = apply_correlation(per_engine, corr)
    per_engine_2 = [f for f in second_pass if f.scanner_engine != "correlation"]
    # Confidence shouldn't keep climbing
    for a, b in zip(per_engine, per_engine_2):
        assert a.confidence == b.confidence
        assert a.tags.count("corroborated") == b.tags.count("corroborated") == 1


# ---------------------------------------------------------------------------
# Clean-scan invariant: zero per-engine findings → zero clusters
# ---------------------------------------------------------------------------


def test_clean_scan_produces_no_clusters() -> None:
    result = correlate_findings([])
    assert result.cluster_findings == []
    assert result.boosted_finding_ids == {}


def test_unrelated_findings_produce_no_clusters() -> None:
    """A pile of unrelated findings should not produce spurious clusters."""
    findings = [
        _f("Mixed-content warning", "headers", severity=Severity.LOW,
           confidence=0.7),
        _f("Cookie missing Secure flag", "cookie_scanner",
           severity=Severity.LOW, confidence=0.8),
    ]
    result = correlate_findings(findings)
    assert result.cluster_findings == []


# ---------------------------------------------------------------------------
# Cluster finding shape — must include the chain name + constituent IDs in
# a structured way (export/UI relies on this contract)
# ---------------------------------------------------------------------------


def test_cluster_finding_carries_constituent_metadata() -> None:
    findings = [
        _f("Missing CSP", "security_headers", confidence=0.7),
        _f("Suspicious third-party domain", "threat_intel", confidence=0.7),
    ]
    result = correlate_findings(findings)
    cluster = result.cluster_findings[0]
    assert cluster.scanner_engine == "correlation"
    assert "cluster" in cluster.tags
    assert "correlated" in cluster.tags
    constituents = cluster.metadata.get("constituents") or []
    assert len(constituents) == 2
    # Each constituent records engine + severity for transparency
    for c in constituents:
        assert "engine" in c
        assert "severity" in c
        assert "title" in c
