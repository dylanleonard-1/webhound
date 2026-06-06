# WebHound — tests/test_trust_policy.py
# Phase-7: finding-type + confidence-label classification and the
# central severity calibrator. These encode the trust contract:
# inventory is not a risk, hardening is not a vulnerability, and
# pattern-only detections cannot be CRITICAL.

from __future__ import annotations

import pytest

from webhound.core.severity_calibrator import calibrate_findings
from webhound.core.trust_policy import (
    apply_trust_policy,
    classify_finding,
    confidence_label,
)
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.severity import Severity


def _finding(title="Test", severity=Severity.MEDIUM, confidence=0.8,
             category=FindingCategory.SECURITY_HEADER, engine="test",
             tags=None, metadata=None) -> Finding:
    return Finding(
        title=title, description="d", severity=severity,
        category=category, confidence=confidence,
        scanner_engine=engine, tags=tags or [],
        metadata=metadata or {},
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW, content="x",
            location="https://t.test/", source_engine=engine,
        )],
    )


# ---------------------------------------------------------------------------
# Confidence labels (Task 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("conf,label", [
    (0.95, "confirmed"), (0.9, "confirmed"), (0.8, "high"),
    (0.6, "medium"), (0.45, "low"), (0.2, "heuristic"),
])
def test_confidence_label_thresholds(conf, label) -> None:
    assert confidence_label(_finding(confidence=conf)) == label


def test_heuristic_tag_overrides_numeric_confidence() -> None:
    f = _finding(confidence=0.85, tags=["heuristic"])
    assert confidence_label(f) == "heuristic"


# ---------------------------------------------------------------------------
# Finding types (Task 2)
# ---------------------------------------------------------------------------


def test_security_headers_are_hardening_not_risk() -> None:
    f = _finding(title="Missing Content-Security-Policy header",
                 severity=Severity.MEDIUM, confidence=1.0)
    assert classify_finding(f) == "hardening"


def test_confirmed_but_hardening_stays_hardening() -> None:
    """Task-3 contract: confirmed-missing Permissions-Policy is still
    hardening — confirmed != risky."""
    f = _finding(title="Permissions-Policy not set",
                 severity=Severity.LOW, confidence=1.0)
    assert classify_finding(f) == "hardening"


def test_dns_email_auth_gaps_are_hardening() -> None:
    f = _finding(title="Missing DMARC record", confidence=1.0,
                 category=FindingCategory.DNS, engine="dns_checker")
    assert classify_finding(f) == "hardening"


def test_info_findings_are_inventory() -> None:
    f = _finding(title="API surface mapped: 4 endpoint reference(s)",
                 severity=Severity.INFO, category=FindingCategory.API)
    assert classify_finding(f) == "inventory"


def test_inventory_tag_wins() -> None:
    f = _finding(severity=Severity.LOW, tags=["inventory"],
                 category=FindingCategory.JAVASCRIPT)
    assert classify_finding(f) == "inventory"


def test_confirmed_secret_is_confirmed_risk() -> None:
    f = _finding(title="AWS access key exposed in JavaScript",
                 severity=Severity.CRITICAL, confidence=0.95,
                 category=FindingCategory.JAVASCRIPT,
                 engine="secret_scanner")
    assert classify_finding(f) == "confirmed_risk"


def test_admin_portal_is_likely_risk() -> None:
    f = _finding(title="Exposed Admin panel detected",
                 severity=Severity.MEDIUM, confidence=0.8,
                 category=FindingCategory.RECON,
                 engine="sensitive_paths")
    assert classify_finding(f) == "likely_risk"


def test_pattern_only_detection_is_heuristic_signal() -> None:
    f = _finding(title="Suspicious random-looking domain",
                 severity=Severity.MEDIUM, confidence=0.5,
                 tags=["heuristic"],
                 category=FindingCategory.COMPROMISE,
                 engine="threat_intel")
    assert classify_finding(f) == "heuristic_signal"


def test_apply_trust_policy_annotates_without_overwriting() -> None:
    f1 = _finding(title="Missing CSP")
    f2 = _finding(metadata={"finding_type": "confirmed_risk",
                            "confidence_label": "confirmed"})
    apply_trust_policy([f1, f2])
    assert f1.metadata["finding_type"] == "hardening"
    assert f1.metadata["confidence_label"] == "high"
    # Pre-existing explicit annotation preserved.
    assert f2.metadata["finding_type"] == "confirmed_risk"


# ---------------------------------------------------------------------------
# Severity calibration (Tasks 4 + 6)
# ---------------------------------------------------------------------------


def test_coop_coep_headers_cap_at_low() -> None:
    f = _finding(title="Missing Cross-Origin-Opener-Policy (COOP)",
                 severity=Severity.HIGH, confidence=1.0)
    assert calibrate_findings([f]) == 1
    assert f.severity == Severity.LOW
    assert f.metadata["calibration"]["original_severity"] == "high"


def test_missing_csp_caps_at_medium_not_high() -> None:
    f = _finding(title="Missing Content-Security-Policy",
                 severity=Severity.HIGH, confidence=1.0)
    calibrate_findings([f])
    assert f.severity == Severity.MEDIUM


def test_obfuscation_without_corroboration_caps_at_medium() -> None:
    f = _finding(title="Heavily obfuscated JavaScript detected",
                 severity=Severity.HIGH, confidence=0.8,
                 category=FindingCategory.JAVASCRIPT,
                 engine="obfuscation_detector")
    calibrate_findings([f])
    assert f.severity == Severity.MEDIUM


def test_corroborated_obfuscation_keeps_severity() -> None:
    f = _finding(title="Heavily obfuscated JavaScript detected",
                 severity=Severity.HIGH, confidence=0.8,
                 category=FindingCategory.JAVASCRIPT,
                 engine="obfuscation_detector",
                 metadata={"corroborated_by": ["csp_engine"]})
    calibrate_findings([f])
    assert f.severity == Severity.HIGH


def test_threat_intel_heuristic_alone_is_not_high() -> None:
    """Task-9 #9."""
    f = _finding(title="Suspicious third-party domain",
                 severity=Severity.HIGH, confidence=0.5,
                 tags=["heuristic"],
                 category=FindingCategory.COMPROMISE,
                 engine="threat_intel")
    calibrate_findings([f])
    assert f.severity == Severity.MEDIUM


def test_threat_intel_with_external_confirmation_stays_high() -> None:
    f = _finding(title="Domain flagged by URLhaus",
                 severity=Severity.HIGH, confidence=0.9,
                 category=FindingCategory.COMPROMISE,
                 engine="threat_intel",
                 metadata={"enrichment": {"provider": "urlhaus"}})
    calibrate_findings([f])
    assert f.severity == Severity.HIGH


def test_heuristic_critical_demoted_to_medium() -> None:
    f = _finding(title="Random-looking domain observed",
                 severity=Severity.CRITICAL, confidence=0.3,
                 category=FindingCategory.COMPROMISE,
                 engine="some_engine")
    calibrate_findings([f])
    assert f.severity == Severity.MEDIUM


def test_medium_confidence_critical_demoted_to_high() -> None:
    f = _finding(title="Possibly exposed backup",
                 severity=Severity.CRITICAL, confidence=0.6,
                 category=FindingCategory.RECON, engine="recon")
    calibrate_findings([f])
    assert f.severity == Severity.HIGH


def test_confirmed_critical_untouched() -> None:
    """Task-9 #10: an exposed secret with direct proof stays CRITICAL."""
    f = _finding(title="Exposed Environment variable file detected",
                 severity=Severity.CRITICAL, confidence=0.95,
                 category=FindingCategory.RECON,
                 engine="sensitive_paths")
    assert calibrate_findings([f]) == 0
    assert f.severity == Severity.CRITICAL
    assert "calibration" not in f.metadata


def test_calibrator_never_escalates() -> None:
    f = _finding(title="Missing COOP", severity=Severity.INFO,
                 confidence=0.2)
    calibrate_findings([f])
    assert f.severity == Severity.INFO


def test_wade_findings_skipped() -> None:
    f = _finding(title="New script detected", severity=Severity.HIGH,
                 confidence=0.5, tags=["heuristic"],
                 category=FindingCategory.COMPROMISE, engine="wade")
    assert calibrate_findings([f]) == 0
    assert f.severity == Severity.HIGH
