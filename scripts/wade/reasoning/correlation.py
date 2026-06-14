"""Phase 8D: WADE Multi-Finding Correlation Reasoning.

Identifies compound security patterns from sets of findings.
Advisory only — does NOT modify production finding status or severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import (
    ConfidenceLevel, Finding, ReasoningChain, ReasoningEvidence,
)


@dataclass
class CorrelationExplanation:
    pattern_name: str
    summary: str
    detail: str
    chain: ReasoningChain = field(default_factory=ReasoningChain)
    caveats: list[str] = field(default_factory=list)


@dataclass
class CorrelationConfidence:
    level: ConfidenceLevel
    score: float
    rationale: str


@dataclass
class CorrelationContext:
    """A multi-finding correlation result."""
    pattern_name: str
    matched_findings: list[str]       # finding_type values that triggered
    explanation: CorrelationExplanation
    confidence: CorrelationConfidence
    evidence: list[ReasoningEvidence] = field(default_factory=list)
    advisory_only: bool = True

    def summary_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern_name,
            "matched_findings": self.matched_findings,
            "summary": self.explanation.summary,
            "confidence": self.confidence.level.value,
            "advisory_only": self.advisory_only,
        }


# ---------------------------------------------------------------------------
# Correlation rules — pure functions, no I/O
# ---------------------------------------------------------------------------

def _rule_supply_chain_exposure(types: frozenset[str]) -> CorrelationContext | None:
    required = {"missing_csp", "third_party_script_risk"}
    optional = {"graphql_exposure", "api_exposure"}
    if not required.issubset(types):
        return None
    matched = list(required | (optional & types))
    chain = ReasoningChain()
    chain.add("Missing CSP allows arbitrary script execution")
    chain.add("Third-party scripts load from external domains")
    if "graphql_exposure" in types:
        chain.add("Exposed GraphQL may leak data to injected scripts")
    chain.add("→ possible supply-chain exposure pattern")

    extra = " GraphQL exposure increases data-exfiltration risk." if "graphql_exposure" in types else ""
    return CorrelationContext(
        pattern_name="supply_chain_exposure",
        matched_findings=matched,
        explanation=CorrelationExplanation(
            pattern_name="supply_chain_exposure",
            summary=(
                "Missing CSP combined with third-party script risk indicates "
                "a possible supply-chain exposure."
            ),
            detail=(
                "Without a Content Security Policy, any third-party script loaded "
                "by the page executes with full DOM access. This is the standard "
                "attack surface for supply-chain compromises (e.g. Magecart)." + extra
            ),
            chain=chain,
            caveats=[
                "Severity depends on which third-party domains are loaded and whether "
                "they are well-known, trusted CDNs or unknown vendors."
            ],
        ),
        confidence=CorrelationConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.82,
            rationale="Both required signals present; OWASP A08 well-documented pattern",
        ),
    )


def _rule_session_protection_weakness(types: frozenset[str]) -> CorrelationContext | None:
    required = {"missing_secure_cookie", "missing_httponly_cookie"}
    supporting = {"missing_hsts", "missing_samesite_cookie"}
    if not required.issubset(types):
        return None
    matched = list(required | (supporting & types))
    chain = ReasoningChain()
    chain.add("Cookies lack Secure flag (transmitted over HTTP)")
    chain.add("Cookies lack HttpOnly flag (readable by JavaScript)")
    if "missing_hsts" in types:
        chain.add("No HSTS allows downgrade to HTTP")
    if "missing_samesite_cookie" in types:
        chain.add("No SameSite attribute enables CSRF vectors")
    chain.add("→ session-protection weakness cluster")

    hsts_note = " HSTS absence allows active MITM to intercept cookies." if "missing_hsts" in types else ""
    return CorrelationContext(
        pattern_name="session_protection_weakness",
        matched_findings=matched,
        explanation=CorrelationExplanation(
            pattern_name="session_protection_weakness",
            summary=(
                "Multiple cookie/session protection gaps detected together indicate "
                "a systematic session-protection weakness."
            ),
            detail=(
                "Cookies missing both Secure and HttpOnly flags are vulnerable to "
                "both network interception and JavaScript theft simultaneously." + hsts_note
            ),
            chain=chain,
            caveats=[
                "If the site is served exclusively over HTTPS with no HTTP endpoint, "
                "the Secure-flag risk is partially mitigated."
            ],
        ),
        confidence=CorrelationConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.80,
            rationale="Multi-signal session weakness; each gap independently documented in CWE",
        ),
    )


def _rule_elevated_compromise_risk(types: frozenset[str]) -> CorrelationContext | None:
    admin_signals = {"exposed_env", "exposed_git", "exposed_backup_file"}
    auth_signals = {"wordpress_xmlrpc", "graphql_exposure", "swagger_exposure"}
    ti_signal = "threat_intel_match"
    has_admin = bool(admin_signals & types)
    has_auth = bool(auth_signals & types)
    has_ti = ti_signal in types
    if not (has_admin and has_ti):
        return None
    matched = list((admin_signals | auth_signals | {ti_signal}) & types)
    chain = ReasoningChain()
    if has_admin:
        chain.add(f"Sensitive path exposure ({', '.join(admin_signals & types)})")
    if has_ti:
        chain.add("Threat-intel match on observed IP/domain")
    if has_auth:
        chain.add(f"Exposed API/auth surface ({', '.join(auth_signals & types)})")
    chain.add("→ elevated compromise risk indicator")

    return CorrelationContext(
        pattern_name="elevated_compromise_risk",
        matched_findings=matched,
        explanation=CorrelationExplanation(
            pattern_name="elevated_compromise_risk",
            summary=(
                "Sensitive file exposure plus threat-intel match indicates "
                "elevated compromise risk."
            ),
            detail=(
                "When a site exposes sensitive paths (env/git/backup files) AND "
                "a threat-intel match is observed on the same scan, the combination "
                "suggests the target may already be under active reconnaissance or "
                "early-stage compromise. Each finding individually warrants "
                "investigation; together they warrant escalation."
            ),
            chain=chain,
            caveats=[
                "Threat-intel matches on shared CDN IPs may be false positives. "
                "Confirm TI match is on a customer-controlled IP/domain.",
                "ADVISORY ONLY — do not assert active compromise without further investigation.",
            ],
        ),
        confidence=CorrelationConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.68,
            rationale="Pattern is plausible but TI match may be shared-CDN FP",
        ),
    )


def _rule_tls_downgrade_cluster(types: frozenset[str]) -> CorrelationContext | None:
    if "tls_misconfiguration" not in types:
        return None
    supporting = {"missing_hsts", "mixed_content", "tls_expiry"}
    if not (supporting & types):
        return None
    matched = ["tls_misconfiguration"] + list(supporting & types)
    chain = ReasoningChain()
    chain.add("Weak TLS configuration (deprecated protocol/cipher)")
    if "missing_hsts" in types:
        chain.add("No HSTS allows plain-HTTP downgrade")
    if "mixed_content" in types:
        chain.add("Mixed content loads resources over HTTP")
    if "tls_expiry" in types:
        chain.add("Expired certificate causes client trust errors")
    chain.add("→ TLS/transport security cluster")

    return CorrelationContext(
        pattern_name="tls_downgrade_cluster",
        matched_findings=matched,
        explanation=CorrelationExplanation(
            pattern_name="tls_downgrade_cluster",
            summary=(
                "Multiple TLS/transport security gaps create compounding downgrade risk."
            ),
            detail=(
                "Weak cipher suites or deprecated TLS versions, combined with "
                "absent HSTS or mixed content, create multiple pathways for an "
                "attacker to degrade the transport security of the connection."
            ),
            chain=chain,
        ),
        confidence=CorrelationConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.72,
            rationale="TLS cluster well-documented; severity depends on deployment context",
        ),
    )


_CORRELATION_RULES = (
    _rule_supply_chain_exposure,
    _rule_session_protection_weakness,
    _rule_elevated_compromise_risk,
    _rule_tls_downgrade_cluster,
)


def correlate_findings(findings: list[Finding]) -> list[CorrelationContext]:
    """Run all correlation rules against a set of findings. Advisory only."""
    types = frozenset(f.finding_type for f in findings)
    results: list[CorrelationContext] = []
    for rule in _CORRELATION_RULES:
        try:
            ctx = rule(types)
            if ctx is not None:
                results.append(ctx)
        except Exception:
            continue
    return results
