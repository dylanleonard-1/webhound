"""Phase 8D: WADE Attack Chain Reasoning.

Models plausible attack chains from finding combinations.
Advisory only — does NOT assert actual compromise or modify production findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import (
    ConfidenceLevel, Finding, ReasoningChain,
)


@dataclass
class AttackChainExplanation:
    chain_name: str
    summary: str
    steps: list[str]
    mitigations: list[str] = field(default_factory=list)
    advisory_note: str = (
        "ADVISORY ONLY — this chain describes a plausible attack scenario, "
        "not a confirmed or active attack."
    )


@dataclass
class AttackChainConfidence:
    level: ConfidenceLevel
    score: float
    rationale: str


@dataclass
class AttackChainCandidate:
    """A plausible attack chain identified from scan findings."""
    chain_name: str
    entry_point: str        # first finding_type in chain
    chain_steps: ReasoningChain
    target_impact: str
    matched_findings: list[str]
    explanation: AttackChainExplanation
    confidence: AttackChainConfidence
    advisory_only: bool = True

    def summary_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain_name,
            "entry_point": self.entry_point,
            "steps": self.chain_steps.steps,
            "impact": self.target_impact,
            "matched_findings": self.matched_findings,
            "confidence": self.confidence.level.value,
            "advisory_only": self.advisory_only,
        }


# ---------------------------------------------------------------------------
# Attack chain rules
# ---------------------------------------------------------------------------

def _chain_admin_takeover(types: frozenset[str]) -> AttackChainCandidate | None:
    """exposed-admin + credential-attack surface → account-takeover path."""
    needs = {"exposed_env", "wordpress_xmlrpc"}
    if not (needs & types):
        return None
    entry = "exposed_env" if "exposed_env" in types else "wordpress_xmlrpc"
    matched = list(needs & types)

    chain = ReasoningChain()
    chain.add("Sensitive credential/config exposure")
    if "exposed_env" in types:
        chain.add("Attacker reads .env for DB/API credentials")
    if "wordpress_xmlrpc" in types:
        chain.add("XML-RPC enables brute-force or credential stuffing")
    chain.add("Credential use for account access")
    chain.add("→ Account Takeover")

    return AttackChainCandidate(
        chain_name="admin_credential_takeover",
        entry_point=entry,
        chain_steps=chain,
        target_impact="Account Takeover / Unauthorized Admin Access",
        matched_findings=matched,
        explanation=AttackChainExplanation(
            chain_name="admin_credential_takeover",
            summary=(
                "Exposed credentials or brute-forceable admin endpoints create "
                "a direct path to account takeover."
            ),
            steps=chain.steps,
            mitigations=[
                "Remove exposed .env files immediately and rotate all disclosed credentials",
                "Disable XML-RPC if not required; implement rate-limiting on auth endpoints",
                "Enable multi-factor authentication on all admin accounts",
            ],
        ),
        confidence=AttackChainConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.85,
            rationale="Credential exposure directly enables account takeover — well-documented attack path",
        ),
    )


def _chain_supply_chain_client_compromise(
    types: frozenset[str],
) -> AttackChainCandidate | None:
    """third-party-script + missing-CSP → client-side compromise."""
    if "third_party_script_risk" not in types or "missing_csp" not in types:
        return None

    chain = ReasoningChain()
    chain.add("Third-party script loaded from external domain")
    chain.add("No CSP restricts script sources")
    chain.add("If external domain is compromised, injected script executes")
    chain.add("Script runs with full page/DOM access")
    chain.add("→ Client-side compromise (skimming, credential theft, redirect)")

    return AttackChainCandidate(
        chain_name="supply_chain_client_compromise",
        entry_point="third_party_script_risk",
        chain_steps=chain,
        target_impact="Client-Side Compromise / Data Exfiltration",
        matched_findings=["third_party_script_risk", "missing_csp"],
        explanation=AttackChainExplanation(
            chain_name="supply_chain_client_compromise",
            summary=(
                "Third-party scripts without CSP create a supply-chain compromise "
                "path that has been exploited in Magecart-style attacks."
            ),
            steps=chain.steps,
            mitigations=[
                "Implement Content Security Policy with strict script-src allowlist",
                "Use Subresource Integrity (SRI) for external scripts",
                "Audit and minimize third-party dependencies",
            ],
        ),
        confidence=AttackChainConfidence(
            level=ConfidenceLevel.HIGH,
            score=0.83,
            rationale="Supply-chain attack pattern; OWASP A08; actively exploited in the wild",
        ),
    )


def _chain_weak_headers_xss(types: frozenset[str]) -> AttackChainCandidate | None:
    """Weak headers → increased XSS exploitability."""
    weak_signals = {"missing_csp", "missing_x_frame_options"}
    if not (weak_signals & types):
        return None
    if "suspicious_javascript" not in types and len(weak_signals & types) < 2:
        return None

    matched = list((weak_signals | {"suspicious_javascript"}) & types)
    chain = ReasoningChain()
    chain.add("Missing security headers reduce browser-level protections")
    if "missing_csp" in types:
        chain.add("No CSP: inline scripts and external sources unrestricted")
    if "missing_x_frame_options" in types:
        chain.add("No X-Frame-Options: clickjacking vectors available")
    if "suspicious_javascript" in types:
        chain.add("Suspicious JS changes may indicate existing compromise")
    chain.add("→ Increased XSS / browser-exploitation surface")

    return AttackChainCandidate(
        chain_name="weak_headers_browser_exploitation",
        entry_point="missing_csp",
        chain_steps=chain,
        target_impact="Browser Exploitation / XSS Amplification",
        matched_findings=matched,
        explanation=AttackChainExplanation(
            chain_name="weak_headers_browser_exploitation",
            summary=(
                "Missing browser security headers compound XSS risk and enable "
                "clickjacking; suspicious JS suggests possible in-progress compromise."
            ),
            steps=chain.steps,
            mitigations=[
                "Add Content-Security-Policy header with strict directives",
                "Add X-Frame-Options: DENY or CSP frame-ancestors",
                "Audit all JavaScript changes in version control",
            ],
        ),
        confidence=AttackChainConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.65,
            rationale=(
                "Pattern is valid but impact depends on whether user-controlled "
                "input reaches the page without sanitization"
            ),
        ),
    )


def _chain_recon_to_exfiltration(types: frozenset[str]) -> AttackChainCandidate | None:
    """API exposure + TI match → recon-to-data-exfiltration."""
    if "threat_intel_match" not in types:
        return None
    api_signals = {"graphql_exposure", "swagger_exposure", "api_exposure"}
    if not (api_signals & types):
        return None

    matched = ["threat_intel_match"] + list(api_signals & types)
    chain = ReasoningChain()
    chain.add("Threat-intel match: known-bad actor observing the target")
    chain.add(f"Exposed API surface ({', '.join(api_signals & types)})")
    chain.add("API introspection reveals data endpoints")
    chain.add("→ Data Exfiltration / Unauthorized API Access")

    return AttackChainCandidate(
        chain_name="recon_to_data_exfiltration",
        entry_point="threat_intel_match",
        chain_steps=chain,
        target_impact="Data Exfiltration via Exposed API",
        matched_findings=matched,
        explanation=AttackChainExplanation(
            chain_name="recon_to_data_exfiltration",
            summary=(
                "Threat-intel activity combined with exposed API endpoints suggests "
                "active reconnaissance that could escalate to data exfiltration."
            ),
            steps=chain.steps,
            mitigations=[
                "Disable API introspection in production (especially GraphQL)",
                "Implement authentication on all API endpoints",
                "Review API logs for suspicious query patterns",
            ],
            advisory_note=(
                "ADVISORY ONLY — TI match may be shared CDN IP. "
                "Verify IP/domain is customer-controlled before escalating."
            ),
        ),
        confidence=AttackChainConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.60,
            rationale="TI matches on shared CDNs reduce confidence; API exposure is real signal",
        ),
    )


_CHAIN_RULES = (
    _chain_admin_takeover,
    _chain_supply_chain_client_compromise,
    _chain_weak_headers_xss,
    _chain_recon_to_exfiltration,
)


def identify_attack_chains(findings: list[Finding]) -> list[AttackChainCandidate]:
    """Identify plausible attack chains from a set of findings. Advisory only."""
    types = frozenset(f.finding_type for f in findings)
    chains: list[AttackChainCandidate] = []
    for rule in _CHAIN_RULES:
        try:
            candidate = rule(types)
            if candidate is not None:
                chains.append(candidate)
        except Exception:
            continue
    return chains
