"""Phase 8D: WADE Priority Reasoning.

Produces advisory priority recommendations without altering production severity.
Uses 6 factors: Exploitability, Exposure, Business Impact, Provider Context,
Threat Intel, Attack-Chain Relevance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import Finding, PriorityLevel


_CRITICAL_FINDINGS = frozenset({"exposed_env", "exposed_git", "exposed_backup_file"})
_HIGH_EXPLOITABILITY = frozenset({
    "wordpress_xmlrpc", "graphql_exposure", "suspicious_javascript",
    "threat_intel_match", "tls_expiry",
})
_PROVIDER_DEPRIORITIZE = frozenset({
    "cloudflare_challenge_page", "vercel_deployment_protection", "provider_blocked_scan",
})
_MEDIUM_FINDINGS = frozenset({
    "missing_csp", "missing_hsts", "missing_x_frame_options",
    "third_party_script_risk", "tls_misconfiguration",
    "swagger_exposure", "api_exposure", "mixed_content",
})
_LOW_FINDINGS = frozenset({
    "missing_secure_cookie", "missing_httponly_cookie", "missing_samesite_cookie",
    "wordpress_xmlrpc",  # medium on its own, but de-ranked without supporting signals
})


@dataclass
class PriorityExplanation:
    level: PriorityLevel
    factors: dict[str, str]   # factor_name → rationale
    summary: str
    rationale: str

    def as_text(self) -> str:
        lines = [f"Advisory Priority: {self.level.value}", f"Summary: {self.summary}"]
        for factor, why in self.factors.items():
            lines.append(f"  [{factor}] {why}")
        return "\n".join(lines)


@dataclass
class PriorityRecommendation:
    finding_type: str
    advisory_priority: PriorityLevel
    explanation: PriorityExplanation
    has_attack_chain_support: bool = False
    has_threat_intel: bool = False
    provider_context: str = ""
    advisory_only: bool = True

    def summary_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "advisory_priority": self.advisory_priority.value,
            "summary": self.explanation.summary,
            "has_attack_chain": self.has_attack_chain_support,
            "has_threat_intel": self.has_threat_intel,
            "provider_context": self.provider_context,
            "advisory_only": self.advisory_only,
        }


class PriorityReasoner:
    """Assigns advisory priority levels without altering production severity."""

    def prioritize(
        self,
        finding: Finding,
        *,
        attack_chain_names: list[str] | None = None,
        has_threat_intel: bool = False,
        correlation_patterns: list[str] | None = None,
    ) -> PriorityRecommendation:
        ft = finding.finding_type
        factors: dict[str, str] = {}
        score = 0.0

        # Exploitability
        if ft in _CRITICAL_FINDINGS:
            score += 0.60
            factors["exploitability"] = "CRITICAL: directly exploitable without preconditions"
        elif ft in _HIGH_EXPLOITABILITY:
            score += 0.30
            factors["exploitability"] = "HIGH: known exploitation techniques exist"
        elif ft in _MEDIUM_FINDINGS:
            score += 0.20
            factors["exploitability"] = "MEDIUM: requires attacker interaction or chaining"
        else:
            score += 0.10
            factors["exploitability"] = "LOW: limited standalone exploitability"

        # Provider context
        if ft in _PROVIDER_DEPRIORITIZE:
            score -= 0.20
            factors["provider_context"] = (
                "Provider behavior — not a customer vulnerability; "
                "advisory priority reduced"
            )
        elif finding.provider and finding.provider.lower() in ("cloudflare", "vercel"):
            score -= 0.05
            factors["provider_context"] = (
                f"Provider ({finding.provider}) may affect observation reliability"
            )
        else:
            factors["provider_context"] = "No provider masking detected"

        # Threat intel
        if has_threat_intel:
            score += 0.15
            factors["threat_intel"] = "Threat-intel corroboration elevates priority"
            self_has_ti = True
        else:
            self_has_ti = False

        # Attack chain support
        chains = attack_chain_names or []
        if chains:
            score += 0.10
            factors["attack_chain"] = f"Part of attack chain(s): {', '.join(chains)}"
            has_chain = True
        else:
            has_chain = False

        # Correlation
        corr = correlation_patterns or []
        if corr:
            score += 0.05
            factors["correlation"] = f"In correlation pattern(s): {', '.join(corr)}"

        score = max(0.0, min(1.0, score))

        if score >= 0.60:
            level = PriorityLevel.IMMEDIATE
        elif score >= 0.40:
            level = PriorityLevel.HIGH
        elif score >= 0.25:
            level = PriorityLevel.MEDIUM
        else:
            level = PriorityLevel.LOW

        summary_map = {
            PriorityLevel.IMMEDIATE: (
                f"IMMEDIATE advisory priority: {ft} should be investigated/remediated first."
            ),
            PriorityLevel.HIGH: (
                f"HIGH advisory priority: {ft} warrants prompt attention in the next sprint."
            ),
            PriorityLevel.MEDIUM: (
                f"MEDIUM advisory priority: {ft} should be scheduled for remediation."
            ),
            PriorityLevel.LOW: (
                f"LOW advisory priority: {ft} is worth tracking but not urgent."
            ),
        }

        return PriorityRecommendation(
            finding_type=ft,
            advisory_priority=level,
            explanation=PriorityExplanation(
                level=level,
                factors=factors,
                summary=summary_map[level],
                rationale=f"Score {score:.2f} from {len(factors)} factors",
            ),
            has_attack_chain_support=has_chain,
            has_threat_intel=self_has_ti,
            provider_context=factors.get("provider_context", ""),
        )

    def prioritize_set(
        self,
        findings: list[Finding],
        *,
        attack_chain_names: list[str] | None = None,
        correlation_patterns: list[str] | None = None,
    ) -> list[PriorityRecommendation]:
        has_ti = any(f.finding_type == "threat_intel_match" for f in findings)
        results = []
        for finding in findings:
            rec = self.prioritize(
                finding,
                attack_chain_names=attack_chain_names,
                has_threat_intel=has_ti,
                correlation_patterns=correlation_patterns,
            )
            results.append(rec)
        return sorted(
            results,
            key=lambda r: ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"].index(
                r.advisory_priority.value
            ),
        )
