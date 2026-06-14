"""Phase 8D: WADE Confidence Reasoning.

Tracks 8 confidence factors and produces an explainable confidence assessment.
Advisory only — does NOT modify production scoring.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import ConfidenceLevel, ReasoningConfidence


PROVIDER_FP_SIGNALS = frozenset({
    "cloudflare_challenge_page",
    "vercel_deployment_protection",
    "provider_blocked_scan",
})


@dataclass
class ConfidenceFactors:
    """8 confidence factors that feed the overall confidence assessment."""
    source_authority: float = 0.0        # 0–1: OWASP/CWE > internal > none
    evidence_quality: float = 0.0        # 0–1: direct observation vs inference
    provider_effects: float = 1.0        # 0–1: 1=clean, <0.5=likely provider FP
    finding_consistency: float = 0.0     # 0–1: consistent across scans
    historical_similarity: float = 0.0   # 0–1: matches prior similar findings
    threat_intel_corroboration: float = 0.0  # 0–1: TI confirms finding
    attack_chain_support: float = 0.0    # 0–1: finding fits a known chain
    false_positive_signals: float = 1.0  # 0–1: 1=no FP signals, 0=strong FP

    def weighted_score(self) -> float:
        weights = {
            "source_authority": 0.15,
            "evidence_quality": 0.20,
            "provider_effects": 0.20,
            "finding_consistency": 0.10,
            "historical_similarity": 0.05,
            "threat_intel_corroboration": 0.10,
            "attack_chain_support": 0.05,
            "false_positive_signals": 0.15,
        }
        score = (
            self.source_authority * weights["source_authority"]
            + self.evidence_quality * weights["evidence_quality"]
            + self.provider_effects * weights["provider_effects"]
            + self.finding_consistency * weights["finding_consistency"]
            + self.historical_similarity * weights["historical_similarity"]
            + self.threat_intel_corroboration * weights["threat_intel_corroboration"]
            + self.attack_chain_support * weights["attack_chain_support"]
            + self.false_positive_signals * weights["false_positive_signals"]
        )
        return round(min(1.0, max(0.0, score)), 3)

    def to_dict(self) -> dict[str, float]:
        return {
            "source_authority": self.source_authority,
            "evidence_quality": self.evidence_quality,
            "provider_effects": self.provider_effects,
            "finding_consistency": self.finding_consistency,
            "historical_similarity": self.historical_similarity,
            "threat_intel_corroboration": self.threat_intel_corroboration,
            "attack_chain_support": self.attack_chain_support,
            "false_positive_signals": self.false_positive_signals,
        }


def build_confidence(
    factors: ConfidenceFactors,
    finding_type: str = "",
    retrieval_chunks: int = 0,
    graph_nodes: int = 0,
    memory_episodes: int = 0,
) -> ReasoningConfidence:
    """Build an explainable ReasoningConfidence from ConfidenceFactors."""
    score = factors.weighted_score()

    # Adjust for retrieval evidence
    if retrieval_chunks >= 3:
        score = min(1.0, score + 0.05)
    if graph_nodes >= 2:
        score = min(1.0, score + 0.03)
    if memory_episodes >= 1:
        score = min(1.0, score + 0.02)

    if score >= 0.72:
        level = ConfidenceLevel.HIGH
    elif score >= 0.50:
        level = ConfidenceLevel.MEDIUM
    elif score >= 0.30:
        level = ConfidenceLevel.LOW
    else:
        level = ConfidenceLevel.INSUFFICIENT

    explanation_parts: list[str] = []

    if factors.provider_effects < 0.5:
        explanation_parts.append(
            "LOW because provider WAF/deployment-protection likely affecting observation"
        )
    elif factors.false_positive_signals < 0.5:
        explanation_parts.append("LOW because strong false-positive signals present")
    elif level == ConfidenceLevel.HIGH:
        reasons = []
        if factors.source_authority >= 0.7:
            reasons.append("authoritative source (OWASP/CWE)")
        if factors.evidence_quality >= 0.7:
            reasons.append("directly observed")
        if factors.finding_consistency >= 0.7:
            reasons.append("consistent across scans")
        if factors.threat_intel_corroboration >= 0.7:
            reasons.append("threat-intel corroborated")
        if retrieval_chunks >= 3:
            reasons.append(f"{retrieval_chunks} knowledge-corpus chunks supporting")
        explanation_parts.append("HIGH: " + "; ".join(reasons) if reasons else "HIGH")
    elif level == ConfidenceLevel.MEDIUM:
        explanation_parts.append(
            "MEDIUM: some evidence present but not all signals corroborating"
        )
    else:
        explanation_parts.append(
            "LOW/INSUFFICIENT: limited evidence; treat advisory as tentative"
        )

    if finding_type in PROVIDER_FP_SIGNALS:
        explanation_parts.append(
            f"Note: {finding_type} is a known provider-behavior pattern — "
            "low intrinsic risk, high scanner-coverage-impact"
        )

    return ReasoningConfidence(
        level=level,
        score=round(score, 3),
        explanation="; ".join(explanation_parts),
        factors=factors.to_dict(),
    )


def factors_from_retrieval(
    finding_type: str,
    retrieval_chunks: list[dict],
    provider: str | None = None,
) -> ConfidenceFactors:
    """Build ConfidenceFactors from retrieval results alone (no graph/memory)."""
    f = ConfidenceFactors()

    has_authoritative = any(
        c.get("authority", "") in ("OWASP", "CWE", "nist")
        for c in retrieval_chunks
    )
    f.source_authority = 0.8 if has_authoritative else (0.4 if retrieval_chunks else 0.1)
    f.evidence_quality = min(1.0, len(retrieval_chunks) * 0.15)

    is_provider_type = finding_type in PROVIDER_FP_SIGNALS
    if is_provider_type:
        f.provider_effects = 0.3
        f.false_positive_signals = 0.4
    elif provider and provider.lower() in ("cloudflare", "vercel"):
        f.provider_effects = 0.7
    else:
        f.provider_effects = 0.9

    return f
