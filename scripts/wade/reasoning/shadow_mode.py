"""Phase 8D: WADE Shadow Mode Reasoner.

Takes production WADE findings and runs the advisory reasoning engine in parallel
WITHOUT modifying any production finding status, severity, or confidence.
Outputs a shadow reasoning package for comparison.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.attack_chain import AttackChainCandidate, identify_attack_chains
from scripts.wade.reasoning.confidence import ConfidenceFactors, build_confidence, factors_from_retrieval
from scripts.wade.reasoning.correlation import CorrelationContext, correlate_findings
from scripts.wade.reasoning.executive import ExecutiveSummary, generate_executive_summary
from scripts.wade.reasoning.models import (
    Finding, PriorityLevel, ReasoningChain, ReasoningEvidence,
    ReasoningExplanation, ReasoningResult,
)
from scripts.wade.reasoning.priority import PriorityRecommendation, PriorityReasoner
from scripts.wade.reasoning.root_cause import RootCauseResult, RootCauseReasoner


@dataclass
class ShadowReasoningPackage:
    """Complete advisory reasoning output for a set of findings.

    Production findings are NEVER modified. This package lives separately.
    """
    scan_id: str
    findings_analyzed: list[str]             # finding_type values only, no PII
    correlations: list[CorrelationContext]
    attack_chains: list[AttackChainCandidate]
    root_causes: list[RootCauseResult]
    priority_recommendations: list[PriorityRecommendation]
    executive_summary: ExecutiveSummary
    retrieval_results: dict[str, list[dict]] = field(default_factory=dict)
    graph_nodes_used: int = 0
    memory_episodes_used: int = 0
    production_unchanged: bool = True        # always True

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "findings_analyzed": self.findings_analyzed,
            "production_unchanged": self.production_unchanged,
            "correlations": [c.summary_dict() for c in self.correlations],
            "attack_chains": [a.summary_dict() for a in self.attack_chains],
            "root_causes": [r.summary_dict() for r in self.root_causes],
            "priorities": [p.summary_dict() for p in self.priority_recommendations],
            "executive_summary": self.executive_summary.summary_dict(),
            "graph_nodes_used": self.graph_nodes_used,
            "memory_episodes_used": self.memory_episodes_used,
        }

    def delta_vs_production(
        self,
        production_severities: dict[str, str],
    ) -> dict[str, Any]:
        """Compare advisory priorities vs production severities. Read-only."""
        advisory_map = {
            p.finding_type: p.advisory_priority.value
            for p in self.priority_recommendations
        }
        deltas = {}
        for ft, prod_sev in production_severities.items():
            advisory = advisory_map.get(ft, "NOT_ANALYZED")
            if advisory != prod_sev:
                deltas[ft] = {
                    "production_severity": prod_sev,
                    "advisory_priority": advisory,
                    "note": "Advisory and production may legitimately differ — advisory is explainable only",
                }
        return {
            "total_findings": len(production_severities),
            "deltas_found": len(deltas),
            "deltas": deltas,
            "production_unchanged": True,
        }


class WADEShadowReasoner:
    """Runs the full advisory reasoning pipeline without touching production."""

    def __init__(self) -> None:
        self._priority_reasoner = PriorityReasoner()
        self._root_cause_reasoner = RootCauseReasoner()

    def analyze(
        self,
        findings: list[Finding],
        *,
        scan_id: str = "shadow",
        retrieval_service: Any | None = None,
    ) -> ShadowReasoningPackage:
        """Run full advisory reasoning. Returns ShadowReasoningPackage. Production unchanged."""
        correlations = correlate_findings(findings)
        attack_chains = identify_attack_chains(findings)
        root_causes = self._root_cause_reasoner.analyse(findings)

        correlation_names = [c.pattern_name for c in correlations]
        chain_names = [a.chain_name for a in attack_chains]

        retrieval_results: dict[str, list[dict]] = {}
        if retrieval_service is not None:
            for f in findings:
                try:
                    chunks = retrieval_service.get_security_guidance(f.finding_type, k=3)
                    retrieval_results[f.finding_type] = chunks
                except Exception:
                    retrieval_results[f.finding_type] = []

        priority_levels: dict[str, PriorityLevel] = {}
        priorities = self._priority_reasoner.prioritize_set(
            findings,
            attack_chain_names=chain_names,
            correlation_patterns=correlation_names,
        )
        for p in priorities:
            priority_levels[p.finding_type] = p.advisory_priority

        executive = generate_executive_summary(
            findings,
            correlation_patterns=correlation_names,
            attack_chain_names=chain_names,
            priority_levels=priority_levels,
        )

        return ShadowReasoningPackage(
            scan_id=scan_id,
            findings_analyzed=[f.finding_type for f in findings],
            correlations=correlations,
            attack_chains=attack_chains,
            root_causes=root_causes,
            priority_recommendations=priorities,
            executive_summary=executive,
            retrieval_results=retrieval_results,
            production_unchanged=True,
        )

    def analyze_single(
        self,
        finding: Finding,
        *,
        retrieval_chunks: list[dict] | None = None,
        graph_nodes: int = 0,
        memory_episodes: int = 0,
    ) -> ReasoningResult:
        """Reason about a single finding. Advisory only."""
        chunks = retrieval_chunks or []
        factors = factors_from_retrieval(
            finding.finding_type,
            chunks,
            provider=finding.provider,
        )
        confidence = build_confidence(
            factors,
            finding_type=finding.finding_type,
            retrieval_chunks=len(chunks),
            graph_nodes=graph_nodes,
            memory_episodes=memory_episodes,
        )

        evidence = [
            ReasoningEvidence(
                source="knowledge_corpus",
                document_id=c.get("chunk_id", f"chunk_{i}"),
                excerpt=c.get("text", "")[:200],
                authority=c.get("authority", "corpus"),
                relevance_score=c.get("score", 0.0),
            )
            for i, c in enumerate(chunks[:5])
        ]

        chain = ReasoningChain()
        chain.add(f"Finding: {finding.finding_type}")
        if chunks:
            chain.add(f"Retrieved {len(chunks)} knowledge-corpus chunks")
        if graph_nodes:
            chain.add(f"Graph context: {graph_nodes} related nodes")
        if memory_episodes:
            chain.add(f"Memory: {memory_episodes} similar episode(s)")
        chain.add(f"Confidence assessment: {confidence.level.value}")

        from scripts.wade.language_resolver import resolve_risk_summary
        try:
            risk_summary = resolve_risk_summary(finding.finding_type)
        except Exception:
            risk_summary = finding.finding_type.replace("_", " ")

        explanation = ReasoningExplanation(
            summary=risk_summary,
            detail=(
                f"Advisory analysis for {finding.finding_type}. "
                f"Based on {len(chunks)} retrieval chunk(s), "
                f"{graph_nodes} graph node(s), and "
                f"{memory_episodes} memory episode(s). "
                "Production severity/confidence unchanged."
            ),
            chain=chain,
        )

        return ReasoningResult(
            finding_type=finding.finding_type,
            advisory_label="ADVISORY",
            evidence=evidence,
            explanation=explanation,
            confidence=confidence,
            retrieval_chunks_used=len(chunks),
            graph_nodes_used=graph_nodes,
            memory_episodes_used=memory_episodes,
            production_unchanged=True,
        )
