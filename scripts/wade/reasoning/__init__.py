"""Phase 8D: WADE Reasoning Engine — package exports.

Advisory only. No production scoring/severity/confidence/finding changes.
"""
from scripts.wade.reasoning.models import (
    ConfidenceLevel,
    Finding,
    PriorityLevel,
    ReasoningChain,
    ReasoningConfidence,
    ReasoningEvidence,
    ReasoningExplanation,
    ReasoningResult,
)
from scripts.wade.reasoning.confidence import (
    ConfidenceFactors,
    build_confidence,
    factors_from_retrieval,
)
from scripts.wade.reasoning.correlation import (
    CorrelationConfidence,
    CorrelationContext,
    CorrelationExplanation,
    correlate_findings,
)
from scripts.wade.reasoning.attack_chain import (
    AttackChainCandidate,
    AttackChainConfidence,
    AttackChainExplanation,
    identify_attack_chains,
)
from scripts.wade.reasoning.root_cause import (
    RootCauseConfidence,
    RootCauseEvidence,
    RootCauseReasoner,
    RootCauseResult,
    RootCauseSummary,
)
from scripts.wade.reasoning.priority import (
    PriorityExplanation,
    PriorityRecommendation,
    PriorityReasoner,
)
from scripts.wade.reasoning.executive import (
    ExecutiveSummary,
    generate_executive_summary,
)
from scripts.wade.reasoning.graph_reasoning import (
    GraphReasoner,
    GraphReasoningResult,
)
from scripts.wade.reasoning.memory_reasoning import (
    MemoryReasoner,
    MemoryReasoningResult,
)
from scripts.wade.reasoning.shadow_mode import (
    ShadowReasoningPackage,
    WADEShadowReasoner,
)

__all__ = [
    # Models
    "ConfidenceLevel", "PriorityLevel", "Finding",
    "ReasoningEvidence", "ReasoningChain", "ReasoningExplanation",
    "ReasoningConfidence", "ReasoningResult",
    # Confidence
    "ConfidenceFactors", "build_confidence", "factors_from_retrieval",
    # Correlation
    "CorrelationContext", "CorrelationExplanation", "CorrelationConfidence",
    "correlate_findings",
    # Attack chains
    "AttackChainCandidate", "AttackChainExplanation", "AttackChainConfidence",
    "identify_attack_chains",
    # Root cause
    "RootCauseReasoner", "RootCauseResult", "RootCauseSummary",
    "RootCauseConfidence", "RootCauseEvidence",
    # Priority
    "PriorityReasoner", "PriorityRecommendation", "PriorityExplanation",
    # Executive
    "ExecutiveSummary", "generate_executive_summary",
    # Graph
    "GraphReasoner", "GraphReasoningResult",
    # Memory
    "MemoryReasoner", "MemoryReasoningResult",
    # Shadow
    "WADEShadowReasoner", "ShadowReasoningPackage",
]
