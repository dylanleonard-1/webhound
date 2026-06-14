"""Phase 8D: WADE Reasoning Engine — core data models.

Advisory only. No production scoring/severity/confidence/finding changes.
All dataclasses are pure Python — no external dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class PriorityLevel(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ReasoningEvidence:
    """A single piece of supporting evidence for a reasoning conclusion."""
    source: str          # e.g. "knowledge_corpus", "neo4j_graph", "graphiti_memory"
    document_id: str     # chunk ID, node ID, or episode ID
    excerpt: str         # relevant text or relationship description
    authority: str       # e.g. "OWASP", "CWE", "internal_doc"
    relevance_score: float = 0.0


@dataclass
class ReasoningChain:
    """Ordered list of reasoning steps leading to a conclusion."""
    steps: list[str] = field(default_factory=list)

    def add(self, step: str) -> None:
        self.steps.append(step)

    def as_text(self) -> str:
        return " → ".join(self.steps)


@dataclass
class ReasoningExplanation:
    """Human-readable explanation of a reasoning conclusion."""
    summary: str
    detail: str
    chain: ReasoningChain = field(default_factory=ReasoningChain)
    caveats: list[str] = field(default_factory=list)


@dataclass
class ReasoningConfidence:
    """Confidence assessment for a reasoning output."""
    level: ConfidenceLevel
    score: float          # 0.0–1.0
    explanation: str
    factors: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReasoningResult:
    """Top-level result from the WADE reasoning engine for a single finding."""
    finding_type: str
    advisory_label: str
    evidence: list[ReasoningEvidence]
    explanation: ReasoningExplanation
    confidence: ReasoningConfidence
    retrieval_chunks_used: int = 0
    graph_nodes_used: int = 0
    memory_episodes_used: int = 0
    production_unchanged: bool = True  # always True — advisory only

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence.level == ConfidenceLevel.HIGH

    def summary_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "advisory_label": self.advisory_label,
            "confidence": self.confidence.level.value,
            "confidence_score": self.confidence.score,
            "explanation": self.explanation.summary,
            "reasoning_chain": self.explanation.chain.as_text(),
            "evidence_count": len(self.evidence),
            "retrieval_chunks": self.retrieval_chunks_used,
            "graph_nodes": self.graph_nodes_used,
            "memory_episodes": self.memory_episodes_used,
            "production_unchanged": self.production_unchanged,
        }


@dataclass
class Finding:
    """Minimal representation of a scan finding for advisory reasoning."""
    finding_type: str
    provider: str | None = None
    url: str | None = None
    detail: str = ""
    raw_severity: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
