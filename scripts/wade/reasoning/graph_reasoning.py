"""Phase 8D: WADE Graph Reasoning (Neo4j-backed).

Queries the Neo4j brain graph to augment finding analysis with graph context.
Degrades gracefully when Neo4j is unavailable (CI-safe, offline-safe).
Advisory only — no production changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scripts.wade.reasoning.models import ReasoningEvidence

_NEO4J_AVAILABLE = False
_driver_factory = None

try:
    from neo4j import GraphDatabase as _GraphDatabase
    _NEO4J_AVAILABLE = True
    _driver_factory = _GraphDatabase.driver
except ImportError:
    pass


@dataclass
class GraphNode:
    node_id: str
    label: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphRelationship:
    rel_type: str
    from_node: str
    to_node: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphReasoningResult:
    """Advisory result from graph-based reasoning."""
    finding_type: str
    related_nodes: list[GraphNode]
    relationships: list[GraphRelationship]
    evidence: list[ReasoningEvidence]
    graph_available: bool
    advisory_summary: str
    caveats: list[str] = field(default_factory=list)

    def summary_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "graph_available": self.graph_available,
            "nodes_used": len(self.related_nodes),
            "relationships_used": len(self.relationships),
            "advisory_summary": self.advisory_summary,
            "caveats": self.caveats,
        }


_DEGRADED_RESULT_TEMPLATE = GraphReasoningResult(
    finding_type="",
    related_nodes=[],
    relationships=[],
    evidence=[],
    graph_available=False,
    advisory_summary=(
        "Graph reasoning unavailable (Neo4j offline). "
        "Advisory is based on retrieval and rule-based reasoning only."
    ),
    caveats=["Neo4j not reachable — graph context not available"],
)


class GraphReasoner:
    """Graph reasoning over the Neo4j brain. Degrades gracefully if offline."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "webhound-brain-local-dev",
    ) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._available = False
        self._driver = None
        if _NEO4J_AVAILABLE and _driver_factory is not None:
            try:
                drv = _driver_factory(uri, auth=(user, password))
                drv.verify_connectivity()
                self._driver = drv
                self._available = True
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return self._available

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:
                pass

    def _degraded(self, finding_type: str) -> GraphReasoningResult:
        result = GraphReasoningResult(
            finding_type=finding_type,
            related_nodes=[],
            relationships=[],
            evidence=[],
            graph_available=False,
            advisory_summary=_DEGRADED_RESULT_TEMPLATE.advisory_summary,
            caveats=_DEGRADED_RESULT_TEMPLATE.caveats.copy(),
        )
        return result

    def get_cwe_related_findings(self, finding_type: str) -> GraphReasoningResult:
        """Query the knowledge graph for CWE/taxonomy nodes related to a finding."""
        if not self._available or self._driver is None:
            return self._degraded(finding_type)

        nodes: list[GraphNode] = []
        rels: list[GraphRelationship] = []
        evidence: list[ReasoningEvidence] = []

        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (f:FileNode)-[r]->(n)
                    WHERE f.category = $category OR f.source = $category
                    RETURN f, type(r) AS rel_type, n
                    LIMIT 10
                    """,
                    category=finding_type,
                )
                for record in result:
                    fn = record.get("f")
                    rtype = record.get("rel_type", "RELATED")
                    n = record.get("n")
                    if fn:
                        nodes.append(GraphNode(
                            node_id=str(fn.id),
                            label="FileNode",
                            properties=dict(fn),
                        ))
                    if n:
                        nodes.append(GraphNode(
                            node_id=str(n.id),
                            label=list(n.labels)[0] if n.labels else "Node",
                            properties=dict(n),
                        ))
                    if fn and n:
                        rels.append(GraphRelationship(
                            rel_type=rtype,
                            from_node=str(fn.id),
                            to_node=str(n.id),
                        ))

            if nodes:
                evidence.append(ReasoningEvidence(
                    source="neo4j_graph",
                    document_id=f"cwe_query:{finding_type}",
                    excerpt=(
                        f"Found {len(nodes)} graph nodes related to {finding_type}. "
                        f"Relationships: {', '.join(set(r.rel_type for r in rels))}"
                    ),
                    authority="neo4j_brain",
                    relevance_score=0.7,
                ))

            summary = (
                f"Graph query found {len(nodes)} related nodes "
                f"and {len(rels)} relationships for {finding_type}."
                if nodes else
                f"No graph nodes found for {finding_type} — may not be indexed yet."
            )

        except Exception as exc:
            return GraphReasoningResult(
                finding_type=finding_type,
                related_nodes=[],
                relationships=[],
                evidence=[],
                graph_available=True,
                advisory_summary=f"Graph query failed: {exc}",
                caveats=["Graph query error — partial degradation"],
            )

        return GraphReasoningResult(
            finding_type=finding_type,
            related_nodes=nodes,
            relationships=rels,
            evidence=evidence,
            graph_available=True,
            advisory_summary=summary,
        )

    def get_provider_graph_context(self, provider: str) -> GraphReasoningResult:
        """Query graph for provider-related context nodes."""
        if not self._available or self._driver is None:
            return self._degraded(provider)

        nodes: list[GraphNode] = []
        evidence: list[ReasoningEvidence] = []

        try:
            with self._driver.session() as session:
                result = session.run(
                    """
                    MATCH (n:FileNode)
                    WHERE toLower(n.source) CONTAINS toLower($provider)
                       OR toLower(n.category) CONTAINS toLower($provider)
                    RETURN n LIMIT 8
                    """,
                    provider=provider,
                )
                for record in result:
                    n = record.get("n")
                    if n:
                        nodes.append(GraphNode(
                            node_id=str(n.id),
                            label="FileNode",
                            properties=dict(n),
                        ))

            if nodes:
                evidence.append(ReasoningEvidence(
                    source="neo4j_graph",
                    document_id=f"provider_query:{provider}",
                    excerpt=(
                        f"{len(nodes)} provider-context nodes found for {provider}"
                    ),
                    authority="neo4j_brain",
                    relevance_score=0.65,
                ))

        except Exception as exc:
            return self._degraded(provider)

        return GraphReasoningResult(
            finding_type=provider,
            related_nodes=nodes,
            relationships=[],
            evidence=evidence,
            graph_available=True,
            advisory_summary=(
                f"Graph found {len(nodes)} provider-context nodes for {provider}."
                if nodes else
                f"No provider-context nodes found for {provider} in the graph."
            ),
        )
