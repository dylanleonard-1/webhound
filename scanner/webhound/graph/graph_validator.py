# WebHound — scanner/webhound/graph/graph_validator.py
# Phase-20 Task 12: validate a built graph — catch the structural
# problems a builder bug would introduce so they surface in tests/CI
# rather than in a customer's graph.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.graph.models import EdgeType, NodeType, SecurityGraph


@dataclass
class ValidationReport:
    ok: bool = True
    orphan_findings: list[str] = field(default_factory=list)
    orphan_scripts: list[str] = field(default_factory=list)
    broken_edges: list[dict[str, str]] = field(default_factory=list)
    missing_source: list[str] = field(default_factory=list)
    missing_confidence: list[str] = field(default_factory=list)
    duplicate_node_ids: list[str] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return (len(self.orphan_findings) + len(self.orphan_scripts)
                + len(self.broken_edges) + len(self.missing_source)
                + len(self.missing_confidence) + len(self.duplicate_node_ids))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "issue_count": self.issue_count,
            "orphan_findings": list(self.orphan_findings),
            "orphan_scripts": list(self.orphan_scripts),
            "broken_edges": list(self.broken_edges),
            "missing_source": list(self.missing_source),
            "missing_confidence": list(self.missing_confidence),
            "duplicate_node_ids": list(self.duplicate_node_ids),
        }


def validate_graph(graph: SecurityGraph) -> ValidationReport:
    """Structural validation. Findings/scripts with no connection,
    edges pointing at non-existent nodes, and nodes missing source /
    confidence are all flagged."""
    rep = ValidationReport()
    node_ids = {n.id for n in graph.nodes()}

    for n in graph.nodes():
        # Missing metadata.
        if not n.source:
            rep.missing_source.append(n.id)
        if n.confidence is None:
            rep.missing_confidence.append(n.id)
        # Orphan findings: a finding connected to nothing.
        if n.type == NodeType.FINDING and not graph.in_edges(
                n.id, EdgeType.RELATED_TO_FINDING):
            rep.orphan_findings.append(n.label)
        # Orphan scripts: a script no page loads.
        if n.type == NodeType.SCRIPT and not graph.in_edges(
                n.id, EdgeType.LOADS):
            rep.orphan_scripts.append(n.value)

    # Broken edges: endpoint not a node. (add_edge keeps endpoints, but a
    # malformed builder could reference a deleted node — defensive.)
    for e in graph.edges():
        if e.from_node not in node_ids or e.to_node not in node_ids:
            rep.broken_edges.append({"from": e.from_node, "to": e.to_node,
                                     "type": e.type.value})

    # Duplicate node ids can't occur via add_node (dict-keyed), but verify
    # the invariant holds.
    seen: set[str] = set()
    for n in graph.nodes():
        if n.id in seen:
            rep.duplicate_node_ids.append(n.id)
        seen.add(n.id)

    rep.ok = rep.issue_count == 0
    return rep
