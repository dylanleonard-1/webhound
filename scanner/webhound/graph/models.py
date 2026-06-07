# WebHound — scanner/webhound/graph/models.py
# Phase-20 Security Graph: the node/edge vocabulary + the SecurityGraph
# container. An ENRICHMENT layer — it never replaces findings or scan
# output. Deterministic + testable: node ids are derived from
# (type, normalized value) so the same asset always yields the same id,
# and adding a node twice deduplicates.

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class NodeType(str, Enum):
    SITE = "site"
    PAGE = "page"
    RENDERED_PAGE = "rendered_page"
    SCRIPT = "script"
    INLINE_SCRIPT = "inline_script"
    THIRD_PARTY_DOMAIN = "third_party_domain"
    VENDOR = "vendor"
    API_ENDPOINT = "api_endpoint"
    FORM = "form"
    COOKIE = "cookie"
    HEADER = "header"
    IFRAME = "iframe"
    REDIRECT = "redirect"
    TECHNOLOGY = "technology"
    FINDING = "finding"
    WADE_CHANGE = "wade_change"
    THREAT_INDICATOR = "threat_indicator"


class EdgeType(str, Enum):
    CONTAINS = "contains"
    LOADS = "loads"
    CALLS = "calls"
    SUBMITS_TO = "submits_to"
    SETS_COOKIE = "sets_cookie"
    HAS_HEADER = "has_header"
    EMBEDS = "embeds"
    REDIRECTS_TO = "redirects_to"
    BELONGS_TO_VENDOR = "belongs_to_vendor"
    LOADS_FROM = "loads_from"
    OBSERVED_ON = "observed_on"
    EVIDENCED_BY = "evidenced_by"
    RELATED_TO_FINDING = "related_to_finding"
    CHANGED_IN_WADE = "changed_in_wade"
    MATCHES_THREAT_INTEL = "matches_threat_intel"


def make_node_id(node_type: NodeType, normalized_value: str) -> str:
    """Deterministic id from (type, normalized value). The same asset on
    repeated builds — and across scans — gets the same id."""
    h = hashlib.sha256(
        f"{node_type.value}::{normalized_value}".encode("utf-8")
    ).hexdigest()[:16]
    return f"{node_type.value}:{h}"


@dataclass
class GraphNode:
    id: str
    type: NodeType
    label: str
    value: str                              # normalized value (the id basis)
    source: str = "scanner"
    confidence: float = 1.0
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type.value, "label": self.label,
            "value": self.value, "source": self.source,
            "confidence": round(self.confidence, 3),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "metadata": dict(self.metadata),
        }


@dataclass
class GraphEdge:
    from_node: str
    to_node: str
    type: EdgeType
    source: str = "scanner"
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str]:
        return (self.from_node, self.to_node, self.type.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_node, "to": self.to_node,
            "type": self.type.value, "source": self.source,
            "confidence": round(self.confidence, 3),
            "metadata": dict(self.metadata),
        }


class SecurityGraph:
    """A site's security relationship graph. Nodes are keyed by id (so
    duplicates merge); edges are keyed by (from, to, type)."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[tuple[str, str, str], GraphEdge] = {}
        # Adjacency indices for cheap queries.
        self._out: dict[str, list[GraphEdge]] = {}
        self._in: dict[str, list[GraphEdge]] = {}

    # ------------------------------------------------------------------
    # Mutation (dedup-on-add)
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> GraphNode:
        """Add or merge a node. On merge, the existing node keeps its id +
        label but accumulates metadata, widens first/last-seen, and takes
        the max confidence (a more-corroborated sighting wins)."""
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return node
        existing.metadata.update(node.metadata)
        existing.confidence = max(existing.confidence, node.confidence)
        if node.first_seen and (existing.first_seen is None
                                or node.first_seen < existing.first_seen):
            existing.first_seen = node.first_seen
        if node.last_seen and (existing.last_seen is None
                               or node.last_seen > existing.last_seen):
            existing.last_seen = node.last_seen
        return existing

    def node(self, node_type: NodeType, value: str, label: str | None = None,
             **kw: Any) -> GraphNode:
        """Convenience: build + add a node from (type, value)."""
        nid = make_node_id(node_type, value)
        return self.add_node(GraphNode(
            id=nid, type=node_type, label=label or value, value=value, **kw))

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add or merge an edge (dedup by from/to/type). Both endpoints
        must already be nodes — a broken edge is dropped (the validator
        reports if a builder ever produces one)."""
        existing = self._edges.get(edge.key())
        if existing is not None:
            existing.metadata.update(edge.metadata)
            existing.confidence = max(existing.confidence, edge.confidence)
            return existing
        self._edges[edge.key()] = edge
        self._out.setdefault(edge.from_node, []).append(edge)
        self._in.setdefault(edge.to_node, []).append(edge)
        return edge

    def edge(self, frm: GraphNode | str, to: GraphNode | str,
             edge_type: EdgeType, **kw: Any) -> GraphEdge:
        f = frm.id if isinstance(frm, GraphNode) else frm
        t = to.id if isinstance(to, GraphNode) else to
        return self.add_edge(GraphEdge(
            from_node=f, to_node=t, type=edge_type, **kw))

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def edges(self) -> list[GraphEdge]:
        return list(self._edges.values())

    def nodes_of_type(self, node_type: NodeType) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def out_edges(self, node_id: str,
                  edge_type: EdgeType | None = None) -> list[GraphEdge]:
        edges = self._out.get(node_id, [])
        if edge_type is None:
            return list(edges)
        return [e for e in edges if e.type == edge_type]

    def in_edges(self, node_id: str,
                 edge_type: EdgeType | None = None) -> list[GraphEdge]:
        edges = self._in.get(node_id, [])
        if edge_type is None:
            return list(edges)
        return [e for e in edges if e.type == edge_type]

    def neighbors(self, node_id: str, edge_type: EdgeType | None = None,
                  *, target_type: NodeType | None = None) -> list[GraphNode]:
        out: list[GraphNode] = []
        for e in self.out_edges(node_id, edge_type):
            n = self._nodes.get(e.to_node)
            if n is not None and (target_type is None or n.type == target_type):
                out.append(n)
        return out

    def find_node(self, node_type: NodeType, value: str) -> GraphNode | None:
        return self._nodes.get(make_node_id(node_type, value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }
