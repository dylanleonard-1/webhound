# WebHound — scanner/webhound/graph/graph_scoring.py
# Phase-20 Task 10: graph CONTEXT for risk scoring + correlation. Answers
# "is this thing connected to a sensitive surface?" — it does NOT change
# risk scoring itself, it exposes context the scorer/correlation layers
# can consult.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from webhound.graph.graph_query import GraphQuery
from webhound.graph.models import EdgeType, GraphNode, NodeType, SecurityGraph

_SENSITIVE_RE = re.compile(
    r"/(checkout|payment|pay|billing|login|signin|sign-in|account|admin|"
    r"auth|password|profile|settings|order)", re.IGNORECASE)
_CHECKOUT_RE = re.compile(r"/(checkout|payment|pay|billing|cart)", re.IGNORECASE)
_LOGIN_RE = re.compile(r"/(login|signin|sign-in|auth|account|password)", re.IGNORECASE)


def is_sensitive_page_value(value: str) -> bool:
    return bool(_SENSITIVE_RE.search(value or ""))


@dataclass
class GraphContext:
    """Graph-derived context flags for one query subject."""

    on_sensitive_page: bool = False
    connected_to_login: bool = False
    connected_to_checkout: bool = False
    connected_to_form: bool = False
    sensitive_pages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "on_sensitive_page": self.on_sensitive_page,
            "connected_to_login": self.connected_to_login,
            "connected_to_checkout": self.connected_to_checkout,
            "connected_to_form": self.connected_to_form,
            "sensitive_pages": list(self.sensitive_pages),
        }


class GraphScoring:
    def __init__(self, graph: SecurityGraph) -> None:
        self.g = graph
        self.q = GraphQuery(graph)

    def _pages_referencing(self, node: GraphNode) -> list[GraphNode]:
        """Pages that load/contain/embed/call this node (walk in-edges)."""
        pages: list[GraphNode] = []
        for e in self.g.in_edges(node.id):
            src = self.g.get_node(e.from_node)
            if src and src.type in (NodeType.PAGE, NodeType.RENDERED_PAGE):
                pages.append(src)
        return pages

    def context_for_node(self, node: GraphNode) -> GraphContext:
        ctx = GraphContext()
        pages = self._pages_referencing(node)
        for p in pages:
            if is_sensitive_page_value(p.value):
                ctx.on_sensitive_page = True
                ctx.sensitive_pages.append(p.value)
            if _LOGIN_RE.search(p.value):
                ctx.connected_to_login = True
            if _CHECKOUT_RE.search(p.value):
                ctx.connected_to_checkout = True
        # Connected to a form? (a script/domain on a page that also has a form)
        for p in pages:
            if self.q.get_page_forms(p.value):
                ctx.connected_to_form = True
                break
        return ctx

    # --- Task-10 question helpers --------------------------------------

    def is_finding_on_sensitive_page(self, finding_label: str) -> bool:
        node = next((n for n in self.g.nodes_of_type(NodeType.FINDING)
                     if n.label == finding_label), None)
        if node is None:
            return False
        for e in self.g.in_edges(node.id, EdgeType.RELATED_TO_FINDING):
            src = self.g.get_node(e.from_node)
            if src and is_sensitive_page_value(src.value):
                return True
        return False

    def is_script_connected_to_login(self, script_value: str) -> bool:
        node = self.g.find_node(NodeType.SCRIPT, script_value)
        return bool(node) and self.context_for_node(node).connected_to_login

    def is_domain_connected_to_checkout(self, domain: str) -> bool:
        from webhound.graph.relationship_extractor import hostname
        dom = self.g.find_node(NodeType.THIRD_PARTY_DOMAIN,
                               hostname(domain) or domain)
        if dom is None:
            return False
        # Walk: domain ← (loads_from) script ← (loads) page.
        for e in self.g.in_edges(dom.id, EdgeType.LOADS_FROM):
            asset = self.g.get_node(e.from_node)
            if asset and self.context_for_node(asset).connected_to_checkout:
                return True
        return False

    def is_third_party_connected_to_form(self, domain: str) -> bool:
        from webhound.graph.relationship_extractor import hostname
        dom = self.g.find_node(NodeType.THIRD_PARTY_DOMAIN,
                               hostname(domain) or domain)
        if dom is None:
            return False
        for e in self.g.in_edges(dom.id, EdgeType.LOADS_FROM):
            asset = self.g.get_node(e.from_node)
            if asset and self.context_for_node(asset).connected_to_form:
                return True
        return False

    def is_wade_change_connected_to_finding(self, change_key: str) -> bool:
        """Did a WADE change land on an asset that also has a risk finding?"""
        change = self.g.find_node(NodeType.WADE_CHANGE, change_key)
        if change is None:
            return False
        for e in self.g.out_edges(change.id, EdgeType.CHANGED_IN_WADE):
            asset = self.g.get_node(e.to_node)
            if asset is None:
                continue
            # The asset (or a page referencing it) has a finding.
            if self.g.out_edges(asset.id, EdgeType.RELATED_TO_FINDING):
                return True
            for e2 in self.g.in_edges(asset.id):
                src = self.g.get_node(e2.from_node)
                if src and self.g.out_edges(src.id, EdgeType.RELATED_TO_FINDING):
                    return True
        return False
