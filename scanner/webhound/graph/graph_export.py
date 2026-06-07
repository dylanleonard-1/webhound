# WebHound — scanner/webhound/graph/graph_export.py
# Phase-20 Task 11: export a SecurityGraph. Full JSON for tooling /
# future dashboards; a COMPACT summary for the customer report (the raw
# graph is never shipped to customers by default).

from __future__ import annotations

from collections import Counter
from typing import Any

from webhound.graph.graph_query import GraphQuery
from webhound.graph.models import EdgeType, NodeType, SecurityGraph


def export_json(graph: SecurityGraph) -> dict[str, Any]:
    """Full graph as JSON (for tooling / visualization, not the default
    customer report)."""
    return graph.to_dict()


def export_summary(graph: SecurityGraph) -> dict[str, Any]:
    """Compact, customer-safe summary: counts + top connections, no raw
    node dump."""
    node_types = Counter(n.type.value for n in graph.nodes())
    edge_types = Counter(e.type.value for e in graph.edges())
    q = GraphQuery(graph)

    third_parties = q.get_third_party_domains()
    unknown = q.get_unknown_vendors()
    vendors = graph.nodes_of_type(NodeType.VENDOR)

    # Most-connected pages (degree) — the busiest surfaces.
    page_degree = []
    for p in (graph.nodes_of_type(NodeType.PAGE)
              + graph.nodes_of_type(NodeType.RENDERED_PAGE)):
        deg = len(graph.out_edges(p.id))
        page_degree.append((p.value, deg))
    page_degree.sort(key=lambda kv: kv[1], reverse=True)

    return {
        "node_count": graph.node_count,
        "edge_count": graph.edge_count,
        "node_types": dict(node_types),
        "edge_types": dict(edge_types),
        "page_count": node_types.get("page", 0),
        "script_count": node_types.get("script", 0),
        "third_party_domain_count": len(third_parties),
        "unknown_vendor_count": len(unknown),
        "vendor_count": len(vendors),
        "form_count": node_types.get("form", 0),
        "api_endpoint_count": node_types.get("api_endpoint", 0),
        "finding_count": node_types.get("finding", 0),
        "wade_change_count": node_types.get("wade_change", 0),
        "threat_indicator_count": node_types.get("threat_indicator", 0),
        "top_third_parties": [d.value for d in third_parties[:10]],
        "unknown_vendors": [d.value for d in unknown[:10]],
        "busiest_pages": [{"page": v, "connections": d}
                          for v, d in page_degree[:5]],
    }


def export_evidence_graph(graph: SecurityGraph) -> dict[str, Any]:
    """Finding-centric view for the evidence-graph report: each finding
    with the assets it connects to."""
    out = []
    for f in graph.nodes_of_type(NodeType.FINDING):
        connected = []
        for e in graph.in_edges(f.id, EdgeType.RELATED_TO_FINDING):
            src = graph.get_node(e.from_node)
            if src:
                connected.append({"type": src.type.value, "label": src.label})
        out.append({
            "finding": f.label,
            "severity": f.metadata.get("severity"),
            "connected_assets": connected,
        })
    return {"findings": out}
