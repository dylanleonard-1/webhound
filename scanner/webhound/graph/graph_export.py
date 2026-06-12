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

    # Headline API count = API_ENDPOINT nodes whose canonical class is in the
    # headline set (first-party / graphql / auth). When the canonical inventory
    # tagged the nodes, count those; otherwise fall back to the raw node count
    # (legacy graphs built without an inventory). This is the SINGLE number the
    # UI ("APIs") + every other surface report.
    _HEADLINE = {"first_party_api", "graphql", "auth_api"}
    api_nodes = graph.nodes_of_type(NodeType.API_ENDPOINT)
    tagged = [n for n in api_nodes if (n.metadata or {}).get("endpoint_class")]
    if tagged:
        headline_api_count = sum(
            1 for n in tagged
            if (n.metadata or {}).get("endpoint_class") in _HEADLINE)
    else:
        headline_api_count = node_types.get("api_endpoint", 0)

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
        # Headline (deduped, canonical) API count — the SAME number shown by the
        # UI, coverage_summary, and the visibility map. api_node_count is the
        # raw graph total (incl. third-party) for graph accounting only.
        "api_endpoint_count": headline_api_count,
        "api_node_count": node_types.get("api_endpoint", 0),
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
