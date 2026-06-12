# WebHound — scanner/webhound/core/visibility/site_graph.py
# Phase 10: the site-visibility graph + page tree.
#
# REUSES the existing Security Graph (graph/graph_builder.build_graph + export_
# summary) for the rich node/edge inventory (pages/api/form/script/third_party
# + loads/calls/submits_to/embeds/redirects_to) — the orchestrator already
# builds it and stores the summary in metadata.security_graph_summary. On top of
# that, this module derives the NAVIGATION page tree (which page links to which)
# from the DiscoveredUrl inventory's parent pointers — the structure the
# dashboard's Site Visibility Map renders, which the security graph doesn't
# emphasise.
#
# Safe-mode: pure aggregation. No network.

from __future__ import annotations

from typing import Any

_TREE_NODE_CAP = 2000
_CHILDREN_CAP = 200


def build_page_tree(inventory: Any) -> dict:
    """Build a navigation adjacency map from the DiscoveredUrl inventory.

    Returns ``{"roots": [...], "edges": {parent: [children]}, "node_count": N,
    "edge_count": M}`` where edges are parent→child links_to relationships drawn
    from each DiscoveredUrl.parent. Only in-scope URLs are included."""
    edges: dict[str, list[str]] = {}
    nodes: set[str] = set()
    children: set[str] = set()

    urls = [d for d in inventory.all() if d.in_scope][:_TREE_NODE_CAP]
    present = {d.normalized for d in urls}
    for d in urls:
        nodes.add(d.normalized)
        parent = d.parent
        if parent and parent in present and parent != d.normalized:
            bucket = edges.setdefault(parent, [])
            if len(bucket) < _CHILDREN_CAP and d.normalized not in bucket:
                bucket.append(d.normalized)
                children.add(d.normalized)

    roots = sorted(n for n in nodes if n not in children)
    edge_count = sum(len(v) for v in edges.values())
    return {
        "roots": roots[:_CHILDREN_CAP],
        "root_count": len(roots),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": edge_count,
    }


def build_site_graph_section(
    inventory: Any,
    *,
    security_graph_summary: dict | None = None,
) -> dict:
    """Combine the reused Security Graph summary (node/edge type counts +
    relationships) with the visibility page tree into one site-graph section."""
    page_tree = build_page_tree(inventory)
    sg = security_graph_summary or {}
    return {
        "generated": True,
        # Reused from the existing Security Graph (relationships).
        "node_count": sg.get("node_count", page_tree["node_count"]),
        "edge_count": sg.get("edge_count", page_tree["edge_count"]),
        "node_types": sg.get("node_types", {}),
        "edge_types": sg.get("edge_types", {}),
        "busiest_pages": sg.get("busiest_pages", []),
        # Visibility-derived navigation structure.
        "page_tree": page_tree,
    }
