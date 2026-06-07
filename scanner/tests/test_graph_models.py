# WebHound — tests/test_graph_models.py
# Phase-20 Task 1/13: graph node/edge model + dedup + indices.

from __future__ import annotations

from webhound.graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SecurityGraph,
    make_node_id,
)


def test_node_id_deterministic() -> None:
    a = make_node_id(NodeType.SCRIPT, "https://cdn.x/a.js")
    b = make_node_id(NodeType.SCRIPT, "https://cdn.x/a.js")
    assert a == b
    assert a != make_node_id(NodeType.PAGE, "https://cdn.x/a.js")  # type matters


def test_duplicate_nodes_merge() -> None:
    g = SecurityGraph()
    g.node(NodeType.SCRIPT, "https://cdn.x/a.js", confidence=0.5,
           metadata={"seen": 1})
    g.node(NodeType.SCRIPT, "https://cdn.x/a.js", confidence=0.9,
           first_seen="2026-06-01", metadata={"vendor": "x"})
    assert g.node_count == 1                     # deduped
    n = g.find_node(NodeType.SCRIPT, "https://cdn.x/a.js")
    assert n.confidence == 0.9                   # max wins
    assert n.metadata == {"seen": 1, "vendor": "x"}  # merged
    assert n.first_seen == "2026-06-01"


def test_duplicate_edges_merge() -> None:
    g = SecurityGraph()
    p = g.node(NodeType.PAGE, "https://t.test/")
    s = g.node(NodeType.SCRIPT, "https://cdn.x/a.js")
    g.edge(p, s, EdgeType.LOADS, confidence=0.5)
    g.edge(p, s, EdgeType.LOADS, confidence=0.9, metadata={"k": 1})
    assert g.edge_count == 1
    assert g.edges()[0].confidence == 0.9


def test_adjacency_queries() -> None:
    g = SecurityGraph()
    p = g.node(NodeType.PAGE, "https://t.test/checkout")
    s1 = g.node(NodeType.SCRIPT, "https://js.stripe.com/v3")
    s2 = g.node(NodeType.SCRIPT, "https://cdn.x/a.js")
    form = g.node(NodeType.FORM, "form:checkout")
    g.edge(p, s1, EdgeType.LOADS)
    g.edge(p, s2, EdgeType.LOADS)
    g.edge(p, form, EdgeType.CONTAINS)

    scripts = g.neighbors(p.id, EdgeType.LOADS, target_type=NodeType.SCRIPT)
    assert {n.value for n in scripts} == {"https://js.stripe.com/v3",
                                          "https://cdn.x/a.js"}
    forms = g.neighbors(p.id, EdgeType.CONTAINS, target_type=NodeType.FORM)
    assert len(forms) == 1
    # in-edges: the script's page.
    assert g.in_edges(s1.id, EdgeType.LOADS)[0].from_node == p.id


def test_nodes_of_type_and_to_dict() -> None:
    g = SecurityGraph()
    g.node(NodeType.THIRD_PARTY_DOMAIN, "cdn.x")
    g.node(NodeType.THIRD_PARTY_DOMAIN, "vendor.y")
    g.node(NodeType.PAGE, "https://t.test/")
    assert len(g.nodes_of_type(NodeType.THIRD_PARTY_DOMAIN)) == 2
    d = g.to_dict()
    assert d["node_count"] == 3
    assert all("type" in n for n in d["nodes"])
