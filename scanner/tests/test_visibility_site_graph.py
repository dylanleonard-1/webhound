# WebHound — scanner/tests/test_visibility_site_graph.py
# Phase 10 tests: page tree from the inventory + site-graph section assembly.

from __future__ import annotations

from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.inventory import DiscoveredUrlInventory
from webhound.core.visibility.site_graph import (
    build_page_tree,
    build_site_graph_section,
)


def _inv():
    inv = DiscoveredUrlInventory()
    root = inv.add_raw("https://example.com/", source=UrlSource.SEED)
    a = inv.add_raw("https://example.com/a", source=UrlSource.ANCHOR,
                    parent="https://example.com/")
    b = inv.add_raw("https://example.com/b", source=UrlSource.ANCHOR,
                    parent="https://example.com/")
    inv.add_raw("https://example.com/a/deep", source=UrlSource.ANCHOR,
                parent="https://example.com/a")
    # An out-of-scope URL must not appear in the tree.
    ext = inv.add_raw("https://other.com/x", source=UrlSource.ANCHOR,
                      parent="https://example.com/")
    ext.in_scope = False
    return inv


def test_page_tree_roots_and_edges():
    tree = build_page_tree(_inv())
    assert tree["roots"] == ["https://example.com/"]
    assert tree["node_count"] == 4  # external excluded
    assert "https://example.com/a" in tree["edges"]["https://example.com/"]
    assert "https://example.com/b" in tree["edges"]["https://example.com/"]
    assert tree["edges"]["https://example.com/a"] == ["https://example.com/a/deep"]
    assert tree["edge_count"] == 3


def test_external_excluded_from_tree():
    tree = build_page_tree(_inv())
    flat = set(tree["edges"].keys())
    for kids in tree["edges"].values():
        flat.update(kids)
    assert all("other.com" not in u for u in flat)


def test_site_graph_section_reuses_security_summary():
    sg_summary = {
        "node_count": 42,
        "edge_count": 99,
        "node_types": {"page": 4, "api_endpoint": 6, "form": 2},
        "edge_types": {"loads": 10, "calls": 6},
        "busiest_pages": [{"page": "https://example.com/", "connections": 9}],
    }
    section = build_site_graph_section(_inv(), security_graph_summary=sg_summary)
    assert section["generated"] is True
    assert section["node_count"] == 42
    assert section["node_types"]["api_endpoint"] == 6
    assert section["edge_types"]["loads"] == 10
    assert section["page_tree"]["roots"] == ["https://example.com/"]


def test_site_graph_section_without_security_summary():
    section = build_site_graph_section(_inv(), security_graph_summary=None)
    assert section["generated"] is True
    # Falls back to the page-tree counts.
    assert section["node_count"] == 4
