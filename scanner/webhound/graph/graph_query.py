# WebHound — scanner/webhound/graph/graph_query.py
# Phase-20 Task 9: query helpers over a SecurityGraph. Thin, read-only
# traversals the advisor / correlation / reporting layers call.

from __future__ import annotations

from webhound.graph.models import EdgeType, GraphNode, NodeType, SecurityGraph
from webhound.graph.relationship_extractor import hostname, normalize_url, registrable


class GraphQuery:
    def __init__(self, graph: SecurityGraph) -> None:
        self.g = graph

    # --- helpers --------------------------------------------------------

    def _page(self, page_url: str) -> GraphNode | None:
        u = normalize_url(page_url)
        return (self.g.find_node(NodeType.PAGE, u)
                or self.g.find_node(NodeType.RENDERED_PAGE, u))

    # --- Task-9 queries -------------------------------------------------

    def get_page_scripts(self, page_url: str) -> list[GraphNode]:
        page = self._page(page_url)
        return (self.g.neighbors(page.id, EdgeType.LOADS,
                                 target_type=NodeType.SCRIPT)
                if page else [])

    def get_page_forms(self, page_url: str) -> list[GraphNode]:
        page = self._page(page_url)
        return (self.g.neighbors(page.id, EdgeType.CONTAINS,
                                 target_type=NodeType.FORM)
                if page else [])

    def get_page_apis(self, page_url: str) -> list[GraphNode]:
        page = self._page(page_url)
        if not page:
            return []
        out = self.g.neighbors(page.id, EdgeType.CALLS,
                               target_type=NodeType.API_ENDPOINT)
        # Forms that submit to an API also count.
        for form in self.get_page_forms(page_url):
            out += self.g.neighbors(form.id, EdgeType.SUBMITS_TO,
                                    target_type=NodeType.API_ENDPOINT)
        return list({n.id: n for n in out}.values())

    def get_third_party_domains(self) -> list[GraphNode]:
        return self.g.nodes_of_type(NodeType.THIRD_PARTY_DOMAIN)

    def get_unknown_vendors(self) -> list[GraphNode]:
        """Third-party domains with no recognised vendor (Task 4/9)."""
        out = []
        for dom in self.get_third_party_domains():
            has_vendor = self.g.neighbors(dom.id, EdgeType.BELONGS_TO_VENDOR,
                                          target_type=NodeType.VENDOR)
            if not has_vendor or dom.metadata.get("vendor") == "unknown":
                out.append(dom)
        return out

    def get_findings_for_page(self, page_url: str) -> list[GraphNode]:
        page = self._page(page_url)
        return (self.g.neighbors(page.id, EdgeType.RELATED_TO_FINDING,
                                 target_type=NodeType.FINDING)
                if page else [])

    def get_findings_for_domain(self, domain: str) -> list[GraphNode]:
        dom = self.g.find_node(NodeType.THIRD_PARTY_DOMAIN,
                               hostname(domain) or domain)
        return (self.g.neighbors(dom.id, EdgeType.RELATED_TO_FINDING,
                                 target_type=NodeType.FINDING)
                if dom else [])

    def get_wade_changes_for_page(self, page_url: str) -> list[GraphNode]:
        """WADE changes whose affected asset is loaded by / contained in
        the page."""
        page = self._page(page_url)
        if not page:
            return []
        # Assets the page touches.
        asset_ids = {n.id for e in self.g.out_edges(page.id)
                     for n in [self.g.get_node(e.to_node)] if n}
        out = []
        for change in self.g.nodes_of_type(NodeType.WADE_CHANGE):
            for e in self.g.out_edges(change.id, EdgeType.CHANGED_IN_WADE):
                if e.to_node in asset_ids:
                    out.append(change)
                    break
        return out

    def get_paths_from_page_to_domain(
        self, page_url: str, domain: str, *, max_depth: int = 4,
    ) -> list[list[GraphNode]]:
        """All simple paths page → … → domain (e.g. page→script→domain).
        Bounded BFS over out-edges."""
        page = self._page(page_url)
        dom = self.g.find_node(NodeType.THIRD_PARTY_DOMAIN,
                               hostname(domain) or domain)
        if not page or not dom:
            return []
        paths: list[list[GraphNode]] = []
        stack = [(page, [page])]
        while stack:
            node, path = stack.pop()
            if len(path) > max_depth:
                continue
            for e in self.g.out_edges(node.id):
                nxt = self.g.get_node(e.to_node)
                if nxt is None or nxt in path:
                    continue
                if nxt.id == dom.id:
                    paths.append(path + [nxt])
                else:
                    stack.append((nxt, path + [nxt]))
        return paths

    def get_related_security_story(self, finding_id: str):
        """The security-story correlation a finding belongs to, if the
        grouped finding carried correlation metadata (set by Phase-8)."""
        node = self.g.get_node(finding_id) \
            or next((n for n in self.g.nodes_of_type(NodeType.FINDING)
                     if n.label == finding_id), None)
        if node is None:
            return None
        return node.metadata.get("correlation_id") \
            or node.metadata.get("correlation_type")
