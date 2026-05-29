# WebHound — scanner/webhound/reporting/evidence_graph.py
# Phase-3 D: structured evidence graph for the JSON export.
#
# Today the JSON report serialises findings + grouped findings + raw
# evidence as parallel flat arrays. That's enough for SIEM ingestion
# but misses the *relationships* between them — which finding cites
# which evidence, which evidence was captured on which page, which
# finding corroborates which other finding (cluster membership), and
# which engine produced each artifact.
#
# This module emits one structured "evidence graph" object: a list
# of typed nodes + a list of typed edges. Designed to be:
#
#   * cheap to construct (O(F + E + P) where F = findings, E =
#     evidence items, P = pages crawled);
#   * cheap to render (the dashboard can lay it out as a network
#     diagram, an explorer tree, or a table — same payload);
#   * additive (the existing top-level findings + grouped_findings
#     keys are untouched; the graph is a new key);
#   * stable (every node has a deterministic id derived from its
#     content + kind, so re-rendering the same scan produces the
#     same graph).

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from webhound.models.finding import Finding
from webhound.models.scan_result import ScanResult


_NODE_KINDS = (
    "scan",         # the scan itself
    "engine",       # one scanner engine that ran
    "page",         # one crawled URL
    "finding",      # one Finding
    "evidence",     # one Evidence artifact
    "host",         # an external host the scan touched
    "chain",        # a correlation chain (engine='correlation')
)

_EDGE_KINDS = (
    "scan_ran_engine",
    "engine_produced_finding",
    "finding_cites_evidence",
    "evidence_observed_on_page",
    "finding_references_host",
    "chain_corroborated_finding",
    "page_belongs_to_scan",
)


@dataclass
class EvidenceNode:
    """One node. ``id`` is content-addressed (sha1(kind:key)) so the
    same scan-result always serialises to the same graph."""

    id: str
    kind: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind,
                 "label": self.label, "attrs": self.attrs}


@dataclass
class EvidenceEdge:
    """One directed edge."""

    src: str
    dst: str
    kind: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst,
                 "kind": self.kind, "attrs": self.attrs}


@dataclass
class EvidenceGraph:
    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _nid(kind: str, key: str) -> str:
    return f"{kind}:{hashlib.sha1(key.encode()).hexdigest()[:16]}"


def build_evidence_graph(result: ScanResult) -> EvidenceGraph:
    """Build the graph from a completed :class:`ScanResult`."""
    g = EvidenceGraph()
    seen_nodes: set[str] = set()

    def _add_node(n: EvidenceNode) -> None:
        if n.id in seen_nodes:
            return
        seen_nodes.add(n.id)
        g.nodes.append(n)

    # --- Scan root node ---
    scan_id = _nid("scan", str(getattr(result, "id", "") or "scan"))
    _add_node(EvidenceNode(
        id=scan_id, kind="scan",
        label=f"Scan {getattr(result, 'id', '')}",
        attrs={"target": getattr(getattr(result, "target", None),
                                  "base_url", None)},
    ))

    # --- Engine nodes from engines_run ---
    for engine in getattr(result, "engines_run", None) or []:
        en_id = _nid("engine", engine)
        _add_node(EvidenceNode(
            id=en_id, kind="engine", label=engine,
        ))
        g.edges.append(EvidenceEdge(
            src=scan_id, dst=en_id, kind="scan_ran_engine",
        ))

    # --- Finding + evidence nodes ---
    findings: Iterable[Finding] = getattr(result, "active_findings",
                                            None) or []
    finding_ids_by_uuid: dict[str, str] = {}
    chain_nodes: dict[str, str] = {}   # chain_name -> node id

    for f in findings:
        f_id_str = str(getattr(f, "id", ""))
        n_id = _nid("finding", f_id_str)
        finding_ids_by_uuid[f_id_str] = n_id
        is_cluster = (getattr(f, "scanner_engine", "") == "correlation")
        kind = "chain" if is_cluster else "finding"
        _add_node(EvidenceNode(
            id=n_id, kind=kind,
            label=f.title,
            attrs={
                "severity": getattr(f.severity, "value", str(f.severity)),
                "confidence": round(getattr(f, "confidence", 0.0) or 0.0, 4),
                "engine": f.scanner_engine,
                "category": getattr(f.category, "value", str(f.category)),
                "tags": list(getattr(f, "tags", None) or []),
                "quality_label": getattr(f, "quality_label", None),
            },
        ))
        # Engine → finding edge.
        en_id = _nid("engine", f.scanner_engine)
        _add_node(EvidenceNode(
            id=en_id, kind="engine", label=f.scanner_engine,
        ))
        g.edges.append(EvidenceEdge(
            src=en_id, dst=n_id, kind="engine_produced_finding",
        ))

        # Cluster-finding bookkeeping for later corroboration edges.
        if is_cluster:
            chain_name = (f.metadata or {}).get("chain_name") or ""
            if chain_name:
                chain_nodes[chain_name] = n_id

        # Evidence + page nodes.
        for ev in getattr(f, "evidence", None) or []:
            ev_key = f"{f_id_str}:{getattr(ev, 'id', '')}"
            ev_id = _nid("evidence", ev_key)
            _add_node(EvidenceNode(
                id=ev_id, kind="evidence",
                label=(getattr(ev, "evidence_type", "raw") or "raw").value
                       if hasattr(getattr(ev, "evidence_type", None), "value")
                       else "evidence",
                attrs={
                    "source_engine": getattr(ev, "source_engine", ""),
                    "location": getattr(ev, "location", ""),
                    "type": (getattr(ev, "evidence_type", None).value
                              if getattr(ev, "evidence_type", None)
                              else "raw"),
                },
            ))
            g.edges.append(EvidenceEdge(
                src=n_id, dst=ev_id, kind="finding_cites_evidence",
            ))
            loc = getattr(ev, "location", "")
            if loc:
                page_id = _nid("page", loc)
                _add_node(EvidenceNode(
                    id=page_id, kind="page", label=loc,
                ))
                g.edges.append(EvidenceEdge(
                    src=ev_id, dst=page_id, kind="evidence_observed_on_page",
                ))
                g.edges.append(EvidenceEdge(
                    src=page_id, dst=scan_id, kind="page_belongs_to_scan",
                ))

    # --- Cluster → constituent edges from correlation metadata ---
    for f in findings:
        if getattr(f, "scanner_engine", "") != "correlation":
            continue
        chain_id = finding_ids_by_uuid.get(str(f.id))
        if not chain_id:
            continue
        for cfid in (f.metadata or {}).get(
            "constituent_finding_ids", []
        ):
            target = finding_ids_by_uuid.get(str(cfid))
            if target is None:
                continue
            g.edges.append(EvidenceEdge(
                src=chain_id, dst=target,
                kind="chain_corroborated_finding",
            ))

    # --- Host nodes from scan-wide inventory (if present) ---
    asset_map = (result.metadata or {}).get("asset_map") or {}
    for host in (asset_map.get("external_hosts") or [])[:200]:
        host_id = _nid("host", host)
        _add_node(EvidenceNode(
            id=host_id, kind="host", label=host,
            attrs={"discovery": "scan_wide_inventory"},
        ))
        g.edges.append(EvidenceEdge(
            src=scan_id, dst=host_id, kind="finding_references_host",
        ))

    return g
