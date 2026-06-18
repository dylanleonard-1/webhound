"""Phase 8C: Lightweight repo/doc link-graph (Graphify equivalent).

Scans Python imports, Markdown wikilinks, and YAML frontmatter to build a
directed dependency/reference graph. Outputs graph.json, graph.html, and
graph_report.md into docs/ai/graphify/.

Graphify (the commercial binary) is unavailable in this env — this is the
local equivalent built on standard library only.

Run: .venv-api/Scripts/python scripts/ai/build_graphify.py
"""
from __future__ import annotations
import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_DIR = ROOT / "docs" / "ai" / "graphify"
VAULT_DIR = ROOT / "vault" / "WebHound AI Brain"
DOCS_AI = ROOT / "docs" / "ai"
SCRIPTS_AI = ROOT / "scripts" / "ai"
SCRIPTS_WADE = ROOT / "scripts" / "wade"
TESTS_AI = ROOT / "tests" / "ai"
# CONTROL-2B: production code dirs so the graph sees the real product, not just
# the advisory scripts/vault. Imports of webhound.*/apps.* are now graph edges.
SCANNER_DIR = ROOT / "scanner" / "webhound"
API_DIR = ROOT / "apps" / "api"
PROD_IMPORT_PREFIXES = ("scripts.", "tests.", "webhound", "apps.")
_SKIP_DIRS = ("__pycache__", "node_modules", ".next", "migrations/versions")


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(p)


# ── Python import scanner ─────────────────────────────────────────────────────

def _py_imports(path: Path) -> list[str]:
    """Return list of imported module paths (internal only)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    refs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = ""
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    if mod.startswith(PROD_IMPORT_PREFIXES):
                        refs.append(mod.replace(".", "/"))
            elif isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module
                if mod.startswith(PROD_IMPORT_PREFIXES):
                    refs.append(mod.replace(".", "/"))
    return refs


def scan_python_files(dirs: list[Path]) -> list[tuple[str, str, str]]:
    """Return edges: (source_file, target_module, 'import')."""
    edges = []
    for d in dirs:
        for f in sorted(d.rglob("*.py")):
            rels = _rel(f)
            if any(s in rels for s in _SKIP_DIRS):
                continue
            src = rels
            for imp in _py_imports(f):
                edges.append((src, imp + ".py", "import"))
    return edges


# ── Markdown wikilink scanner ─────────────────────────────────────────────────

_WIKILINK_RE = re.compile(r"\[\[([^\]|]+?)(?:\|[^\]]+)?\]\]")
_FRONTMATTER_TAG_RE = re.compile(r"^tags:\s*\[([^\]]+)\]", re.MULTILINE)


def scan_md_files(dirs: list[Path]) -> tuple[list[tuple[str, str, str]], dict[str, list[str]]]:
    """Return (edges, node_tags). edges: (source, target, 'wikilink')."""
    edges = []
    node_tags: dict[str, list[str]] = {}
    for d in dirs:
        for f in sorted(d.rglob("*.md")):
            src = _rel(f)
            text = f.read_text(encoding="utf-8", errors="replace")
            # tags from frontmatter
            m = _FRONTMATTER_TAG_RE.search(text)
            if m:
                node_tags[src] = [t.strip().strip('"\'') for t in m.group(1).split(",")]
            # wikilinks
            for link in _WIKILINK_RE.findall(text):
                target = link.strip()
                if not target.endswith(".md"):
                    target += ".md"
                edges.append((src, target, "wikilink"))
    return edges, node_tags


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_graph(
    py_edges: list[tuple[str, str, str]],
    md_edges: list[tuple[str, str, str]],
    node_tags: dict[str, list[str]],
) -> dict:
    nodes: dict[str, dict] = {}
    edges_out: list[dict] = []

    def ensure(nid: str, kind: str = "file") -> None:
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "label": nid.split("/")[-1],
                "kind": kind,
                "tags": node_tags.get(nid, []),
                "in_degree": 0,
                "out_degree": 0,
            }

    for src, tgt, rel in (py_edges + md_edges):
        kind_s = "python" if src.endswith(".py") else "markdown"
        kind_t = "python" if tgt.endswith(".py") else "markdown"
        ensure(src, kind_s)
        ensure(tgt, kind_t)
        nodes[src]["out_degree"] += 1
        nodes[tgt]["in_degree"] += 1
        edges_out.append({"source": src, "target": tgt, "type": rel})

    return {
        "nodes": list(nodes.values()),
        "edges": edges_out,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges_out),
            "python_files": sum(1 for n in nodes.values() if n["kind"] == "python"),
            "markdown_files": sum(1 for n in nodes.values() if n["kind"] == "markdown"),
        },
    }


# ── HTML visualization ────────────────────────────────────────────────────────

def build_html(graph: dict) -> str:
    nodes_js = json.dumps(graph["nodes"])
    edges_js = json.dumps(graph["edges"])
    stats = graph["stats"]
    return f"""<!DOCTYPE html>
<!-- generated by build_graphify.py -->
<html><head><meta charset="utf-8">
<title>WebHound Brain Graph</title>
<style>
body{{margin:0;background:#1a1a2e;color:#eee;font-family:monospace}}
#info{{position:fixed;top:10px;left:10px;background:rgba(0,0,0,0.7);padding:10px;border-radius:6px;font-size:12px}}
svg{{width:100vw;height:100vh}}
.node circle{{stroke:#fff;stroke-width:1.5}}
.node text{{font-size:8px;fill:#ddd}}
.link{{stroke:#555;stroke-opacity:0.5}}
.import{{stroke:#4ecdc4}}
.wikilink{{stroke:#f7dc6f}}
</style></head>
<body>
<div id="info">
  <b>WebHound Brain Graph</b><br>
  Nodes: {stats['node_count']} &nbsp; Edges: {stats['edge_count']}<br>
  Python: {stats['python_files']} &nbsp; Markdown: {stats['markdown_files']}<br>
  <span style="color:#4ecdc4">■</span> import &nbsp;
  <span style="color:#f7dc6f">■</span> wikilink
</div>
<svg id="graph"></svg>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const graphData = {{nodes:{nodes_js},edges:{edges_js}}};
const svg = d3.select("#graph");
const W = window.innerWidth, H = window.innerHeight;
const color = n => n.kind==="python"?"#4ecdc4":"#f7dc6f";
const sim = d3.forceSimulation(graphData.nodes)
  .force("link", d3.forceLink(graphData.edges).id(d=>d.id).distance(60))
  .force("charge", d3.forceManyBody().strength(-80))
  .force("center", d3.forceCenter(W/2,H/2));
const link = svg.append("g").selectAll("line").data(graphData.edges).join("line")
  .attr("class", d=>"link "+d.type).attr("stroke", d=>d.type==="import"?"#4ecdc4":"#f7dc6f")
  .attr("stroke-opacity",0.4);
const node = svg.append("g").selectAll("g").data(graphData.nodes).join("g")
  .attr("class","node").call(d3.drag()
    .on("start", (e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y}})
    .on("drag",  (e,d)=>{{d.fx=e.x;d.fy=e.y}})
    .on("end",   (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}));
node.append("circle").attr("r", d=>4+Math.min(d.in_degree+d.out_degree,10)*0.8)
  .attr("fill",color).attr("opacity",0.85);
node.append("title").text(d=>d.id+"\\nin:"+d.in_degree+" out:"+d.out_degree);
node.append("text").attr("dx",6).attr("dy",".35em").text(d=>d.label.replace(/[.]md|[.]py/,"").slice(0,20));
sim.on("tick",()=>{{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
}});
</script></body></html>"""


# ── Report builder ────────────────────────────────────────────────────────────

def build_report(graph: dict) -> str:
    nodes = graph["nodes"]
    stats = graph["stats"]
    by_in = sorted(nodes, key=lambda n: n["in_degree"], reverse=True)[:10]
    by_out = sorted(nodes, key=lambda n: n["out_degree"], reverse=True)[:10]
    top_in = "\n".join(
        f"  {n['in_degree']:3d} ← {n['id']}" for n in by_in if n["in_degree"] > 0
    )
    top_out = "\n".join(
        f"  {n['out_degree']:3d} → {n['id']}" for n in by_out if n["out_degree"] > 0
    )
    orphans = [n["id"] for n in nodes if n["in_degree"] == 0 and n["out_degree"] == 0]
    return f"""# WebHound Brain Graph Report

Generated by: scripts/ai/build_graphify.py (local equivalent — Graphify binary not installed)
Method: AST import scanning (Python) + wikilink extraction (Markdown)

## Statistics

| Metric | Count |
|--------|-------|
| Total nodes | {stats['node_count']} |
| Total edges | {stats['edge_count']} |
| Python files | {stats['python_files']} |
| Markdown files | {stats['markdown_files']} |
| Orphan nodes | {len(orphans)} |

## Most Referenced (highest in-degree)

```
{top_in}
```

## Most Referencing (highest out-degree)

```
{top_out}
```

## Orphan Nodes ({len(orphans)})

Files with no incoming or outgoing links:

{chr(10).join('- ' + o for o in orphans[:20])}
{'...' if len(orphans) > 20 else ''}

## Visualization

See graph.html for interactive D3.js force-directed graph.
See graph.json for raw node/edge data.

## Notes

- Graphify (commercial binary): not installed in this environment
- This report uses local AST + wikilink scanning as equivalent
- Import edges: Python `import` statements pointing to internal modules
- Wikilink edges: `[[note]]` references in Markdown vault files
"""


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Scanning Python files (incl. production scanner + API)...")
    py_edges = scan_python_files([SCANNER_DIR, API_DIR, SCRIPTS_AI, SCRIPTS_WADE, TESTS_AI])

    print("Scanning Markdown files...")
    md_dirs = [VAULT_DIR, DOCS_AI]
    md_edges, node_tags = scan_md_files(md_dirs)

    print(f"Building graph: {len(py_edges)} py-edges + {len(md_edges)} md-edges")
    graph = build_graph(py_edges, md_edges, node_tags)

    (OUT_DIR / "graph.json").write_text(
        json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (OUT_DIR / "graph.html").write_text(build_html(graph), encoding="utf-8")
    (OUT_DIR / "graph_report.md").write_text(build_report(graph), encoding="utf-8")

    s = graph["stats"]
    print(
        f"Done. nodes={s['node_count']} edges={s['edge_count']} "
        f"py={s['python_files']} md={s['markdown_files']}"
    )
    print(f"Output: {OUT_DIR.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
