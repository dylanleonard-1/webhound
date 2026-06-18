"""Phase CONTROL-2B: ingest WebHound PRODUCTION CODE into the brain.

READ-ONLY over production code (scanner/webhound/, apps/api/, apps/web/, tests/).
Produces code-aware corpus chunks + a production entity/edge graph, both with
full provenance. Does NOT edit production code, scanner behavior, WADE scoring,
reports, provider-access, billing/auth, or .mcp.json.

Outputs (build artifacts — NOT meant for git commit; regenerable):
  corpus/normalized/code/production_code_chunks.jsonl   (code-aware chunks)
  corpus/indexes/graph/production_entities.json         (entities + edges)

Run: .venv-api/Scripts/python scripts/ai/ingest_production_code.py
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# (label, root dir, ownership category default)
TARGETS = [
    ("scanner", ROOT / "scanner" / "webhound", "scanner"),
    ("api", ROOT / "apps" / "api", "api"),
    ("web", ROOT / "apps" / "web" / "src", "frontend"),
    ("tests", ROOT / "tests", "test"),
    ("scanner_tests", ROOT / "scanner" / "tests", "test"),
    ("api_tests", ROOT / "apps" / "api" / "tests", "test"),
]

CHUNKS_OUT = ROOT / "corpus" / "normalized" / "code" / "production_code_chunks.jsonl"
GRAPH_OUT = ROOT / "corpus" / "indexes" / "graph" / "production_entities.json"

SKIP = ("__pycache__", "node_modules", ".next", ".venv", "venv", "dist", "build",
        ".turbo", "migrations/versions")


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def ownership(path: str, default: str) -> str:
    """Classify a production file into an ownership category."""
    p = path.lower()
    if "/wade/" in p or p.endswith("wade_correlation.py") or "/scripts/wade/" in p:
        return "wade_production" if "scanner/webhound/wade" in p else "wade_advisory"
    if "scanner/webhound/engines/" in p:
        return "scanner_engine"
    if "scanner/webhound/threat_intel" in p or "threat_intel" in p:
        return "threat_intel"
    if "scanner/webhound/providers" in p or "provider_access" in p or "provider" in p:
        return "provider"
    if "scanner/webhound/reporting" in p or "report" in p:
        return "report"
    if "scanner/webhound/core" in p or "orchestrator" in p:
        return "scanner_core"
    if "apps/api/routers" in p:
        return "api_route"
    if "apps/api/services" in p:
        return "api_service"
    if "apps/api/models" in p:
        return "api_model"
    if "apps/web" in p:
        return "frontend"
    if "test" in p:
        return "test"
    return default


def parse_python(path: Path):
    """Return (module_doc, classes[list[(name,doc,methods)]], funcs[list[name]], imports[list])."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError):
        return "", [], [], []
    module_doc = ast.get_docstring(tree) or ""
    classes, funcs, imports = [], [], []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            classes.append((node.name, (ast.get_docstring(node) or "")[:200], methods))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(node.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith(("webhound", "apps.", "scripts.", "tests")):
                imports.append(node.module)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.startswith(("webhound", "apps.", "scripts.")):
                    imports.append(a.name)
    return module_doc, classes, funcs, imports


_TS_EXPORT = re.compile(r"export\s+(?:default\s+)?(?:async\s+)?(?:function|const|class|interface|type)\s+([A-Za-z0-9_]+)")
_TS_IMPORT = re.compile(r"""from\s+['"]([^'"]+)['"]""")


def parse_ts(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    exports = _TS_EXPORT.findall(text)[:40]
    imports = [i for i in _TS_IMPORT.findall(text) if i.startswith((".", "@/"))][:40]
    return "", exports, imports


def iter_files():
    seen: set[str] = set()
    for label, base, default_cat in TARGETS:
        if not base.is_dir():
            continue
        for ext in ("*.py", "*.ts", "*.tsx"):
            for f in sorted(base.rglob(ext)):
                rp = _rel(f)
                if any(s in rp for s in SKIP):
                    continue
                if rp in seen:  # overlapping targets (e.g. apps/api covers apps/api/tests)
                    continue
                seen.add(rp)
                yield f, rp, default_cat


def main() -> None:
    CHUNKS_OUT.parent.mkdir(parents=True, exist_ok=True)
    GRAPH_OUT.parent.mkdir(parents=True, exist_ok=True)

    chunks: list[dict] = []
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    cat_counts: dict[str, int] = {}

    def add_node(nid, kind, cat, label=None, extra=None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "category": cat,
                          "label": label or nid.split("/")[-1], **(extra or {})}

    for f, rp, default_cat in iter_files():
        cat = ownership(rp, default_cat)
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        is_py = rp.endswith(".py")
        if is_py:
            doc, classes, funcs, imports = parse_python(f)
            symbols = [c[0] for c in classes] + funcs
        else:
            doc, symbols, imports = parse_ts(f)
            classes = []

        add_node(rp, "module", cat, extra={"symbols": symbols[:30]})
        for imp in imports:
            tgt = imp.replace(".", "/")
            edges.append({"source": rp, "target": tgt, "type": "import"})
        for cname, cdoc, methods in classes:
            cid = f"{rp}::{cname}"
            add_node(cid, "class", cat, label=cname, extra={"methods": methods[:25]})
            edges.append({"source": rp, "target": cid, "type": "defines"})

        # Code-aware chunk (one per file; preserves full provenance).
        symtext = ", ".join(symbols[:30])
        text = (f"PRODUCTION CODE MODULE: {rp}\n"
                f"category: {cat}\n"
                f"purpose: {doc[:400] if doc else '(no module docstring)'}\n"
                f"symbols: {symtext}\n"
                f"imports: {', '.join(imports[:20])}")
        doc_id = "code-" + re.sub(r"[^a-z0-9]+", "-", rp.lower()).strip("-")
        chunks.append({
            "chunk_id": doc_id + "--c000",
            "doc_id": doc_id,
            "chunk_index": 0,
            "total_chunks": 1,
            "text": text,
            "file_path": rp,
            "module": rp,
            "source_type": "production_code",
            "authority_tier": "A",
            "source_url": rp,
            "title": rp.split("/")[-1],
            "verification_status": "verified",
            "topic_tags": [cat],
            "phase": "CONTROL-2B",
        })

    with open(CHUNKS_OUT, "w", encoding="utf-8") as fh:
        for c in chunks:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    graph = {"nodes": list(nodes.values()), "edges": edges,
             "stats": {"nodes": len(nodes), "edges": len(edges),
                       "modules": sum(1 for n in nodes.values() if n["kind"] == "module"),
                       "classes": sum(1 for n in nodes.values() if n["kind"] == "class"),
                       "by_category": cat_counts}}
    with open(GRAPH_OUT, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, indent=2, ensure_ascii=False)

    print(f"code chunks: {len(chunks)}")
    print(f"graph nodes: {len(nodes)} (modules={graph['stats']['modules']}, classes={graph['stats']['classes']})")
    print(f"graph edges: {len(edges)}")
    print(f"by_category: {json.dumps(cat_counts, indent=0)}")
    print(f"chunks -> {_rel(CHUNKS_OUT)}")
    print(f"graph  -> {_rel(GRAPH_OUT)}")


if __name__ == "__main__":
    main()
