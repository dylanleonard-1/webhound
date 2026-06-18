"""Phase CONTROL-2C: build the CANONICAL, code-aware WebHound brain index.

Deterministic + regenerable from a fresh clone. NO network, NO Ollama, NO Neo4j,
NO Graphiti. Produces small committed manifests + (optionally) regenerated
retrieval chunks. Reads production code READ-ONLY; never edits it.

Committed (small, deterministic):
  corpus/index/brain_sources_manifest.json   — every brain source (include/exclude)
  corpus/index/code_chunks_manifest.jsonl    — one line per code chunk (metadata only)
  corpus/index/retrieval_config.json         — canonical retrieval config

Regenerated (NOT committed — build artifacts):
  corpus/index/canonical_chunks.jsonl        — code+doc chunks WITH text (for retrieval)

Usage:
  python scripts/ai/build_canonical_brain_index.py            # write manifests + chunks
  python scripts/ai/build_canonical_brain_index.py --dry-run  # summary only, write nothing
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
INDEX_DIR = ROOT / "corpus" / "index"
SOURCES_MANIFEST = INDEX_DIR / "brain_sources_manifest.json"
CODE_CHUNKS_MANIFEST = INDEX_DIR / "code_chunks_manifest.jsonl"
RETRIEVAL_CONFIG = INDEX_DIR / "retrieval_config.json"
CANONICAL_CHUNKS = INDEX_DIR / "canonical_chunks.jsonl"  # regenerated, not committed
DOC_CHUNKS = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"  # existing doc corpus

# (label, dir, language, default category)
CODE_ROOTS = [
    ("scanner", ROOT / "scanner" / "webhound", "python", "scanner"),
    ("scanner_tests", ROOT / "scanner" / "tests", "python", "test"),
    ("api", ROOT / "apps" / "api", "python", "api"),
    ("web", ROOT / "apps" / "web" / "src", "typescript", "frontend"),
    ("tests", ROOT / "tests", "python", "test"),
]
CODE_EXTS = {".py": "python", ".ts": "typescript", ".tsx": "typescript"}

# Hard exclusions — never index these (build artifacts, deps, secrets, local state).
EXCLUDE_SUBSTR = (
    "node_modules/", ".next/", "/dist/", "/build/", ".venv", "/venv/", "__pycache__/",
    ".turbo/", "migrations/versions/", "/.git/", "lightrag_storage/",
    "corpus/indexes/", "corpus/index/", ".pytest_cache/", "/coverage/",
)
EXCLUDE_NAMES = (
    ".env", ".env.local", ".env.example", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "uv.lock", "poetry.lock", "ruvector.db",
)
SECRET_HINT = re.compile(r"(^|[/.])(secret|credential|\.pem|\.key)($|[/.])", re.I)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def excluded(path: str, name: str) -> str | None:
    if any(s in path for s in EXCLUDE_SUBSTR):
        return "build/dep/cache/local-state path"
    if name in EXCLUDE_NAMES:
        return "lock/env/local file"
    if SECRET_HINT.search(path):
        return "potential secret/credential"
    return None


def category(path: str, default: str) -> str:
    p = path.lower()
    if "scanner/webhound/wade/" in p:
        return "wade_production"
    if "/scripts/wade/" in p:
        return "wade_advisory"
    if "scanner/webhound/engines/" in p:
        return "scanner_engine"
    if "scanner/webhound/threat_intel" in p:
        return "threat_intel"
    if "scanner/webhound/providers" in p:
        return "provider"
    if "scanner/webhound/reporting" in p:
        return "report"
    if "scanner/webhound/core" in p:
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


_TS_SYM = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?(function|const|class|interface|type)\s+([A-Za-z0-9_]+)",
    re.M)


def chunk_python(text: str, rp: str, cat: str):
    """Yield (symbol_name, symbol_type, start_line, end_line, chunk_text)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        yield (None, "module", 1, text.count("\n") + 1, text[:1500])
        return
    lines = text.splitlines()
    mod_doc = ast.get_docstring(tree) or ""
    yield ("<module>", "module", 1, min(len(lines), 1),
           f"MODULE {rp} [{cat}]\n{mod_doc[:400]}")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stype = "class" if isinstance(node, ast.ClassDef) else "function"
            start = node.lineno
            end = getattr(node, "end_lineno", start) or start
            body = "\n".join(lines[start - 1:min(end, start + 40)])
            doc = ast.get_docstring(node) or ""
            yield (node.name, stype, start, end,
                   f"{stype.upper()} {node.name} in {rp} [{cat}]\n{doc[:200]}\n{body[:1200]}")


def chunk_ts(text: str, rp: str, cat: str):
    lines = text.splitlines()
    yield ("<module>", "module", 1, 1, f"MODULE {rp} [{cat}]\n" + "\n".join(lines[:8]))
    for m in _TS_SYM.finditer(text):
        stype, name = m.group(1), m.group(2)
        start = text[:m.start()].count("\n") + 1
        body = "\n".join(lines[start - 1:start + 30])
        yield (name, stype, start, start + 30, f"{stype.upper()} {name} in {rp} [{cat}]\n{body[:1000]}")


def iter_sources():
    seen = set()
    for label, base, lang, default_cat in CODE_ROOTS:
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or f.suffix not in CODE_EXTS:
                continue
            rp = rel(f)
            if rp in seen:
                continue
            seen.add(rp)
            yield f, rp, CODE_EXTS[f.suffix]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--embed", action="store_true",
                    help="also build local dense embeddings (needs sentence-transformers; "
                         "model cached after first download). Build artifact — not committed.")
    args = ap.parse_args()

    sources, chunk_meta, canonical_rows = [], [], []
    skipped, warnings = 0, []
    cat_counts: dict[str, int] = {}

    for f, rp, lang in iter_sources():
        name = f.name
        reason = excluded(rp, name)
        if reason:
            sources.append({"source_id": sha(rp.encode()), "path": rp,
                            "source_type": "code", "language": lang,
                            "status": "exclude", "reason": reason, "category": "excluded"})
            skipped += 1
            continue
        try:
            raw = f.read_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError as e:
            warnings.append(f"read-fail {rp}: {e}")
            skipped += 1
            continue
        cat = category(rp, "code")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        src_hash = sha(raw)
        sources.append({"source_id": sha(rp.encode()), "path": rp,
                        "source_type": "code", "language": lang,
                        "status": "include", "reason": "production/test source",
                        "hash": src_hash, "category": cat})
        chunker = chunk_python if lang == "python" else chunk_ts
        for i, (sym, stype, s_line, e_line, ctext) in enumerate(chunker(text, rp, cat)):
            cid = f"{cat}:{rp}:{sym or i}:{s_line}"
            cid = re.sub(r"[^A-Za-z0-9:._/-]", "_", cid)
            ch = sha(ctext.encode())
            chunk_meta.append({
                "chunk_id": cid, "source_path": rp, "source_hash": src_hash,
                "symbol_name": sym, "symbol_type": stype, "language": lang,
                "start_line": s_line, "end_line": e_line,
                "token_estimate": max(1, len(ctext) // 4), "content_hash": ch,
                "category": cat,
            })
            canonical_rows.append({
                "chunk_id": cid, "doc_id": "code-" + sha(rp.encode()),
                "text": ctext, "file_path": rp, "module": rp,
                "source_type": "production_code", "authority_tier": "A",
                "source_url": rp, "title": (sym or rp.split("/")[-1]),
                "verification_status": "verified", "topic_tags": [cat],
                "phase": "CONTROL-2C",
            })

    # deterministic ordering
    sources.sort(key=lambda r: r["path"])
    chunk_meta.sort(key=lambda r: (r["source_path"], r["start_line"], r["chunk_id"]))
    n_doc = sum(1 for _ in open(DOC_CHUNKS, encoding="utf-8")) if DOC_CHUNKS.exists() else 0

    print(f"sources: {len(sources)} (include={sum(1 for s in sources if s['status']=='include')}, "
          f"exclude={sum(1 for s in sources if s['status']=='exclude')})")
    print(f"code chunks: {len(chunk_meta)}")
    print(f"doc chunks (existing corpus): {n_doc}")
    print(f"canonical total: {len(chunk_meta) + n_doc}")
    print(f"skipped files: {skipped}; warnings: {len(warnings)}")
    print(f"by_category: {json.dumps(cat_counts)}")

    if args.dry_run:
        print("[dry-run] no files written")
        return

    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema": "webhound.brain.sources.v1",
        "deterministic": True,
        "note": "Per-file timestamps intentionally omitted; hashes provide change detection.",
        "code_roots": [rel(b) for _, b, _, _ in CODE_ROOTS if b.is_dir()],
        "exclude_rules": {"substrings": list(EXCLUDE_SUBSTR), "names": list(EXCLUDE_NAMES)},
        "counts": {"sources": len(sources),
                   "included": sum(1 for s in sources if s["status"] == "include"),
                   "excluded": sum(1 for s in sources if s["status"] == "exclude"),
                   "code_chunks": len(chunk_meta), "doc_chunks": n_doc},
        "sources": sources,
    }
    SOURCES_MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(CODE_CHUNKS_MANIFEST, "w", encoding="utf-8") as fh:
        for c in chunk_meta:
            fh.write(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n")
    RETRIEVAL_CONFIG.write_text(json.dumps({
        "schema": "webhound.brain.retrieval.v1",
        "canonical_chunks": "corpus/index/canonical_chunks.jsonl",
        "doc_chunks": "corpus/normalized/unified_chunks.jsonl",
        "code_chunks_manifest": "corpus/index/code_chunks_manifest.jsonl",
        "sources_manifest": "corpus/index/brain_sources_manifest.json",
        "embedding_model": "all-MiniLM-L6-v2",
        "prefer_canonical": True,
        "rebuild_cmd": "python scripts/ai/build_canonical_brain_index.py",
        "note": "canonical_chunks.jsonl is regenerated (not committed). Run rebuild_cmd after clone.",
    }, indent=2), encoding="utf-8")
    with open(CANONICAL_CHUNKS, "w", encoding="utf-8") as fh:
        for r in canonical_rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\nwrote: {rel(SOURCES_MANIFEST)}, {rel(CODE_CHUNKS_MANIFEST)}, {rel(RETRIEVAL_CONFIG)}")
    print(f"regenerated (not committed): {rel(CANONICAL_CHUNKS)}")

    if args.embed:
        # Local dense embeddings over the canonical doc+code chunk set (build
        # artifact — NOT committed). Aligns 1:1 with canonical_chunks.jsonl order.
        import numpy as np
        from sentence_transformers import SentenceTransformer
        doc_rows = [json.loads(l) for l in open(DOC_CHUNKS, encoding="utf-8") if l.strip()] \
            if DOC_CHUNKS.exists() else []
        all_rows = canonical_rows + doc_rows  # canonical (code) first, then docs
        # rewrite canonical_chunks to include docs so embeddings align with retrieval
        with open(CANONICAL_CHUNKS, "w", encoding="utf-8") as fh:
            for r in all_rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        model = SentenceTransformer("all-MiniLM-L6-v2")
        emb = model.encode([r.get("text", "") for r in all_rows], batch_size=64,
                           normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
        dense_dir = INDEX_DIR / "dense"
        dense_dir.mkdir(parents=True, exist_ok=True)
        np.save(str(dense_dir / "chunk_embeddings.npy"), emb)
        json.dump([{"idx": i, "chunk_id": r["chunk_id"], "file_path": r.get("file_path", ""),
                    "source_type": r.get("source_type", "")} for i, r in enumerate(all_rows)],
                  open(dense_dir / "chunk_embedding_meta.json", "w"), indent=0)
        print(f"embedded {len(all_rows)} chunks -> {rel(dense_dir)}/ (not committed)")


if __name__ == "__main__":
    main()
