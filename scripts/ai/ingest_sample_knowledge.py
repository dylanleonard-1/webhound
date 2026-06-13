#!/usr/bin/env python3
"""Build a tiny LOCAL index from existing local knowledge (Phase 4).

LOCAL + READ-ONLY inputs. Operates ONLY on local knowledge/, docs/ai/, vault/.
NO external downloads, NO web crawl, NO threat-feed fetch, NO secrets, NO customer
data, NO production DB.

If LightRAG is installed, a future version builds a LightRAG index. For Phase 4 it
builds a simple local keyword index (path -> top terms) and writes it to a
WORKING DIR that defaults to the OS temp dir (NOT the repo), so no index blob is
committed. Override with --output.

Usage:
  python scripts/ai/ingest_sample_knowledge.py [--output DIR] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SOURCES = ["knowledge", "docs/ai", "vault"]
STOP = set("a an the is are of to and or in on for with not no this that it as by".split())


def _lightrag_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("lightrag") is not None


def _md_files() -> list[str]:
    out = []
    for top in SOURCES:
        for dp, _d, files in os.walk(os.path.join(ROOT, top)):
            out += [os.path.join(dp, fn) for fn in files if fn.endswith(".md")]
    return out


def _top_terms(text: str, n: int = 12) -> list[str]:
    counts: dict[str, int] = {}
    for t in re.findall(r"[a-z][a-z0-9_-]{3,}", text.lower()):
        if t in STOP:
            continue
        counts[t] = counts.get(t, 0) + 1
    return [t for t, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:n]]


def build_index() -> list[dict]:
    index = []
    for path in _md_files():
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except Exception:  # noqa: BLE001
            continue
        rel = os.path.relpath(path, ROOT)
        index.append({
            "path": rel,
            "chars": len(text),
            "top_terms": _top_terms(text),
            # provenance pointer: curated knowledge is trusted_local
            "trust_label": "trusted_local",
        })
    return index


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=None,
                    help="working dir for the index (default: OS temp; NOT the repo)")
    ap.add_argument("--dry-run", action="store_true", help="print plan, write nothing")
    args = ap.parse_args(argv)

    if _lightrag_available():
        print("[info] LightRAG installed — a future version will build a LightRAG index. "
              "Phase 4 builds the simple local index below (no LLM/network).")
    else:
        print("[info] LightRAG not installed — building a simple local keyword index "
              "(no LLM, no network, no install).")

    index = build_index()
    print(f"[info] indexed {len(index)} local Markdown files from {SOURCES} (read-only).")

    if args.dry_run:
        print("[dry-run] no index written.")
        return 0

    out_dir = args.output or os.path.join(tempfile.gettempdir(), "webhound_rag_work")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "knowledge_index.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
    print(f"[ok] wrote local index: {out_path}")
    print("     (outside the repo by default; nothing committed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
