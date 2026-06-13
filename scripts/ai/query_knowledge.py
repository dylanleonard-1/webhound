#!/usr/bin/env python3
"""Query the local knowledge layer (Phase 4).

LOCAL + READ-ONLY. Operates ONLY on local knowledge/, corpus/, docs/ai/, vault/.
No network, no LLM calls, no external downloads, no secrets.

If LightRAG is installed, a future version uses it; for Phase 4 it falls back to a
transparent MOCK keyword search over local Markdown files so the flow is
demonstrable without installing anything.

Usage:
  python scripts/ai/query_knowledge.py "your question"
  python scripts/ai/query_knowledge.py --samples
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SOURCES = ["knowledge", "corpus", "docs/ai", "vault"]

SAMPLE_QUERIES = [
    "What are known WebHound false-positive classes?",
    "What is the difference between corpus and knowledge?",
    "What is the WebHound provider-access framework?",
    "What is the current threat-intel state?",
    "What should never enter Claude memory?",
]

STOP = set("a an the is are of to and or what how do does in on for with not no".split())


def _lightrag_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("lightrag") is not None


def _md_files() -> list[str]:
    out = []
    for top in SOURCES:
        base = os.path.join(ROOT, top)
        for dp, _d, files in os.walk(base):
            for fn in files:
                if fn.endswith(".md") or fn.endswith(".json"):
                    out.append(os.path.join(dp, fn))
    return out


def _terms(q: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_./-]+", q.lower()) if t not in STOP and len(t) > 2]


def mock_search(query: str, k: int = 5) -> list[tuple[int, str, str]]:
    """Transparent keyword scorer over local files. Returns (score, path, snippet)."""
    terms = _terms(query)
    results = []
    for path in _md_files():
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except Exception:  # noqa: BLE001
            continue
        low = text.lower()
        score = sum(low.count(t) for t in terms)
        if score:
            # first line mentioning any term, as a snippet
            snippet = ""
            for line in text.splitlines():
                if any(t in line.lower() for t in terms) and line.strip():
                    snippet = line.strip()[:160]
                    break
            results.append((score, os.path.relpath(path, ROOT), snippet))
    results.sort(key=lambda r: (-r[0], r[1]))
    return results[:k]


def run_query(query: str) -> None:
    print(f"\nQ: {query}")
    if _lightrag_available():
        print("  [info] LightRAG is installed — a future version will use it. "
              "Phase 4 still uses the mock path (no LLM call).")
    else:
        print("  [info] LightRAG not installed — using mock keyword retrieval (local files only).")
    hits = mock_search(query)
    if not hits:
        print("  (no local matches)")
        return
    for score, path, snippet in hits:
        print(f"  [{score:>3}] {path}")
        if snippet:
            print(f"        {snippet}")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--samples":
        for q in SAMPLE_QUERIES:
            run_query(q)
        return 0
    run_query(" ".join(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
