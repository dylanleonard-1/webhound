#!/usr/bin/env python3
"""Phase 5B — improved (semantic-foundation) retrieval over the INTERNAL corpus only.

Fixes the Phase 5A weakness where raw keyword *counts* let verbose docs (audits,
the master plan) outrank the concise canonical note. Uses BM25 (IDF +
document-length normalization) + an authority-tier weighting, so authority +
relevance outweigh keyword frequency.

EMBEDDINGS GUARDRAIL (honored): this uses a PURE-PYTHON, OFFLINE, zero-dependency
sparse model. It does NOT install LightRAG/torch, does NOT download a model, and
does NOT call any external embeddings API — internal docs never leave the machine.
A pluggable Backend interface lets a future dense-embedding backend drop in (an
explicit, cost-flagged Phase 5C opt-in). Any LLM/API use still gates on
WEBHOUND_AI_ENABLED + ANTHROPIC_API_KEY (not used here).

LOCAL + READ-ONLY. No network, no installs, no secrets, no scanner/WADE changes.

Usage:
  python scripts/ai/semantic_retrieval.py query "What is WADE?" [--backend bm25|keyword]
  python scripts/ai/semantic_retrieval.py compare      # keyword vs bm25 on the 5A test set
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

# Authority multipliers — make tier break near-ties without dominating relevance.
AUTH_WEIGHT = {"A": 1.15, "B": 1.0, "C": 0.85}

STOP = set("a an the is are of to and or in on for with not no this that it as by "
           "be at from we you your our what how do does it's its".split())


def _ingest():
    spec = importlib.util.spec_from_file_location(
        "ingest_internal_knowledge", os.path.join(HERE, "ingest_internal_knowledge.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _tok(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_]+", text.lower()) if t not in STOP and len(t) > 2]


# --------------------------------------------------------------------------- #
# Backends (pluggable). Each ranks chunks for a query -> list[(score, chunk)].
# --------------------------------------------------------------------------- #
class KeywordBackend:
    """Phase-5A baseline: raw term-frequency count (no IDF, no length norm)."""
    name = "keyword"

    def __init__(self, chunks):
        self.chunks = chunks
        self._toks = [_tok(c["text"]) for c in chunks]

    def rank(self, query, authority=False):
        qt = _tok(query)
        out = []
        for c, toks in zip(self.chunks, self._toks):
            tf = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            score = sum(tf.get(t, 0) for t in qt)
            if score:
                if authority:
                    score *= AUTH_WEIGHT.get(c["authority_tier"], 1.0)
                out.append((score, c))
        out.sort(key=lambda s: (-s[0], s[1]["chunk_id"]))
        return out


class BM25Backend:
    """Okapi BM25 (k1, b) + IDF + length normalization. Pure python, offline."""
    name = "bm25"

    def __init__(self, chunks, k1: float = 1.5, b: float = 0.75):
        self.chunks = chunks
        self.k1, self.b = k1, b
        self._toks = [_tok(c["text"]) for c in chunks]
        self._len = [len(t) for t in self._toks]
        self.avgdl = (sum(self._len) / len(self._len)) if self._len else 0.0
        # document frequency per term
        df: dict[str, int] = {}
        for toks in self._toks:
            for t in set(toks):
                df[t] = df.get(t, 0) + 1
        n = len(chunks)
        self.idf = {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}
        self._tf = []
        for toks in self._toks:
            tf: dict[str, int] = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            self._tf.append(tf)

    def rank(self, query, authority=True):
        qt = _tok(query)
        out = []
        for i, c in enumerate(self.chunks):
            tf, dl = self._tf[i], self._len[i]
            s = 0.0
            for t in qt:
                if t not in tf:
                    continue
                idf = self.idf.get(t, 0.0)
                num = tf[t] * (self.k1 + 1)
                den = tf[t] + self.k1 * (1 - self.b + self.b * (dl / (self.avgdl or 1)))
                s += idf * num / den
            if s > 0:
                if authority:
                    s *= AUTH_WEIGHT.get(c["authority_tier"], 1.0)
                out.append((s, c))
        out.sort(key=lambda x: (-x[0], x[1]["chunk_id"]))
        return out


def best_docs(ranked, k=5):
    """Collapse chunk hits to best-per-document (top-k documents)."""
    seen, docs = set(), []
    for score, c in ranked:
        if c["doc_id"] in seen:
            continue
        seen.add(c["doc_id"])
        docs.append((score, c))
        if len(docs) >= k:
            break
    return docs


# --------------------------------------------------------------------------- #
# Evaluation set (gold canonical sources per query — internal only).
# A query is "correct@k" if any accepted path appears in the top-k documents.
# --------------------------------------------------------------------------- #
EVAL = [
    ("What is WADE?",
     ["knowledge/webhound/wade/WADE_FOUNDATION.md"]),
    ("What is the provider access framework?",
     ["knowledge/webhound/provider-access/PLATFORM_ACCESS_FRAMEWORK.md",
      "WEBHOUND_PLATFORM_ACCESS_FRAMEWORK.md"]),
    ("What known false positives exist?",
     ["knowledge/false-positive-catalog/README.md"]),  # plus any catalog note (prefix accepted below)
    ("What scanner IPs are currently approved?",
     ["docs/scanner-identity.md",
      "knowledge/webhound/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md"]),
    ("What is the current threat-intel architecture?",
     ["knowledge/webhound/threat-intel/THREAT_INTEL_CURRENT_STATE.md",
      "knowledge/threat-intel-library/README.md"]),
    ("What is the difference between corpus and knowledge?",
     ["knowledge/README.md", "docs/ai/RAG_ARCHITECTURE.md",
      "docs/ai/corpus/CORPUS_ARCHITECTURE.md"]),
]
FP_PREFIX = "knowledge/false-positive-catalog/"


def _hit(path, accepted):
    if path in accepted:
        return True
    # accept any FP catalog note for the false-positives query
    if any(a.startswith(FP_PREFIX) for a in accepted) and path.startswith(FP_PREFIX):
        return True
    return False


def evaluate(backend, authority):
    top1 = top3 = 0
    auth_ok = 0
    rows = []
    for q, accepted in EVAL:
        docs = best_docs(backend.rank(q, authority=authority), k=3)
        paths = [c["source_path"] for _s, c in docs]
        tiers = [c["authority_tier"] for _s, c in docs]
        h1 = bool(paths) and _hit(paths[0], accepted)
        h3 = any(_hit(p, accepted) for p in paths)
        top1 += h1
        top3 += h3
        # authority correctness: top result is tier A or B (not a stale C audit) when an A/B canonical exists
        auth_ok += (tiers[0] in ("A", "B")) if tiers else 0
        rows.append((q, paths, tiers, h1, h3))
    n = len(EVAL)
    return {"top1": top1, "top3": top3, "n": n, "auth_ok": auth_ok, "rows": rows}


def _print_eval(name, res):
    print(f"\n=== {name} ===")
    print(f"top-1: {res['top1']}/{res['n']}  top-3: {res['top3']}/{res['n']}  "
          f"top-result tier A/B: {res['auth_ok']}/{res['n']}")
    for q, paths, tiers, h1, h3 in res["rows"]:
        flag = "OK " if h1 else ("~3 " if h3 else "MISS")
        print(f"  [{flag}] {q}")
        for p, t in zip(paths, tiers):
            print(f"          ({t}) {p}")


def cmd_compare(_args) -> int:
    chunks = _ingest_chunks()
    kw = KeywordBackend(chunks)
    bm = BM25Backend(chunks)
    print(f"[index] {len(chunks)} chunks (internal corpus only; offline BM25, no model download)")
    _print_eval("KEYWORD (Phase 5A baseline, raw counts)", evaluate(kw, authority=False))
    _print_eval("BM25 + authority weighting (Phase 5B)", evaluate(bm, authority=True))
    return 0


def cmd_query(args) -> int:
    chunks = _ingest_chunks()
    backend = BM25Backend(chunks) if args.backend == "bm25" else KeywordBackend(chunks)
    auth = (args.backend == "bm25")
    for score, c in best_docs(backend.rank(args.text, authority=auth), k=5):
        print(f"  [{score:6.2f}] ({c['authority_tier']}) {c['source_path']}  «{c['heading'][:54]}»")
    return 0


_CHUNK_CACHE = None


def _ingest_chunks():
    global _CHUNK_CACHE
    if _CHUNK_CACHE is None:
        mod = _ingest()
        recs, _ = mod.build_records()
        _CHUNK_CACHE = mod.build_chunks(recs)
    return _CHUNK_CACHE


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 5B semantic-foundation retrieval (offline BM25 + authority)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("query"); q.add_argument("text")
    q.add_argument("--backend", choices=["bm25", "keyword"], default="bm25"); q.set_defaults(fn=cmd_query)
    c = sub.add_parser("compare"); c.set_defaults(fn=cmd_compare)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
