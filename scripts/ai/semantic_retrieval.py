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

# Document-ROLE multipliers. Generalizes (role-based, not topic-based): boost
# canonical/per-domain notes; demote generated reports + audits for DEFINITIONAL
# ("what is X") queries; for AUDIT/HISTORY queries, do NOT demote those.
ROLE_WEIGHT_DEFINITIONAL = {
    "canonical_note": 1.35, "architecture_summary": 1.15, "decision_log": 1.1,
    "false_positive_note": 1.25, "provider_note": 1.1, "engine_note": 1.1,
    "policy_doc": 1.2, "phase_result_report": 0.5, "generated_summary": 0.55,
    "audit_report": 0.55, "historical_reference": 0.7, "empty_stub": 0.0,
}
ROLE_WEIGHT_AUDIT = {
    "audit_report": 1.35, "historical_reference": 1.2, "phase_result_report": 1.15,
    "generated_summary": 1.1,
    # everything else neutral
    "canonical_note": 1.0, "architecture_summary": 1.0, "decision_log": 1.0,
    "false_positive_note": 1.0, "provider_note": 1.0, "engine_note": 1.0,
    "policy_doc": 1.0, "empty_stub": 0.0,
}

# Generic stopwords only. NOTE: do NOT stop content words like "never"/"enter"
# (they discriminate "what should NEVER ENTER the corpus").
STOP = set("a an the is are of to and or in on for with not no this that it as by "
           "be at from we you your our what how do does it's its currently "
           "difference between".split())


def _stem(t: str) -> str:
    """Minimal, conservative plural stemmer (positives->positive, rules->rule)."""
    if len(t) >= 5 and t.endswith("s") and not t.endswith("ss"):
        return t[:-1]
    return t


# --------------------------------------------------------------------------- #
# Synonym / alias query expansion (zero-dep, generalizing). Improves paraphrase
# recall by expanding the QUERY only (never the docs). Keys + values are STEMMED
# at use time. This is a small DOMAIN map (security / retrieval / WebHound terms),
# NOT per-question hardcoding.
#
# HOW TO EXTEND: add a `concept: [synonyms...]` entry below. Use lowercase domain
# words (not phrases tied to a specific test question). Expansion is bidirectional
# (a hit on any member pulls in the rest of its group). Keep it small + reviewed.
# --------------------------------------------------------------------------- #
_ALIAS_GROUPS = [
    ["ip", "address", "egress", "outbound", "allowlist", "allowlisting"],
    ["scanner", "scan", "crawler"],
    ["provider", "cdn", "waf", "cloudflare", "vercel"],
    ["wade", "drift", "anomaly", "baseline"],
    ["memory", "summary", "summaries", "recall"],
    ["corpus", "evidence", "ingestion", "ingest"],
    ["knowledge", "curated", "note"],
    ["threat", "intel", "feed", "indicator", "reputation"],
    ["false", "positive", "fp"],
    ["mcp", "tool", "server"],
    ["retrieval", "search", "rag", "rank", "ranking"],
    ["policy", "rule", "governance"],
    ["security", "safety", "injection"],
    ["graph", "node", "edge", "bridge"],
    ["architecture", "design", "overview", "system"],
]


def _build_alias_index():
    idx: dict[str, set[str]] = {}
    for group in _ALIAS_GROUPS:
        gs = {_stem(w) for w in group}
        for w in gs:
            idx.setdefault(w, set()).update(gs - {w})
    return idx


_ALIAS_INDEX = _build_alias_index()


ALIAS_WEIGHT = 0.25  # alias/synonym terms count for less than exact query terms


def expand_terms(terms: list[str]) -> list[str]:
    """Query-side expansion: add domain synonyms (stemmed, deduped)."""
    return list(expand_terms_weighted(terms).keys())


def expand_terms_weighted(terms: list[str]) -> dict[str, float]:
    """Return {term: weight}: original query terms at 1.0, added synonyms at
    ALIAS_WEIGHT, so exact matches dominate and aliases only add paraphrase recall
    (preserves precision)."""
    weights = {t: 1.0 for t in terms}
    for t in terms:
        for syn in _ALIAS_INDEX.get(t, ()):  # already stemmed
            if syn not in weights:
                weights[syn] = ALIAS_WEIGHT
    return weights


def detect_intent(query: str) -> str:
    q = query.lower()
    if any(w in q for w in ("audit", "review", "history", "historical",
                            "what happened", "previous", "past")):
        return "audit"
    return "definitional"


def path_boost(query: str, chunk: dict) -> float:
    """Boost docs whose FILENAME/path tokens match the query subject — canonical
    notes are named after their topic (WADE_FOUNDATION, PLATFORM_ACCESS_FRAMEWORK,
    SECURITY_GRAPH_BRIDGE, ...), while generic reports (PHASE5A_RESULTS,
    *_REVIEW) are not. Generalizes; no per-topic hardcoding."""
    subj = set(_tok(query))
    if not subj:
        return 1.0
    path = chunk["source_path"].lower()
    fname = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    base_toks = {_stem(x) for x in re.split(r"[_/.-]+", fname) if x and x not in STOP}
    dir_toks = {_stem(x) for x in re.split(r"[_/.-]+", path.rsplit("/", 1)[0] if "/" in path else "")
                if x and x not in STOP}
    head_toks = set(_tok(chunk.get("heading", "")))
    b = 1.0
    b *= 1.0 + 0.28 * len(subj & base_toks)   # strong: filename matches topic
    b *= 1.0 + 0.08 * len(subj & dir_toks)    # weaker: directory matches topic
    b *= 1.0 + 0.05 * len(subj & head_toks)   # small: heading matches topic
    return min(b, 2.4)


def _ingest():
    spec = importlib.util.spec_from_file_location(
        "ingest_internal_knowledge", os.path.join(HERE, "ingest_internal_knowledge.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _tok(text: str) -> list[str]:
    return [_stem(t) for t in re.findall(r"[a-z0-9_]+", text.lower())
            if t not in STOP and len(t) > 2]


# --------------------------------------------------------------------------- #
# Backends (pluggable). Each ranks chunks for a query -> list[(score, chunk)].
# --------------------------------------------------------------------------- #
class KeywordBackend:
    """Phase-5A baseline: raw term-frequency count (no IDF, no length norm)."""
    name = "keyword"

    def __init__(self, chunks):
        self.chunks = chunks
        self._toks = [_tok(c["text"]) for c in chunks]

    def rank(self, query, authority=False, expand=False):
        qt = _tok(query)  # baseline: raw terms, no expansion
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

    def rank(self, query, authority=True, expand=False):
        """authority=True applies the full Phase-5C weighting (tier + role +
        path-match), intent-aware. authority=False is the raw BM25 score.
        expand=True adds Phase-5D synonym/alias query expansion (query side only)."""
        base = _tok(query)
        qweights = expand_terms_weighted(base) if expand else {t: 1.0 for t in base}
        intent = detect_intent(query)
        role_w = ROLE_WEIGHT_AUDIT if intent == "audit" else ROLE_WEIGHT_DEFINITIONAL
        out = []
        for i, c in enumerate(self.chunks):
            tf, dl = self._tf[i], self._len[i]
            s = 0.0
            for t, w in qweights.items():
                if t not in tf:
                    continue
                idf = self.idf.get(t, 0.0)
                num = tf[t] * (self.k1 + 1)
                den = tf[t] + self.k1 * (1 - self.b + self.b * (dl / (self.avgdl or 1)))
                s += w * idf * num / den
            if s <= 0:
                continue
            if authority:
                s *= AUTH_WEIGHT.get(c["authority_tier"], 1.0)
                s *= role_w.get(c.get("doc_role", "canonical_note"), 1.0)
                s *= path_boost(query, c)
            if s > 0:
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
    ("What scanner IPs are currently approved?",
     ["docs/scanner-identity.md",
      "knowledge/webhound/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md"]),
    ("What known false positives exist?",
     ["knowledge/false-positive-catalog/README.md"]),  # plus any catalog note (prefix accepted below)
    ("What is the difference between corpus and knowledge?",
     ["knowledge/README.md", "docs/ai/RAG_ARCHITECTURE.md",
      "docs/ai/corpus/CORPUS_ARCHITECTURE.md"]),
    ("What is the current threat-intel architecture?",
     ["knowledge/webhound/threat-intel/THREAT_INTEL_CURRENT_STATE.md",
      "knowledge/threat-intel-library/README.md"]),
    # Phase 5C — 4 new queries
    ("What are the rules for Claude memory?",
     ["docs/ai/CLAUDE_MEMORY_POLICY.md"]),
    ("What is the Security Graph bridge?",
     ["docs/ai/SECURITY_GRAPH_BRIDGE.md"]),
    ("What should never enter the knowledge corpus?",
     ["docs/ai/corpus/RETENTION_POLICY.md", "docs/ai/CLAUDE_MEMORY_POLICY.md"]),
    ("What is the MCP security model?",
     ["docs/ai/mcp/MCP_SECURITY_MODEL.md"]),
]
# The original six (for the 5A/5B comparison subset).
ORIGINAL_SIX = {0, 1, 2, 3, 4, 5}
FP_PREFIX = "knowledge/false-positive-catalog/"


def _hit(path, accepted):
    if path in accepted:
        return True
    # accept any FP catalog note for the false-positives query
    if any(a.startswith(FP_PREFIX) for a in accepted) and path.startswith(FP_PREFIX):
        return True
    return False


def evaluate(backend, authority, expand=False):
    rows = []
    for idx, (q, accepted) in enumerate(EVAL):
        docs = best_docs(backend.rank(q, authority=authority, expand=expand), k=3)
        paths = [c["source_path"] for _s, c in docs]
        tiers = [c["authority_tier"] for _s, c in docs]
        roles = [c.get("doc_role", "?") for _s, c in docs]
        h1 = bool(paths) and _hit(paths[0], accepted)
        h3 = any(_hit(p, accepted) for p in paths)
        auth1 = bool(tiers) and tiers[0] in ("A", "B")
        rows.append({"i": idx, "q": q, "paths": paths, "tiers": tiers, "roles": roles,
                     "h1": h1, "h3": h3, "auth1": auth1})
    return rows


def _metrics(rows, subset=None):
    sel = [r for r in rows if subset is None or r["i"] in subset]
    n = len(sel)
    return {"n": n,
            "top1": sum(r["h1"] for r in sel),
            "top3": sum(r["h3"] for r in sel),
            "auth1": sum(r["auth1"] for r in sel)}


def _print_eval(name, rows):
    allm = _metrics(rows)
    six = _metrics(rows, ORIGINAL_SIX)
    print(f"\n=== {name} ===")
    print(f"ALL 10  -> top-1: {allm['top1']}/10  top-3: {allm['top3']}/10  top tier A/B: {allm['auth1']}/10")
    print(f"ORIG 6  -> top-1: {six['top1']}/6   top-3: {six['top3']}/6   top tier A/B: {six['auth1']}/6")
    for r in rows:
        flag = "OK  " if r["h1"] else ("~3  " if r["h3"] else "MISS")
        print(f"  [{flag}] {r['q']}")
        for p, t, role in zip(r["paths"], r["tiers"], r["roles"]):
            print(f"          ({t}/{role}) {p}")


def cmd_compare(_args) -> int:
    chunks = _ingest_chunks()
    kw = KeywordBackend(chunks)
    bm = BM25Backend(chunks)
    print(f"[index] {len(chunks)} chunks (internal corpus only; offline BM25, no model download)")
    _print_eval("KEYWORD (5A baseline, raw counts)", evaluate(kw, authority=False))
    _print_eval("BM25 + tier + ROLE + path (Phase 5C)", evaluate(bm, authority=True, expand=False))
    _print_eval("BM25 + tier + ROLE + path + SYNONYMS (Phase 5D-B)", evaluate(bm, authority=True, expand=True))
    return 0


def cmd_query(args) -> int:
    chunks = _ingest_chunks()
    backend = BM25Backend(chunks) if args.backend == "bm25" else KeywordBackend(chunks)
    auth = (args.backend == "bm25")
    expand = auth and not getattr(args, "no_expand", False)  # synonym expansion on by default for bm25
    for score, c in best_docs(backend.rank(args.text, authority=auth, expand=expand), k=5):
        print(f"  [{score:6.2f}] ({c['authority_tier']}/{c.get('doc_role','?')}) "
              f"{c['source_path']}  «{c['heading'][:50]}»")
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
    q.add_argument("--backend", choices=["bm25", "keyword"], default="bm25")
    q.add_argument("--no-expand", action="store_true", help="disable synonym/alias query expansion")
    q.set_defaults(fn=cmd_query)
    c = sub.add_parser("compare"); c.set_defaults(fn=cmd_compare)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
