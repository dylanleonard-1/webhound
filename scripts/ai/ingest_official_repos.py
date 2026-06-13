#!/usr/bin/env python3
"""Phase 6B — official security-repository ingestion (EXTERNAL, controlled).

Ingests a SMALL, fixed allow-list of official/high-authority GitHub repositories
into the WebHound knowledge corpus as Tier-C `official_repo` records. This teaches
WebHound about scanning, crawling, URL discovery, HTTP probing, nuclei-style
templates, static analysis, secret detection, MCP tooling and retrieval — from the
tools' OWN documentation.

This is CONTROLLED repo ingestion, NOT blind repo mirroring:
  * Only documentation-bearing markdown (README / docs / examples docs / security
    docs / release notes) is ingested. Per-repo file caps + size caps apply; the
    rest is reported as skipped.
  * EXCLUDED always: node_modules, vendor, dist, build, .git, test fixtures/data,
    locales/translations, binaries, datasets, generated files, secrets.
  * APPEND-ONLY to corpus/manifests/manifest.jsonl. Pre-existing records (211
    internal + 6 Phase-6A official_doc) are NEVER rewritten and stay byte-stable.
  * Raw clones/fetches are EPHEMERAL (OS temp dir, never committed). Only NORMALIZED
    text + chunks + manifest metadata are committed. No full repo is mirrored.
  * External content is EVIDENCE, never instructions. Stored as plain text, never
    executed. Each file is PINNED to the exact upstream commit SHA for provenance.

Network is used ONLY by `run`. Importing this module performs no network I/O, so
tests/CI (which read committed artifacts offline) never touch the network.

Usage:
  GITHUB_TOKEN=$(gh auth token) python scripts/ai/ingest_official_repos.py run
  python scripts/ai/ingest_official_repos.py run --dry-run
  python scripts/ai/ingest_official_repos.py query "secret detection"
  python scripts/ai/ingest_official_repos.py selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

INGEST_STAMP = "2026-06-13"

MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "repos")
CHUNKS_PATH = os.path.join(NORM_DIR, "repo_chunks.jsonl")
# Raw fetched content is ephemeral and NEVER committed.
RAW_WORK_DIR = os.path.join(tempfile.gettempdir(), "webhound_repo_raw")

USER_AGENT = "WebHound-KnowledgeIngest/6B (+https://webhoundsecurity.com)"
HTTP_TIMEOUT = 30
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

# Controlled-ingestion caps.
MAX_FILE_BYTES = 200_000
DOC_EXTS = (".md", ".mdx")
# Path segments that are NEVER ingested (case-insensitive match on any segment).
EXCLUDE_SEGMENTS = {
    "node_modules", "vendor", "dist", "build", ".git", "bin", "obj",
    "testdata", "test-data", "test_data", "fixtures", "__fixtures__", "snapshots",
    "locales", "locale", "i18n", "translations", "translated", "lang", "langs",
    "dataset", "datasets", ".github",
}
# Non-knowledge / governance / agent-instruction docs — skip by basename stem.
# (SECURITY and real docs are kept; LICENSE/CONTRIBUTING/CLAUDE/etc. are not
# security knowledge, and external CLAUDE.md is agent instructions — excluded per
# the prompt-injection policy: external content is evidence, never instructions.)
EXCLUDE_BASENAMES = {
    "license", "licence", "copying", "notice", "notices", "contributing",
    "code_of_conduct", "code-of-conduct", "codeowners", "thanks", "authors",
    "maintainers", "owners", "users", "claude", "support", "funding", "governance",
    "changelog", "history", "metrics",
}
_THIRD_PARTY_RE = re.compile(r"third[-_]party[-_](licen|notice)", re.IGNORECASE)

# Non-English localized docs (README.zh-CN.md, README_ja.md, README-zh.md) — skip.
# Locale token separated by '.', '_' or '-', with an optional region, before .md.
_LOCALIZED_RE = re.compile(
    r"[._-](zh|cn|tw|ja|jp|ko|kr|fr|de|es|pt|ru|it|tr|pl|id|hi|ar|vi|th|nl|"
    r"uk|fa|bn|ru)(-[a-z]{2})?\.mdx?$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Allow-list: the ONLY repositories Phase 6B may ingest (the approved set).
# ---------------------------------------------------------------------------
REPOS = [
    {
        "slug": "nuclei", "repo": "projectdiscovery/nuclei", "max_files": 10,
        "product": "nuclei", "doc_role": "engine_note",
        "topic_tags": ["github-repo", "vulnerability-detection", "nuclei-templates",
                       "scanner-engine", "web-security", "detection-engineering"],
        "entities": ["ProjectDiscovery", "nuclei"],
    },
    {
        "slug": "httpx", "repo": "projectdiscovery/httpx", "max_files": 8,
        "product": "httpx", "doc_role": "engine_note",
        "topic_tags": ["github-repo", "http-probing", "scanner-engine", "web-security"],
        "entities": ["ProjectDiscovery", "httpx"],
    },
    {
        "slug": "katana", "repo": "projectdiscovery/katana", "max_files": 8,
        "product": "katana", "doc_role": "engine_note",
        "topic_tags": ["github-repo", "crawling", "url-discovery", "scanner-engine",
                       "web-security"],
        "entities": ["ProjectDiscovery", "katana"],
    },
    {
        "slug": "amass", "repo": "owasp-amass/amass", "max_files": 10,
        "product": "amass", "doc_role": "engine_note",
        "license_override": "Apache-2.0",  # LICENSE says Apache2.0; custom header -> API NOASSERTION
        "topic_tags": ["github-repo", "url-discovery", "attack-surface", "scanner-engine",
                       "web-security"],
        "entities": ["OWASP", "Amass"],
    },
    {
        "slug": "gitleaks", "repo": "gitleaks/gitleaks", "max_files": 8,
        "product": "gitleaks", "doc_role": "engine_note",
        "topic_tags": ["github-repo", "secrets-detection", "static-analysis",
                       "scanner-engine"],
        "entities": ["gitleaks"],
    },
    {
        "slug": "semgrep", "repo": "semgrep/semgrep", "max_files": 10,
        "product": "semgrep", "doc_role": "engine_note",
        "topic_tags": ["github-repo", "static-analysis", "javascript-security",
                       "scanner-engine", "detection-engineering"],
        "entities": ["Semgrep"],
    },
    {
        "slug": "mcp-servers", "repo": "modelcontextprotocol/servers", "max_files": 12,
        "product": "modelcontextprotocol-servers", "doc_role": "canonical_note",
        "license_override": "CC-BY-4.0",  # docs are CC-BY-4.0 (repo in MIT->Apache-2.0 transition)
        "topic_tags": ["github-repo", "mcp", "server-tooling"],
        "entities": ["ModelContextProtocol", "MCP"],
    },
    {
        "slug": "playwright-mcp", "repo": "microsoft/playwright-mcp", "max_files": 8,
        "product": "playwright-mcp", "doc_role": "canonical_note",
        "topic_tags": ["github-repo", "mcp", "playwright", "javascript-security"],
        "entities": ["Microsoft", "Playwright", "MCP"],
    },
    {
        "slug": "github-mcp-server", "repo": "github/github-mcp-server", "max_files": 8,
        "product": "github-mcp-server", "doc_role": "canonical_note",
        "topic_tags": ["github-repo", "mcp", "server-tooling"],
        "entities": ["GitHub", "MCP"],
    },
    {
        "slug": "lightrag", "repo": "HKUDS/LightRAG", "max_files": 10,
        "product": "lightrag", "doc_role": "canonical_note",
        "topic_tags": ["github-repo", "lightrag", "benchmarking", "detection-engineering"],
        "entities": ["HKUDS", "LightRAG"],
    },
]

COMMON = {
    "source_type": "official_repo",
    "authority_tier": "C",
    "language": "en",
    "confidence_score": 0.75,
    "verification_status": "verified",
    "citability": "citable_external",
    "pii_risk_class": "none",
    "retention_class": "long",
    "trust_label": "trusted_external",
}

STOP = set((
    "a an the is are was were of to and or in on for with not no this that it "
    "as by be at from we you your our can will may should if then so "
    # query-template / generic words that carry no 'which repository' signal:
    "what which who whom where when how why repository repositories repo repos "
    "help helps helping document documents documentation explain explains "
    "teach teaches relevant most more used use using work works does do did "
    "about into onto via per most"
).split())


# ---------------------------------------------------------------------------
# GitHub API (network — `run` only)
# ---------------------------------------------------------------------------
def _http(url: str, accept: str = "application/vnd.github+json") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:  # noqa: S310
        return r.read()


def _api_json(url: str) -> object:
    return json.loads(_http(url).decode("utf-8", "replace"))


def repo_head(repo: str) -> tuple[str, str, str]:
    """Return (default_branch, commit_sha, commit_date) pinned to HEAD."""
    meta = _api_json(f"https://api.github.com/repos/{repo}")
    branch = meta.get("default_branch", "main")
    commit = _api_json(f"https://api.github.com/repos/{repo}/commits/{branch}")
    sha = commit["sha"]
    date = (commit.get("commit", {}) or {}).get("committer", {}).get("date")
    return branch, sha, date


def repo_license(repo: str) -> str:
    try:
        lic = _api_json(f"https://api.github.com/repos/{repo}/license")
        spdx = (lic.get("license") or {}).get("spdx_id")
        if spdx and spdx not in ("NOASSERTION", "NONE"):
            return spdx
    except Exception:  # noqa: BLE001
        pass
    return "manual_required"


def repo_tree(repo: str, sha: str) -> tuple[list[dict], bool]:
    data = _api_json(
        f"https://api.github.com/repos/{repo}/git/trees/{sha}?recursive=1")
    return data.get("tree", []), bool(data.get("truncated"))


def raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


# ---------------------------------------------------------------------------
# Controlled file selection
# ---------------------------------------------------------------------------
def _excluded(path: str) -> bool:
    segs = [s.lower() for s in path.split("/")]
    if any(s in EXCLUDE_SEGMENTS for s in segs):
        return True
    base = os.path.basename(path)
    if _LOCALIZED_RE.search(base):
        return True
    stem = re.sub(r"\.(md|mdx)$", "", base, flags=re.IGNORECASE).lower()
    if stem in EXCLUDE_BASENAMES or _THIRD_PARTY_RE.search(stem):
        return True
    return False


def _priority(path: str) -> int:
    base = os.path.basename(path).lower()
    depth = path.count("/")
    if depth == 0 and base == "readme.md":
        return 0
    if depth == 0 and base == "security.md":
        return 1
    if depth == 0:
        return 2
    if path.lower().startswith(("docs/", "doc/", "documentation/")):
        return 3
    return 4


def select_files(tree: list[dict], max_files: int) -> tuple[list[str], dict]:
    """Pick documentation markdown under caps. Returns (kept_paths, skip_report)."""
    candidates, too_big, excluded = [], 0, 0
    for node in tree:
        if node.get("type") != "blob":
            continue
        path = node["path"]
        if not path.lower().endswith(DOC_EXTS):
            continue
        if _excluded(path):
            excluded += 1
            continue
        if int(node.get("size", 0)) > MAX_FILE_BYTES:
            too_big += 1
            continue
        candidates.append(path)
    candidates.sort(key=lambda p: (_priority(p), p.count("/"), p.lower()))
    kept = candidates[:max_files]
    skipped_over_cap = max(0, len(candidates) - len(kept))
    report = {
        "doc_md_candidates": len(candidates),
        "kept": len(kept),
        "skipped_over_cap": skipped_over_cap,
        "skipped_too_big": too_big,
        "skipped_excluded_dirs_or_locale": excluded,
    }
    return kept, report


def doc_id_for(slug: str, path: str, seen: set[str]) -> str:
    stem = re.sub(r"\.(md|mdx)$", "", path, flags=re.IGNORECASE)
    slug_path = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    did = f"{slug}--{slug_path}"
    n = 1
    base = did
    while did in seen:
        n += 1
        did = f"{base}-{n}"
    seen.add(did)
    return did


# ---------------------------------------------------------------------------
# Normalize / chunk / hash (shared design with Phase 6A)
# ---------------------------------------------------------------------------
def normalize(raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5:]
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text + "\n"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


CHUNK_TARGET = 1500
CHUNK_MIN = 200


def chunk_text(doc_id: str, text: str) -> list[dict]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if buf and len(buf) + len(p) + 2 > CHUNK_TARGET:
            chunks.append(buf)
            buf = p
        else:
            buf = f"{buf}\n\n{p}" if buf else p
    if buf:
        chunks.append(buf)
    out, seen = [], set()
    for c in chunks:
        c = c.strip()
        key = re.sub(r"\s+", " ", c.lower())
        if len(c) < CHUNK_MIN or key in seen:
            continue
        seen.add(key)
        out.append({
            "chunk_id": f"{doc_id}::{len(out):03d}",
            "doc_id": doc_id,
            "ordinal": len(out),
            "char_len": len(c),
            "text": c,
        })
    return out


# ---------------------------------------------------------------------------
# Manifest record assembly
# ---------------------------------------------------------------------------
def build_record(cfg: dict, doc_id: str, path: str, url: str,
                 content_hash: str, sha: str, date: str | None,
                 license_terms: str) -> dict:
    return {
        "doc_id": doc_id,
        "title": f"{cfg['repo']} — {path}",
        "source_name": cfg["repo"],
        "source_url": url,
        "source_type": COMMON["source_type"],
        "doc_role": cfg["doc_role"],
        "authority_tier": COMMON["authority_tier"],
        "language": COMMON["language"],
        "product_or_provider": cfg["product"],
        "topic_tags": cfg["topic_tags"],
        "version": sha[:12],
        "last_updated": date,
        "first_ingested": INGEST_STAMP,
        "content_hash": content_hash,
        "confidence_score": COMMON["confidence_score"],
        "verification_status": COMMON["verification_status"],
        "license_terms": license_terms,
        "citability": COMMON["citability"],
        "pii_risk_class": COMMON["pii_risk_class"],
        "retention_class": COMMON["retention_class"],
        "entities": cfg["entities"] + [path],
        "related_docs": [],
        "trust_label": COMMON["trust_label"],
    }


def norm_path(doc_id: str) -> str:
    return os.path.join(NORM_DIR, f"{doc_id}.md")


# ---------------------------------------------------------------------------
# Manifest helpers (read-only reads; append-only writes)
# ---------------------------------------------------------------------------
def existing_doc_ids() -> set[str]:
    ids: set[str] = set()
    if not os.path.exists(MANIFEST_PATH):
        return ids
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ids.add(json.loads(line)["doc_id"])
    return ids


def _ensure_trailing_newline(path: str) -> None:
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            last = f.read(1)
        if last != b"\n":
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n")


def append_manifest(records: list[dict]) -> None:
    if not records:
        return
    _ensure_trailing_newline(MANIFEST_PATH)
    with open(MANIFEST_PATH, "a", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Retrieval (offline; over committed chunks)
# ---------------------------------------------------------------------------
def _stem(w: str) -> str:
    # light, symmetric plural folding (applied to both query and corpus terms):
    # 'secrets'->'secret', 'templates'->'template'. Short acronyms (cors, tls) keep.
    if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def _terms(s: str) -> list[str]:
    return [_stem(w) for w in re.findall(r"[a-z0-9]+", s.lower())
            if w not in STOP and len(w) > 1]


# query-term overlap with a repo's manifest topic_tags is a strong 'which
# repository' signal (e.g. 'secret detection' -> the secrets-detection repo).
TAG_BONUS = 8.0


def load_chunks() -> list[dict]:
    if not os.path.exists(CHUNKS_PATH):
        return []
    rows = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _build_idf(chunks: list[dict]) -> dict[str, float]:
    """Inverse document frequency over committed chunks, so distinctive terms
    (e.g. 'subdomain', 'gitleaks', 'template') outweigh generic ones
    (e.g. 'security', 'detection', 'repository')."""
    df: dict[str, int] = {}
    for c in chunks:
        for w in set(_terms(c["text"])):
            df[w] = df.get(w, 0) + 1
    n = max(1, len(chunks))
    return {w: math.log(1 + n / d) for w, d in df.items()}


def _chunk_score(c: dict, qterms: set[str], idf: dict[str, float]) -> float:
    # repo/file name terms are strong signals -> weight x3
    ct = _terms(c["text"]) + 3 * _terms(c["doc_id"].replace("-", " "))
    if not ct:
        return 0.0
    tf: dict[str, int] = {}
    for w in ct:
        tf[w] = tf.get(w, 0) + 1
    denom = 1 + (len(ct) / 500.0)
    return sum(tf.get(w, 0) * idf.get(w, math.log(2)) for w in qterms) / denom


def retrieve(chunks: list[dict], query: str, k: int = 5) -> list[dict]:
    idf = _build_idf(chunks)
    qterms = set(_terms(query))
    scored = [(_chunk_score(c, qterms, idf), c) for c in chunks]
    scored = [(s, c) for s, c in scored if s > 0]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:k]]


def retrieve_repos(chunks: list[dict], query: str, k: int = 3) -> list[str]:
    """Rank REPOS for a 'which repository helps with X?' query by each repo's
    best-scoring chunk (max-pool avoids favouring repos with more files)."""
    idf = _build_idf(chunks)
    qterms = set(_terms(query))
    best: dict[str, float] = {}
    for c in chunks:
        s = _chunk_score(c, qterms, idf)
        if s <= 0:
            continue
        r = repo_of(c["doc_id"])
        if s > best.get(r, 0.0):
            best[r] = s
    for cfg in REPOS:
        overlap = len(qterms & set(_terms(" ".join(cfg["topic_tags"]))))
        if overlap:
            best[cfg["slug"]] = best.get(cfg["slug"], 0.0) + overlap * TAG_BONUS
    return sorted(best, key=lambda r: best[r], reverse=True)[:k]


def repo_of(doc_id: str) -> str:
    return doc_id.split("--", 1)[0]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_run(args) -> int:
    have = existing_doc_ids()
    os.makedirs(RAW_WORK_DIR, exist_ok=True)
    new_records, all_chunks, summaries = [], [], []
    norm_to_write: dict[str, str] = {}
    seen_ids: set[str] = set()

    for cfg in REPOS:
        repo = cfg["repo"]
        branch, sha, date = repo_head(repo)
        license_terms = cfg.get("license_override") or repo_license(repo)
        tree, truncated = repo_tree(repo, sha)
        kept, report = select_files(tree, cfg["max_files"])
        repo_new = 0
        for path in kept:
            try:
                raw = _http(raw_url(repo, sha, path),
                            accept="text/plain").decode("utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                print(f"    [warn] fetch failed {repo}/{path}: {e}")
                continue
            doc_id = doc_id_for(cfg["slug"], path, seen_ids)
            norm = normalize(raw)
            chash = _sha256(norm.encode("utf-8"))
            chunks = chunk_text(doc_id, norm)
            if not chunks:  # too short after normalization — skip
                continue
            all_chunks.extend(chunks)
            norm_to_write[doc_id] = norm
            url = raw_url(repo, sha, path)
            rec = build_record(cfg, doc_id, path, url, chash, sha, date, license_terms)
            if doc_id not in have:
                new_records.append(rec)
                repo_new += 1
        summaries.append({
            "repo": repo, "slug": cfg["slug"], "pin": sha[:12], "license": license_terms,
            "truncated_tree": truncated, "new_records": repo_new, **report,
        })
        print(f"  [{cfg['slug']:16s}] pin={sha[:12]} lic={license_terms:14s} "
              f"kept={report['kept']:2d} new={repo_new:2d} "
              f"skip(cap/big/excl)={report['skipped_over_cap']}/"
              f"{report['skipped_too_big']}/{report['skipped_excluded_dirs_or_locale']}"
              f"{' TRUNCATED' if truncated else ''}")

    total_chunks = len(all_chunks)
    print(f"\n[summary] repos={len(REPOS)} new_records={len(new_records)} "
          f"chunks={total_chunks}")

    if args.dry_run:
        print("[dry-run] nothing written.")
        return 0

    os.makedirs(NORM_DIR, exist_ok=True)
    for doc_id, norm in norm_to_write.items():
        with open(norm_path(doc_id), "w", encoding="utf-8", newline="\n") as f:
            f.write(norm)
    with open(CHUNKS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    append_manifest(new_records)
    # machine-readable run summary for the results doc (committed, no secrets).
    with open(os.path.join(NORM_DIR, "ingest_summary.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"stamp": INGEST_STAMP, "repos": summaries,
                   "new_records": len(new_records), "chunks": total_chunks},
                  f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[ok] wrote {len(norm_to_write)} normalized docs -> "
          f"{os.path.relpath(NORM_DIR, ROOT)}/")
    print(f"[ok] wrote {total_chunks} chunks -> {os.path.relpath(CHUNKS_PATH, ROOT)}")
    print(f"[ok] appended {len(new_records)} records -> "
          f"{os.path.relpath(MANIFEST_PATH, ROOT)} (existing records untouched)")
    return 0


def cmd_query(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run `ingest_official_repos.py run` first.")
        return 1
    hits = retrieve(chunks, args.query, k=args.k)
    print(f"query: {args.query!r}")
    for i, c in enumerate(hits, 1):
        snippet = re.sub(r"\s+", " ", c["text"])[:140]
        print(f"  {i}. [{c['doc_id']}] {snippet}...")
    return 0


# (query, acceptable repo slug or set of slugs)
SELFTEST = [
    ("What repository teaches nuclei-style vulnerability templates?", {"nuclei"}),
    ("What repository helps with crawling and URL discovery?", {"katana"}),
    ("What repository helps with HTTP probing?", {"httpx"}),
    ("What repository helps with attack surface discovery?", {"amass", "katana"}),
    ("What repository helps with secret detection?", {"gitleaks"}),
    ("What repository helps with static analysis rules?", {"semgrep"}),
    ("What repository documents MCP servers?", {"mcp-servers", "github-mcp-server"}),
    ("What repository documents Playwright MCP?", {"playwright-mcp"}),
    ("What repository explains LightRAG retrieval?", {"lightrag"}),
    ("Which repos are most relevant to scanner engine audits?",
     {"nuclei", "httpx", "katana", "amass", "gitleaks", "semgrep"}),
]


def cmd_selftest(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run `run` first.")
        return 1
    top1 = top3 = 0
    for q, want in SELFTEST:
        repos = retrieve_repos(chunks, q, k=3)
        if repos[:1] and repos[0] in want:
            top1 += 1
        if any(r in want for r in repos):
            top3 += 1
        mark = "OK " if any(r in want for r in repos) else "MISS"
        print(f"  [{mark}] want={'/'.join(sorted(want))[:34]:34s} got={repos}")
    n = len(SELFTEST)
    print(f"\n[selftest] top1={top1}/{n} top3={top3}/{n}")
    return 0 if top3 == n else 1


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 6B official security-repo ingestion")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="fetch + normalize + chunk + append (network)")
    r.add_argument("--dry-run", action="store_true", help="compute + report, write nothing")
    r.set_defaults(func=cmd_run)
    q = sub.add_parser("query", help="offline retrieval over committed chunks")
    q.add_argument("query")
    q.add_argument("-k", type=int, default=5)
    q.set_defaults(func=cmd_query)
    s = sub.add_parser("selftest", help="offline retrieval smoke test")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
