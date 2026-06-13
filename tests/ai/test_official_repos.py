"""Phase 6B — tests for ingested official security repositories (Tier C).

All tests are OFFLINE: they read the committed normalized artifacts + manifest
records. No network, matching the CI workflow (pytest + jsonschema only). The
ingestion itself (network) is a one-time, locally-run step.
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "repos")
CHUNKS = os.path.join(NORM_DIR, "repo_chunks.jsonl")

# The approved Phase-6B repository set (manifest source_name = owner/name).
EXPECTED_REPOS = {
    "projectdiscovery/nuclei", "projectdiscovery/httpx", "projectdiscovery/katana",
    "owasp-amass/amass", "gitleaks/gitleaks", "semgrep/semgrep",
    "modelcontextprotocol/servers", "microsoft/playwright-mcp",
    "github/github-mcp-server", "HKUDS/LightRAG",
}
# Licenses confirmed at ingestion (see docs/ai/PHASE6B_RESULTS.md).
ALLOWED_LICENSES = {"MIT", "Apache-2.0", "LGPL-2.1", "CC-BY-4.0"}

# (query, acceptable repo slug(s)) — repo discovery for future scanner audits.
RETRIEVAL_CASES = [
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


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "ingest_official_repos",
        os.path.join(ROOT, "scripts", "ai", "ingest_official_repos.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _repo_records():
    if not os.path.exists(MANIFEST):
        return None
    rows = [json.loads(l) for l in open(MANIFEST, encoding="utf-8") if l.strip()]
    return [r for r in rows if r.get("source_type") == "official_repo"]


def _require(records):
    if records is None:
        pytest.skip("manifest.jsonl not present")
    if not records:
        pytest.skip("no official_repo records ingested yet")


# ---- manifest record shape -------------------------------------------------
def test_all_expected_repos_present():
    recs = _repo_records()
    _require(recs)
    repos = {r["source_name"] for r in recs}
    assert EXPECTED_REPOS.issubset(repos), f"missing repos: {EXPECTED_REPOS - repos}"


def test_repo_records_are_tier_c_official_repo():
    recs = _repo_records()
    _require(recs)
    for r in recs:
        assert r["authority_tier"] == "C", r["doc_id"]
        assert r["source_type"] == "official_repo", r["doc_id"]
        assert r["doc_role"] in {"engine_note", "canonical_note"}, r["doc_id"]
        assert r["pii_risk_class"] == "none", r["doc_id"]
        assert "github-repo" in r["topic_tags"], r["doc_id"]


def test_repo_records_have_external_source_pin_and_license():
    recs = _repo_records()
    _require(recs)
    for r in recs:
        assert r["source_url"].startswith("https://raw.githubusercontent.com/"), r["doc_id"]
        assert r["license_terms"] in ALLOWED_LICENSES, (r["doc_id"], r["license_terms"])
        assert r.get("version"), f"{r['doc_id']} not pinned to a commit"


def test_repo_records_validate_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    recs = _repo_records()
    _require(recs)
    schema = json.load(open(os.path.join(ROOT, "corpus", "manifests",
                                         "manifest.schema.json"), encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    errors = [f"{r['doc_id']}: {e.message}" for r in recs for e in v.iter_errors(r)]
    assert errors == [], errors[:5]


# ---- committed normalized artifacts ---------------------------------------
def test_every_repo_record_has_normalized_artifact():
    recs = _repo_records()
    _require(recs)
    for r in recs:
        p = os.path.join(NORM_DIR, f"{r['doc_id']}.md")
        assert os.path.exists(p), f"missing normalized artifact for {r['doc_id']}"
        assert os.path.getsize(p) > 0, f"empty normalized artifact for {r['doc_id']}"


def test_no_raw_repo_clone_committed():
    """Phase 6B commits NORMALIZED text only — never a mirrored source tree."""
    # the normalized dir holds only flat <doc_id>.md + the chunks/summary files.
    for name in os.listdir(NORM_DIR):
        path = os.path.join(NORM_DIR, name)
        if os.path.isdir(path):
            pytest.fail(f"unexpected nested dir (possible repo clone): {name}")
    # source-code extensions must not have been ingested as artifacts.
    bad = [n for n in os.listdir(NORM_DIR)
           if n.endswith((".go", ".py", ".js", ".ts", ".rs", ".java"))]
    assert bad == [], f"source files committed under normalized/repos: {bad}"


def test_chunks_map_to_repo_records():
    recs = _repo_records()
    _require(recs)
    if not os.path.exists(CHUNKS):
        pytest.skip("repo_chunks.jsonl not present")
    ids = {r["doc_id"] for r in recs}
    chunks = [json.loads(l) for l in open(CHUNKS, encoding="utf-8") if l.strip()]
    assert chunks, "no chunks committed"
    orphans = [c["chunk_id"] for c in chunks if c["doc_id"] not in ids]
    assert orphans == [], f"orphan chunks: {orphans[:5]}"
    covered = {c["doc_id"] for c in chunks}
    assert ids.issubset(covered), f"records without chunks: {ids - covered}"


# ---- retrieval (offline, repo discovery over committed chunks) -------------
def test_retrieval_finds_right_repo_for_topic_queries():
    mod = _load_module()
    chunks = mod.load_chunks()
    if not chunks:
        pytest.skip("no committed chunks")
    misses = []
    for q, want in RETRIEVAL_CASES:
        repos = mod.retrieve_repos(chunks, q, k=3)
        if not any(r in want for r in repos):
            misses.append((q, sorted(want), repos))
    assert misses == [], f"retrieval misses (top-3): {misses}"
