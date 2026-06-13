"""Phase 6A — tests for ingested official Tier-A security docs (OWASP + MDN).

All tests are OFFLINE: they read the committed normalized artifacts + manifest
records. No network, matching the CI workflow which installs only pytest +
jsonschema. The ingestion itself (network) is a one-time, locally-run step.
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "docs", "official")
CHUNKS = os.path.join(NORM_DIR, "official_chunks.jsonl")

EXPECTED_DOC_IDS = {
    "owasp-wstg-readme", "owasp-csp-cheat-sheet", "owasp-asvs-readme",
    "mdn-csp-guide", "mdn-cors-guide", "mdn-subresource-integrity",
}
ALLOWED_LICENSES = {"CC-BY-SA-4.0", "CC-BY-SA-2.5"}


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "ingest_official_docs",
        os.path.join(ROOT, "scripts", "ai", "ingest_official_docs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _official_records():
    if not os.path.exists(MANIFEST):
        return None
    rows = [json.loads(l) for l in open(MANIFEST, encoding="utf-8") if l.strip()]
    return [r for r in rows if r.get("source_type") == "official_doc"]


def _require(records):
    if records is None:
        pytest.skip("manifest.jsonl not present")
    if not records:
        pytest.skip("no official_doc records ingested yet")


# ---- manifest record shape -------------------------------------------------
def test_all_expected_official_docs_present():
    recs = _official_records()
    _require(recs)
    ids = {r["doc_id"] for r in recs}
    assert EXPECTED_DOC_IDS.issubset(ids), f"missing: {EXPECTED_DOC_IDS - ids}"


def test_official_records_are_tier_a_canonical():
    recs = _official_records()
    _require(recs)
    for r in recs:
        assert r["authority_tier"] == "A", r["doc_id"]
        assert r["source_type"] == "official_doc", r["doc_id"]
        assert r["doc_role"] in {"canonical_note", "policy_doc"}, r["doc_id"]
        assert r["pii_risk_class"] == "none", r["doc_id"]


def test_official_records_have_external_source_and_license():
    recs = _official_records()
    _require(recs)
    for r in recs:
        assert r["source_url"].startswith("https://"), r["doc_id"]
        assert r["license_terms"] in ALLOWED_LICENSES, (r["doc_id"], r["license_terms"])
        # provenance: pinned commit recorded in `version`
        assert r.get("version"), f"{r['doc_id']} not pinned to a commit"


def test_official_records_validate_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    recs = _official_records()
    _require(recs)
    schema = json.load(open(os.path.join(ROOT, "corpus", "manifests",
                                         "manifest.schema.json"), encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    errors = [f"{r['doc_id']}: {e.message}" for r in recs for e in v.iter_errors(r)]
    assert errors == [], errors[:5]


# ---- committed normalized artifacts ---------------------------------------
def test_every_official_record_has_normalized_artifact():
    recs = _official_records()
    _require(recs)
    for r in recs:
        p = os.path.join(NORM_DIR, f"{r['doc_id']}.md")
        assert os.path.exists(p), f"missing normalized artifact for {r['doc_id']}"
        assert os.path.getsize(p) > 0, f"empty normalized artifact for {r['doc_id']}"


def test_chunks_map_to_official_records():
    recs = _official_records()
    _require(recs)
    if not os.path.exists(CHUNKS):
        pytest.skip("official_chunks.jsonl not present")
    ids = {r["doc_id"] for r in recs}
    chunks = [json.loads(l) for l in open(CHUNKS, encoding="utf-8") if l.strip()]
    assert chunks, "no chunks committed"
    orphans = [c["chunk_id"] for c in chunks if c["doc_id"] not in ids]
    assert orphans == [], f"orphan chunks: {orphans[:5]}"
    # each doc contributes at least one chunk
    covered = {c["doc_id"] for c in chunks}
    assert ids.issubset(covered), f"docs without chunks: {ids - covered}"


# ---- retrieval (offline, over committed chunks) ---------------------------
def test_retrieval_finds_right_doc_for_topic_queries():
    mod = _load_module()
    chunks = mod.load_chunks()
    if not chunks:
        pytest.skip("no committed chunks")
    cases = [
        ("What is Content Security Policy?", "mdn-csp-guide"),
        ("How does Cross-Origin Resource Sharing work?", "mdn-cors-guide"),
        ("What is Subresource Integrity integrity attribute?", "mdn-subresource-integrity"),
        ("OWASP web security testing guide methodology", "owasp-wstg-readme"),
        ("Application Security Verification Standard requirements", "owasp-asvs-readme"),
        ("CSP cheat sheet nonce hash directives", "owasp-csp-cheat-sheet"),
    ]
    misses = []
    for q, want in cases:
        ids = [h["doc_id"] for h in mod.retrieve(chunks, q, k=3)]
        if want not in ids:
            misses.append((q, want, ids))
    assert misses == [], f"retrieval misses (top-3): {misses}"
