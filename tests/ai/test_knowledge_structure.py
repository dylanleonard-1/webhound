"""AI Knowledge Layer structure tests (Phase 4).

Tiny, dependency-light structural/schema validation — the start of closing the
no-CI gap. LOCAL + READ-ONLY: no network, no DB, no installs, no scanner/WADE/
provider-access behavior touched.

Run:
  apps/api venv (has jsonschema):  .venv-api/Scripts/python -m pytest tests/ai -q
  or standalone:                   python tests/ai/test_knowledge_structure.py
"""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

DEAD_IP = "152.55.180.27"
LIVE_IPS = ("162.220.234.240", "152.55.180.240", "152.55.180.241")

SAMPLE = {
    "doc_id": "x", "title": "t", "source_name": "s", "source_url": "u",
    "source_type": "official_doc", "authority_tier": "A", "language": "en",
    "topic_tags": [], "version": None, "last_updated": None,
    "first_ingested": "2026-01-01", "content_hash": "sha256:0",
    "confidence_score": 0.9, "verification_status": "verified",
    "license_terms": "unknown", "pii_risk_class": "none",
    "retention_class": "long", "related_docs": [],
}


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _schema() -> dict:
    return json.loads(_read("corpus", "manifests", "manifest.schema.json"))


def _load_generator():
    gen = os.path.join(ROOT, "scripts", "_gen_env_example.py")
    spec = importlib.util.spec_from_file_location("_gen_env_example", gen)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_manifest_schema_is_valid_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(_schema())


def test_sample_valid_manifest_record_passes():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(SAMPLE, _schema())


def test_invalid_authority_tier_fails():
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**SAMPLE, "authority_tier": "Z"}, _schema())


def test_required_fields_subset_of_properties():
    s = _schema()
    assert set(s["required"]).issubset(set(s["properties"]))


def test_every_knowledge_dir_has_readme():
    base = os.path.join(ROOT, "knowledge")
    missing = [
        os.path.relpath(dp, ROOT)
        for dp, _d, files in os.walk(base)
        if "README.md" not in files and "index.md" not in files
    ]
    assert missing == [], f"knowledge dirs without README/index: {missing}"


def test_every_vault_dir_has_readme_or_index():
    base = os.path.join(ROOT, "vault")
    missing = [
        os.path.relpath(dp, ROOT)
        for dp, _d, files in os.walk(base)
        if "README.md" not in files and "index.md" not in files
    ]
    assert missing == [], f"vault dirs without README/index: {missing}"


def test_every_corpus_top_dir_has_readme():
    base = os.path.join(ROOT, "corpus")
    missing = [
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d))
        and not os.path.exists(os.path.join(base, d, "README.md"))
    ]
    assert missing == [], f"corpus top-level dirs without README: {missing}"


def test_dead_scanner_ip_absent_from_generated_env():
    mod = _load_generator()
    assert DEAD_IP not in mod.ROOT, "dead scanner IP must not be in generated env output"


def test_current_scanner_ips_present():
    mod = _load_generator()
    for ip in LIVE_IPS:
        assert ip in mod.ROOT, f"current scanner IP missing from generated env: {ip}"


def test_mcp_json_only_expected_servers():
    cfg = json.loads(_read(".mcp.json"))
    servers = set((cfg.get("mcpServers") or {}).keys())
    assert servers == {"claude-flow"}, f"unexpected MCP servers in .mcp.json: {sorted(servers)}"


def _manifest_records():
    p = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
    if not os.path.exists(p):
        return None
    rows = []
    for line in _read("corpus", "manifests", "manifest.jsonl").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def test_manifest_jsonl_every_record_validates():
    """Phase 5A: every internal-ingestion manifest record validates against the schema."""
    rows = _manifest_records()
    if rows is None:
        pytest.skip("manifest.jsonl not present")
    jsonschema = pytest.importorskip("jsonschema")
    schema = _schema()
    v = jsonschema.Draft202012Validator(schema)
    errors = []
    for r in rows:
        for e in v.iter_errors(r):
            errors.append(f"{r.get('doc_id','?')}: {e.message}")
    assert errors == [], f"manifest.jsonl schema errors: {errors[:5]}"


def test_manifest_jsonl_doc_ids_unique_and_pointers_local():
    rows = _manifest_records()
    if rows is None:
        pytest.skip("manifest.jsonl not present")
    ids = [r["doc_id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate doc_id in manifest.jsonl"
    # source_url is a repo-relative local pointer that exists (no external/orphan refs)
    missing = [r["doc_id"] for r in rows if not os.path.exists(os.path.join(ROOT, r["source_url"]))]
    assert missing == [], f"manifest records pointing to missing local files: {missing[:5]}"


def test_memory_summaries_pointers_exist_and_no_secrets():
    p = os.path.join(ROOT, "corpus", "manifests", "memory_summaries.jsonl")
    if not os.path.exists(p):
        pytest.skip("memory_summaries.jsonl not present")
    forbidden = ("sk-", "ghp_", "gho_", "password", "api_key=")
    for line in _read("corpus", "manifests", "memory_summaries.jsonl").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        blob = json.dumps(rec).lower()
        assert not any(f in blob for f in forbidden), f"forbidden token in memory {rec.get('memory_id')}"
        for path in rec.get("related_paths", []):
            assert os.path.exists(os.path.join(ROOT, path.rstrip("/"))), f"memory pointer missing: {path}"


if __name__ == "__main__":
    # Standalone runner (no pytest): run the non-jsonschema checks + best-effort schema.
    failures = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  [ ok ] {name}")
            except Exception as e:  # noqa: BLE001
                # importorskip raises Skipped when jsonschema missing — treat as skip
                if e.__class__.__name__ in ("Skipped", "OutcomeException"):
                    print(f"  [skip] {name} (jsonschema not installed)")
                else:
                    failures.append(name)
                    print(f"  [FAIL] {name}: {e}")
    raise SystemExit(1 if failures else 0)
