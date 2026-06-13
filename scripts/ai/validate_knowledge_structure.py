#!/usr/bin/env python3
"""Validate the AI Knowledge Layer structure (Phase 4).

LOCAL + READ-ONLY. No network, no installs, no secrets, no production DB. Checks:
  * corpus/manifests/manifest.schema.json parses (+ valid JSON Schema if jsonschema
    is available; + a sample record passes and an invalid one fails)
  * every knowledge/ directory has a README.md (or index.md)
  * every corpus/ top-level directory has a README.md
  * the env generator emits the 3 current scanner IPs and NOT the dead 152.55.180.27
  * .mcp.json still defines only the expected server(s) (proxy for "unmodified")

Exit 0 if all pass, 1 otherwise. Usage: python scripts/ai/validate_knowledge_structure.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

DEAD_IP = "152.55.180.27"
LIVE_IPS = ("162.220.234.240", "152.55.180.240", "152.55.180.241")

_problems: list[str] = []
_passes: list[str] = []


def ok(msg: str) -> None:
    _passes.append(msg)


def bad(msg: str) -> None:
    _problems.append(msg)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def check_manifest_schema() -> None:
    p = os.path.join(ROOT, "corpus", "manifests", "manifest.schema.json")
    if not os.path.exists(p):
        bad("manifest.schema.json missing")
        return
    try:
        schema = json.loads(_read(p))
    except Exception as e:  # noqa: BLE001
        bad(f"manifest.schema.json invalid JSON: {e}")
        return
    req = set(schema.get("required", []))
    props = set(schema.get("properties", {}))
    if req - props:
        bad(f"manifest schema: required not in properties: {sorted(req - props)}")
    else:
        ok("manifest schema: required[] subset of properties[]")

    sample = {
        "doc_id": "x", "title": "t", "source_name": "s", "source_url": "u",
        "source_type": "official_doc", "authority_tier": "A", "language": "en",
        "topic_tags": [], "version": None, "last_updated": None,
        "first_ingested": "2026-01-01", "content_hash": "sha256:0",
        "confidence_score": 0.9, "verification_status": "verified",
        "license_terms": "unknown", "pii_risk_class": "none",
        "retention_class": "long", "related_docs": [],
    }
    try:
        import jsonschema  # type: ignore
        jsonschema.Draft202012Validator.check_schema(schema)
        ok("manifest schema: valid JSON Schema (Draft 2020-12)")
        jsonschema.validate(sample, schema)
        ok("manifest schema: sample valid record passes")
        try:
            jsonschema.validate({**sample, "authority_tier": "Z"}, schema)
            bad("manifest schema: invalid authority_tier was NOT rejected")
        except jsonschema.ValidationError:
            ok("manifest schema: invalid authority_tier correctly rejected")
    except ImportError:
        ok("manifest schema: parsed (jsonschema not installed — structural check only)")


def check_dir_readmes(top: str) -> None:
    base = os.path.join(ROOT, top)
    if not os.path.isdir(base):
        bad(f"{top}/ missing")
        return
    missing = []
    for dirpath, _dirs, files in os.walk(base):
        if "README.md" not in files and "index.md" not in files:
            missing.append(os.path.relpath(dirpath, ROOT))
    if missing:
        bad(f"{top}: dirs without README/index: {missing}")
    else:
        ok(f"{top}: every directory has a README/index")


def check_corpus_top_readmes() -> None:
    base = os.path.join(ROOT, "corpus")
    if not os.path.isdir(base):
        bad("corpus/ missing")
        return
    missing = [d for d in os.listdir(base)
               if os.path.isdir(os.path.join(base, d))
               and not os.path.exists(os.path.join(base, d, "README.md"))]
    if missing:
        bad(f"corpus: top-level dirs without README: {missing}")
    else:
        ok("corpus: every top-level directory has a README")


def check_scanner_ips() -> None:
    """Import the env generator and check its ROOT template (the source of truth)."""
    gen = os.path.join(ROOT, "scripts", "_gen_env_example.py")
    if not os.path.exists(gen):
        bad("scripts/_gen_env_example.py missing")
        return
    src = _read(gen)
    # The dead IP appears ONLY inside the FORBIDDEN_STRINGS guard, never in ROOT.
    # Verify via the generated ROOT string by importing the module.
    import importlib.util
    spec = importlib.util.spec_from_file_location("_gen_env_example", gen)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    root = getattr(mod, "ROOT", "")
    if DEAD_IP in root:
        bad(f"env generator ROOT contains dead IP {DEAD_IP}")
    else:
        ok(f"env generator: dead IP {DEAD_IP} absent from generated output")
    if all(ip in root for ip in LIVE_IPS):
        ok("env generator: all 3 current scanner IPs present")
    else:
        bad("env generator: a current scanner IP is missing")
    _ = src  # kept for clarity


def check_mcp_json() -> None:
    p = os.path.join(ROOT, ".mcp.json")
    if not os.path.exists(p):
        bad(".mcp.json missing")
        return
    try:
        cfg = json.loads(_read(p))
    except Exception as e:  # noqa: BLE001
        bad(f".mcp.json invalid JSON: {e}")
        return
    servers = set((cfg.get("mcpServers") or {}).keys())
    # Phase 1-4 must not have added MCP servers; only claude-flow is expected.
    if servers == {"claude-flow"}:
        ok(".mcp.json: only the expected 'claude-flow' server (unmodified by the knowledge layer)")
    else:
        bad(f".mcp.json: unexpected MCP servers present: {sorted(servers)}")


def main() -> int:
    check_manifest_schema()
    check_dir_readmes("knowledge")
    check_dir_readmes("vault")
    check_corpus_top_readmes()
    check_scanner_ips()
    check_mcp_json()

    for m in _passes:
        print(f"  [ ok ] {m}")
    for m in _problems:
        print(f"  [FAIL] {m}")
    print(f"\n{len(_passes)} ok, {len(_problems)} failure(s).")
    return 1 if _problems else 0


if __name__ == "__main__":
    sys.exit(main())
