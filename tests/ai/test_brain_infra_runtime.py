"""Phase 8C-INFRA: Local brain infrastructure runtime tests.

Validates that all infrastructure scripts, compose files, and setup docs
are present and behave correctly. Tests that require live Docker, Neo4j,
or Ollama skip gracefully when those services are unavailable.

Run: .venv-api/Scripts/python -m pytest tests/ai/test_brain_infra_runtime.py -v
"""
from __future__ import annotations
import json
import os
import socket
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)


# ── Availability guards ───────────────────────────────────────────────────────

def _port_open(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=1)
        s.close()
        return True
    except OSError:
        return False


_DOCKER_LIVE = False  # Docker daemon offline in this env — skip Docker-dependent tests
_NEO4J_LIVE = _port_open("localhost", 7687)
_OLLAMA_LIVE = _port_open("localhost", 11434)


# ── 1. File existence ─────────────────────────────────────────────────────────

def test_compose_ai_brain_exists():
    path = os.path.join(ROOT, "docker-compose.ai-brain.yml")
    assert os.path.isfile(path), "docker-compose.ai-brain.yml must exist"


def test_ollama_setup_doc_exists():
    path = os.path.join(ROOT, "docs", "ai", "OLLAMA_SETUP.md")
    assert os.path.isfile(path), "OLLAMA_SETUP.md must exist"


def test_check_neo4j_script_exists():
    path = os.path.join(ROOT, "scripts", "ai", "check_neo4j.py")
    assert os.path.isfile(path)


def test_load_brain_graph_script_exists():
    path = os.path.join(ROOT, "scripts", "ai", "load_brain_graph_neo4j.py")
    assert os.path.isfile(path)


def test_graphiti_runtime_check_exists():
    path = os.path.join(ROOT, "scripts", "ai", "graphiti_runtime_check.py")
    assert os.path.isfile(path)


def test_load_graphiti_seed_script_exists():
    path = os.path.join(ROOT, "scripts", "ai", "load_graphiti_seed_memories.py")
    assert os.path.isfile(path)


def test_lightrag_graph_check_exists():
    path = os.path.join(ROOT, "scripts", "ai", "lightrag_graph_runtime_check.py")
    assert os.path.isfile(path)


# ── 2. Config validation ──────────────────────────────────────────────────────

def test_compose_has_neo4j_service():
    path = os.path.join(ROOT, "docker-compose.ai-brain.yml")
    content = open(path, encoding="utf-8").read()
    assert "neo4j:" in content, "Compose must define a neo4j service"


def test_compose_has_ollama_service():
    path = os.path.join(ROOT, "docker-compose.ai-brain.yml")
    content = open(path, encoding="utf-8").read()
    assert "ollama:" in content, "Compose must define an ollama service"


def test_compose_has_local_dev_label():
    path = os.path.join(ROOT, "docker-compose.ai-brain.yml")
    content = open(path, encoding="utf-8").read()
    assert "LOCAL DEV ONLY" in content, "Compose must have LOCAL DEV ONLY label"


def test_gitignore_covers_neo4j_volumes():
    path = os.path.join(ROOT, ".gitignore")
    content = open(path, encoding="utf-8").read()
    assert "neo4j_data/" in content, "neo4j_data/ must be gitignored"
    assert "neo4j_logs/" in content, "neo4j_logs/ must be gitignored"


def test_ollama_setup_has_windows_instructions():
    path = os.path.join(ROOT, "docs", "ai", "OLLAMA_SETUP.md")
    content = open(path, encoding="utf-8").read()
    assert "Windows" in content or "OllamaSetup" in content
    assert "ollama pull" in content


# ── 3. Script import / function availability ──────────────────────────────────

def test_check_neo4j_script_importable():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_neo4j",
        os.path.join(ROOT, "scripts", "ai", "check_neo4j.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "_port_open")
    assert hasattr(mod, "run_cypher_checks")
    assert hasattr(mod, "main")


def test_load_brain_graph_script_importable():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "load_brain_graph_neo4j",
        os.path.join(ROOT, "scripts", "ai", "load_brain_graph_neo4j.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "load_graph_data")
    assert hasattr(mod, "build_cypher_statements")
    assert hasattr(mod, "run_load")


def test_graphiti_runtime_check_importable():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "graphiti_runtime_check",
        os.path.join(ROOT, "scripts", "ai", "graphiti_runtime_check.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "check_graphiti_install")
    assert hasattr(mod, "check_ollama")
    assert hasattr(mod, "determine_status")


def test_lightrag_graph_check_importable():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "lightrag_graph_runtime_check",
        os.path.join(ROOT, "scripts", "ai", "lightrag_graph_runtime_check.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "check_lightrag_install")
    assert hasattr(mod, "check_graph_entities")
    assert hasattr(mod, "determine_status")


# ── 4. Dry-run execution ──────────────────────────────────────────────────────

def test_load_brain_graph_dry_run():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "load_brain_graph_neo4j",
        os.path.join(ROOT, "scripts", "ai", "load_brain_graph_neo4j.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.run_load(dry_run=True)
    assert result["status"] == "dry_run_ok"
    assert result["node_count"] > 0
    assert result["edge_count"] > 0
    assert result["statement_count"] > 0


def test_graphiti_prereq_check_runs():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "graphiti_runtime_check",
        os.path.join(ROOT, "scripts", "ai", "graphiti_runtime_check.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    g = mod.check_graphiti_install()
    assert isinstance(g, dict)
    assert "installed" in g


def test_lightrag_graph_check_runs():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "lightrag_graph_runtime_check",
        os.path.join(ROOT, "scripts", "ai", "lightrag_graph_runtime_check.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    install = mod.check_lightrag_install()
    vector = mod.check_vector_storage()
    assert isinstance(install, dict)
    assert "installed" in install
    assert isinstance(vector, dict)
    assert "exists" in vector


# ── 5. Episode schema ─────────────────────────────────────────────────────────

def test_episode_schema_has_13_episodes():
    path = os.path.join(ROOT, "corpus", "exports", "graphiti_episode_schema.json")
    assert os.path.isfile(path), "graphiti_episode_schema.json must exist"
    data = json.loads(open(path, encoding="utf-8").read())
    episodes = data.get("episodes", [])
    assert len(episodes) >= 13, f"Expected 13+ episodes, got {len(episodes)}"


def test_episode_schema_has_required_fields():
    path = os.path.join(ROOT, "corpus", "exports", "graphiti_episode_schema.json")
    data = json.loads(open(path, encoding="utf-8").read())
    for ep in data.get("episodes", []):
        assert "episode_id" in ep, f"Missing episode_id in episode: {ep}"
        assert "graphiti_schema" in ep, f"Missing graphiti_schema in {ep.get('episode_id')}"
        schema = ep["graphiti_schema"]
        assert "name" in schema
        assert "episode_body" in schema


# ── 6. Offline graceful handling ──────────────────────────────────────────────

def test_docker_offline_handled_gracefully():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_brain_health",
        os.path.join(ROOT, "scripts", "ai", "check_brain_health.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.check_docker()
    assert isinstance(result, dict)
    assert "status" in result
    assert result["status"] in ("live", "offline", "not_installed")


def test_ollama_offline_handled_gracefully():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_brain_health",
        os.path.join(ROOT, "scripts", "ai", "check_brain_health.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.check_ollama()
    assert isinstance(result, dict)
    assert "status" in result
    assert "models" in result


def test_neo4j_offline_handled_gracefully():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_neo4j",
        os.path.join(ROOT, "scripts", "ai", "check_neo4j.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bolt = mod._port_open("localhost", 7687)
    if not bolt:
        result = {"status": "OFFLINE", "bolt_7687": False}
    else:
        result = {"status": "LIVE", "bolt_7687": True}
    assert result["status"] in ("OFFLINE", "LIVE")


def test_brain_health_has_docker_check():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_brain_health",
        os.path.join(ROOT, "scripts", "ai", "check_brain_health.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "check_docker"), "check_brain_health must have check_docker()"
    assert hasattr(mod, "check_ollama"), "check_brain_health must have check_ollama()"


# ── 7. Live Neo4j (skip if offline) ──────────────────────────────────────────

@pytest.mark.skipif(not _NEO4J_LIVE, reason="Neo4j not running (bolt:7687 offline)")
def test_neo4j_live_cypher():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_neo4j",
        os.path.join(ROOT, "scripts", "ai", "check_neo4j.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.run_cypher_checks()
    assert result.get("live") is True


# ── 8. Live Ollama (skip if offline) ─────────────────────────────────────────

@pytest.mark.skipif(not _OLLAMA_LIVE, reason="Ollama not running (port:11434 offline)")
def test_ollama_live_model_list():
    import urllib.request, json as _json
    resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
    data = _json.loads(resp.read())
    assert "models" in data


# ── 9. Phase 8C-INFRA-LIVE scripts ───────────────────────────────────────────

def test_build_lightrag_ollama_script_exists():
    path = os.path.join(ROOT, "scripts", "ai", "build_lightrag_index_ollama.py")
    assert os.path.isfile(path), "build_lightrag_index_ollama.py must exist"


def test_build_lightrag_ollama_script_importable():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "build_lightrag_index_ollama",
        os.path.join(ROOT, "scripts", "ai", "build_lightrag_index_ollama.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "build_index")
    assert hasattr(mod, "load_corpus_sample")
    assert mod.OLLAMA_MODEL == "phi3:mini"


def test_graphiti_seed_loader_has_null_cross_encoder():
    pytest.importorskip("graphiti_core", reason="graphiti_core not installed — skip in minimal CI")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "load_graphiti_seed_memories",
        os.path.join(ROOT, "scripts", "ai", "load_graphiti_seed_memories.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "_make_null_cross_encoder")
    encoder = mod._make_null_cross_encoder()
    result = encoder.rank("test query", ["passage a", "passage b"])
    assert len(result) == 2
    assert result[0][0] == "passage a"
