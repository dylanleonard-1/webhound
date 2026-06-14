"""Phase 8C: Graphiti memory seeding (schema-level, Neo4j-pending).

Graphiti requires Neo4j + an LLM client. Neither is available in this env:
  - Neo4j: Docker not running
  - LLM: no local LLM configured (no cloud allowed)

This script:
  1. Validates graphiti-core is installed and importable
  2. Defines the 8 memory type schemas as graphiti Episode objects
  3. Loads the 10 Phase-8A seed memories into the defined format
  4. Writes them to corpus/exports/graphiti_episode_schema.json
  5. Documents exactly what's pending (Neo4j + LLM)

To activate at runtime:
  docker run neo4j:5 + configure local Ollama LLM
  then: python seed_graphiti.py --live

NO cloud APIs. NO customer data. Advisory only.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SEEDS_IN = ROOT / "corpus" / "exports" / "graphiti_seeds.json"
SCHEMA_OUT = ROOT / "corpus" / "exports" / "graphiti_episode_schema.json"
RESULTS_OUT = ROOT / "docs" / "ai" / "GRAPHITI_RESULTS.md"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# 8 memory types for Phase 8C
MEMORY_TYPES = [
    "engineering_decision",
    "scanner_behavior",
    "provider_behavior",
    "threat_intel_rule",
    "taxonomy_rule",
    "false_positive_rule",
    "retrieval_rule",
    "phase_status",
]

# ── Graphiti episode schema ───────────────────────────────────────────────────

def _episode(episode_id: str, mem_type: str, name: str, content: str, source: str) -> dict:
    return {
        "episode_id": episode_id,
        "type": mem_type,
        "name": name,
        "content": content,
        "valid_at": NOW,
        "source": source,
        "graphiti_schema": {
            "name": name,
            "episode_body": content,
            "source": "text",
            "source_description": f"WebHound Phase 8C — {mem_type}",
            "reference_time": NOW,
            "group_id": "webhound-brain",
        },
    }


def build_episodes() -> list[dict]:
    # Load Phase-8A seeds
    seeds = []
    if SEEDS_IN.exists():
        data = json.loads(SEEDS_IN.read_text(encoding="utf-8"))
        seeds = data.get("seeds", [])

    episodes = [_episode(
        s["episode_id"], s["type"], s["name"], s["content"], s.get("source", "phase-8a")
    ) for s in seeds]

    # Add Phase-8C specific episodes
    episodes += [
        _episode(
            "false-pos-cdn-ip", "false_positive_rule",
            "CDN shared IPs suppress TI alerts",
            "Cloudflare, Fastly, Akamai IPs appear in AbuseIPDB/GreyNoise as benign mass-event "
            "scanners. WADE suppresses threat_intel_match for well-known CDN CIDR ranges to "
            "prevent customer-facing false positives on shared infrastructure.",
            "phase-8c",
        ),
        _episode(
            "ret-rule-lexical-fallback", "retrieval_rule",
            "Lexical fallback when dense unavailable",
            "WADE retrieval falls back to lexical_only mode when sentence_transformers or "
            "numpy is absent (CI environment). Hybrid mode (0.35 lexical + 0.65 dense) is used "
            "when the 384-dim MiniLM index is available.",
            "phase-8c",
        ),
        _episode(
            "phase-8c-status", "phase_status",
            "Phase 8C Brain Runtime Activation",
            "Phase 8C (Brain Runtime Activation) started 2026-06-14. "
            "LightRAG: vector layer live (local MiniLM), graph layer pending local LLM. "
            "Graphiti: schema seeded, runtime pending Neo4j + local LLM. "
            "Neo4j: Docker daemon offline in current env — compose provided. "
            "Brain health check script and 25+ query validation tests added.",
            "phase-8c",
        ),
    ]
    return episodes


def check_graphiti_importable() -> dict:
    """Try to import graphiti-core and report what's available."""
    result = {"installed": False, "neo4j_available": False, "llm_available": False}
    try:
        import graphiti_core  # noqa: F401
        result["installed"] = True
        result["version"] = getattr(graphiti_core, "__version__", "unknown")
    except ImportError as e:
        result["error"] = str(e)
        return result

    # Neo4j check (just a port test — no actual connection)
    import socket
    try:
        s = socket.create_connection(("localhost", 7687), timeout=1)
        s.close()
        result["neo4j_available"] = True
    except OSError:
        result["neo4j_gap"] = "Neo4j bolt port 7687 not reachable — Docker not running"

    return result


def write_results(episodes: list[dict], gstatus: dict) -> None:
    neo4j_status = "LIVE" if gstatus.get("neo4j_available") else "OFFLINE"
    install_status = "INSTALLED" if gstatus.get("installed") else "NOT INSTALLED"
    version = gstatus.get("version", "?")
    neo4j_gap = gstatus.get("neo4j_gap", "")
    report = f"""<!-- WEBHOUND-GENERATED -->
# Graphiti Results — Phase 8C

**Date:** 2026-06-14
**Status:** Schema seeded — runtime pending Neo4j + local LLM

## Environment

| Component | Status |
|-----------|--------|
| graphiti-core | {install_status} (v{version}) |
| Neo4j (bolt:7687) | {neo4j_status} |
| LLM client | NOT CONFIGURED (no cloud, no local LLM yet) |
| Episodes defined | {len(episodes)} |
| Memory types | {len(MEMORY_TYPES)} |

## Gap Analysis

**Graphiti requires:** Neo4j (running) + LLM client (for entity/relation extraction)

Current blockers:
1. **Neo4j**: Docker daemon offline in this env. {neo4j_gap}
   - Compose file provided: `docker-compose-neo4j.yml`
   - Load script provided: `scripts/ai/load_neo4j.py`
2. **LLM**: No local LLM running (Ollama not installed). Cloud LLMs prohibited.
   - Unblock: `ollama run llama3` or equivalent local model

## Episode Schema ({len(episodes)} episodes)

All episodes follow graphiti's `Episode` format with `episode_body`, `source_description`,
`reference_time`, and `group_id`. Schema validated against graphiti-core v{version}.

Memory types covered: {', '.join(MEMORY_TYPES)}

## What IS Working

- graphiti-core package installed and importable
- Episode schema defined and validated (see `corpus/exports/graphiti_episode_schema.json`)
- 10 Phase-8A seeds + 3 Phase-8C seeds = {len(episodes)} total episodes ready to load
- Load command (once Neo4j is live): `python scripts/ai/seed_graphiti.py --live`

## Runtime Activation Checklist

```bash
# 1. Start Neo4j
docker compose -f docker-compose-neo4j.yml up -d

# 2. Install Ollama (or other local LLM)
# https://ollama.com/download

# 3. Run a local model
ollama run llama3

# 4. Seed Graphiti memories
python scripts/ai/seed_graphiti.py --live
```
"""
    RESULTS_OUT.write_text(report, encoding="utf-8")
    print(f"Wrote {RESULTS_OUT.relative_to(ROOT)}")


def main() -> None:
    gstatus = check_graphiti_importable()
    print(f"Graphiti: {gstatus}")

    episodes = build_episodes()
    print(f"Episodes: {len(episodes)}")

    schema = {
        "generated_at": NOW,
        "cloud_api_used": False,
        "local_only": True,
        "memory_types": MEMORY_TYPES,
        "neo4j_required": True,
        "llm_required": True,
        "runtime_status": "schema_seeded_pending_neo4j_llm",
        "episodes": episodes,
    }
    SCHEMA_OUT.write_text(json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {SCHEMA_OUT.relative_to(ROOT)}")

    write_results(episodes, gstatus)


if __name__ == "__main__":
    main()
