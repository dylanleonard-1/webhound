# Graphify Setup

Graphify is not currently installed in this environment. This document describes how to install and use it to generate an interactive knowledge graph for the WebHound codebase.

## What Graphify Does

Graphify scans a project directory and generates an interactive HTML/JSON graph showing file relationships, import dependencies, and call chains. For WebHound, this would visualize:

- Connections between scanner engines, WADE, and the knowledge corpus
- Script dependency chains (`hybrid_retrieval.py` → `unified_chunks.jsonl` → `manifest.jsonl`)
- Test coverage relationships

## Installation

```bash
pip install graphify-python
# or
pipx install graphify-python
```

Verify:

```bash
graphify --version
```

## Usage

From the WebHound repo root:

```bash
# Generate interactive graph
graphify . --output vault/WebHound\ AI\ Brain/99-Graphify/graph.html

# Also export JSON for programmatic use
graphify . --output-json vault/WebHound\ AI\ Brain/99-Graphify/graph.json \
           --ignore ".venv*,node_modules,__pycache__,*.pyc"
```

## Recommended Filters

Exclude large generated files and non-source directories:

```bash
graphify scripts/ tests/ apps/web/src/ \
  --ignore ".venv*,node_modules,__pycache__,corpus/indexes/dense/*.npy" \
  --output vault/WebHound\ AI\ Brain/99-Graphify/graph.html
```

## Output Files

After running Graphify, commit only:
- `vault/WebHound AI Brain/99-Graphify/graph.html` — interactive viewer
- `vault/WebHound AI Brain/99-Graphify/graph.json` — raw graph data

Do NOT commit the `.npy` embedding files or large JSONL files through Graphify.

## Alternative: Dependency Visualization

If Graphify is not available, `pydeps` can visualize Python module dependencies:

```bash
pip install pydeps
pydeps scripts/ai/hybrid_retrieval.py --max-bacon 3 --show-deps
```
