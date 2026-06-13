#!/usr/bin/env bash
# WebHound AI Knowledge Layer — LightRAG prereq check (Phase 4).
#
# SAFE / READ-ONLY. Does NOT install anything, fetch anything, or touch .mcp.json /
# production. It reports whether LightRAG is available and prints the SAFE, LOCAL
# config it WOULD use. If LightRAG is missing it explains what's needed and the
# (un-run) install command, then exits 0 (graceful).
#
# Installing LightRAG is a SEPARATE, explicitly-approved step (see
# docs/ai/LIGHTRAG_SETUP.md). This script never force-installs.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PY="${PYTHON:-python}"

echo "LightRAG setup check (read-only; installs nothing)"
echo "Repo: ${REPO_ROOT}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "  [warn] python not found on PATH (set \$PYTHON). Cannot check LightRAG."
  exit 0
fi
echo "  [ ok ] python: $("$PY" --version 2>&1)"

if "$PY" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('lightrag') else 1)" 2>/dev/null; then
  echo "  [ ok ] LightRAG is importable."
  echo "         (Phase 4 still uses the mock local-retrieval path; no LLM call.)"
else
  echo "  [warn] LightRAG NOT installed — this is expected in Phase 4."
  echo "         Mock local retrieval is available now: python scripts/ai/query_knowledge.py --samples"
  echo "         To install LATER (only with explicit approval; confirm package name + license):"
  echo "           ${PY} -m pip install lightrag-hku   # name to confirm at install time"
fi

cat <<'EOF'

Safe local config the prototype WOULD use (shape only, not written here):
  - working dir : OS temp or a git-ignored path (never commit an index blob)
  - inputs      : knowledge/, corpus/normalized/, docs/ai/, vault/   (LOCAL only)
  - network     : none  | external embeddings: none by default
  - AI gating   : WEBHOUND_AI_ENABLED + ANTHROPIC_API_KEY (no second AI switch)
  - provenance  : every chunk keeps a pointer to its source path / manifest doc_id

This script changed nothing and installed nothing.
EOF
exit 0
