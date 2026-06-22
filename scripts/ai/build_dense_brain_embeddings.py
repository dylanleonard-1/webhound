"""Phase CONTROL-2D: build reproducible dense embeddings for the canonical brain.

Reads the CONTROL-2C canonical chunk set (corpus/index/canonical_chunks.jsonl —
regenerate first with build_canonical_brain_index.py if missing). Embeds with a
LOCAL sentence-transformers model. NO cloud API; no network once the model is
cached. Writes vectors + a small deterministic embeddings manifest.

The big vectors (.npy) are build artifacts (gitignored). The MANIFEST
(model, count, shape, content hash — small/deterministic) documents the build.

Usage:
  python scripts/ai/build_dense_brain_embeddings.py                 # full build
  python scripts/ai/build_dense_brain_embeddings.py --dry-run       # plan only
  python scripts/ai/build_dense_brain_embeddings.py --limit 25      # CI smoke
  python scripts/ai/build_dense_brain_embeddings.py --output-dir X  # custom out

Honesty: if sentence-transformers is not installed, this FAILS with an install
instruction (exit 3) — it never fabricates vectors.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL = ROOT / "corpus" / "index" / "canonical_chunks.jsonl"
DOC_CHUNKS = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
DEFAULT_OUT = ROOT / "corpus" / "index" / "dense"
MODEL_NAME = "all-MiniLM-L6-v2"
INSTALL_HINT = ("sentence-transformers not installed. Install it in the dev env:\n"
                "  .venv-api/Scripts/python -m pip install sentence-transformers\n"
                "Then re-run this script. (No vectors were written.)")


def _load_chunks() -> list[dict]:
    """Canonical chunks if present; else regenerate hint via doc chunks fallback."""
    if CANONICAL.exists():
        return [json.loads(l) for l in open(CANONICAL, encoding="utf-8") if l.strip()]
    # Canonical not built — fail loudly rather than embedding a stale/partial set.
    print("ERROR: canonical_chunks.jsonl missing. Run first:\n"
          "  python scripts/ai/build_canonical_brain_index.py", file=sys.stderr)
    raise SystemExit(4)


# CONTROL-2D CI gate: the 10 graded concepts -> source-path substrings. A
# concept-seeded shard MUST include every matching chunk so the >=8/10 gate is
# meaningful (a flat --limit shard cannot contain all concepts).
CI_SEED_MODULES = [
    "engines/cookies/cookie_scanner", "threat_intel/domain_classifier",
    "engines/tls_dns/tls_checker", "scanner/webhound/threat_intel",
    "scanner/webhound/wade/", "scripts/wade/", "scanner/webhound/core/orchestrator",
    "apps/api/services/verification", "apps/api/routers/auth", "apps/api/tests/test_auth",
    "scanner/webhound/reporting/",
]


def _select_seeded(chunks: list[dict], seeds: list[str], sample: int) -> list[dict]:
    """All chunks whose file_path matches any seed substring + a DETERMINISTIC
    strided sample of the rest (realistic distractors), capped near `sample`."""
    seeded, rest = [], []
    for c in chunks:
        fp = c.get("file_path", "")
        (seeded if any(s in fp for s in seeds) else rest).append(c)
    budget = max(0, sample - len(seeded))
    if budget and rest:
        stride = max(1, len(rest) // budget)
        sampled = rest[::stride][:budget]
    else:
        sampled = []
    # keep canonical order (stable, deterministic)
    keep_ids = {id(c) for c in seeded} | {id(c) for c in sampled}
    return [c for c in chunks if id(c) in keep_ids]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="embed only first N chunks (CI smoke)")
    ap.add_argument("--seed-modules", default="",
                    help="comma-separated source-path substrings to ALWAYS include; "
                         "use 'CI' for the built-in 10-concept set. Writes a self-contained shard.")
    ap.add_argument("--sample", type=int, default=1200,
                    help="approx total shard size when seeding (seeded chunks + strided sample)")
    ap.add_argument("--output-dir", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    chunks = _load_chunks()
    seeded_mode = bool(args.seed_modules)
    if seeded_mode:
        seeds = CI_SEED_MODULES if args.seed_modules.strip().upper() == "CI" \
            else [s.strip() for s in args.seed_modules.split(",") if s.strip()]
        chunks = _select_seeded(chunks, seeds, args.sample)
    elif args.limit > 0:
        chunks = chunks[:args.limit]
    n = len(chunks)
    n_code = sum(1 for c in chunks if c.get("source_type") == "production_code")
    print(f"chunks to embed: {n} (code={n_code}, doc={n - n_code}); model={MODEL_NAME}")

    if args.dry_run:
        print("[dry-run] no model load, no vectors written")
        return 0

    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print(f"ERROR: {INSTALL_HINT}", file=sys.stderr)
        return 3

    model = SentenceTransformer(MODEL_NAME)
    dim = model.get_sentence_embedding_dimension()
    texts = [c.get("text", "") for c in chunks]
    emb = model.encode(texts, batch_size=64, normalize_embeddings=True,
                       convert_to_numpy=True, show_progress_bar=False)

    out = Path(args.output_dir)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    np.save(str(out / "chunk_embeddings.npy"), emb)
    if seeded_mode:
        # Self-contained shard: write the matching chunk set so a retriever can
        # load chunks + vectors from this one dir (aligned 1:1) for the CI gate.
        with open(out / "canonical_chunks.jsonl", "w", encoding="utf-8") as fh:
            for c in chunks:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    # Per-chunk meta (aligns 1:1 with the .npy row order).
    meta = [{"idx": i, "chunk_id": c.get("chunk_id", ""),
             "file_path": c.get("file_path", ""), "source_type": c.get("source_type", "")}
            for i, c in enumerate(chunks)]
    (out / "chunk_embedding_meta.json").write_text(json.dumps(meta), encoding="utf-8")

    # Small deterministic manifest (safe to inspect / reason about; not the vectors).
    ids_hash = hashlib.sha256("\n".join(c.get("chunk_id", "") for c in chunks).encode()).hexdigest()[:16]
    manifest = {
        "schema": "webhound.brain.dense.v1",
        "model_name": MODEL_NAME,
        "model_full": f"sentence-transformers/{MODEL_NAME}",
        "embedding_dim": int(dim),
        "chunk_count": n,
        "code_chunks": n_code,
        "doc_chunks": n - n_code,
        "vector_shape": list(emb.shape),
        "normalized": True,
        "cloud_api_used": False,
        "limit": args.limit or None,
        "chunk_ids_hash": ids_hash,
        "vectors_file": "chunk_embeddings.npy",
        "vectors_committed": False,
        "rebuild_cmd": "python scripts/ai/build_dense_brain_embeddings.py",
    }
    (out / "embeddings_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        where = out.relative_to(ROOT)
    except ValueError:
        where = out
    print(f"wrote vectors {emb.shape} + manifest -> {where}/ (vectors gitignored, manifest small)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
