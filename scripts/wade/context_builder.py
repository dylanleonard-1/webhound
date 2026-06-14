"""Phase 8B: WADE reasoning context builder.

Assembles a ReasoningContext struct from retrieval service outputs for a
given finding type and optional provider. Advisory only — the context is
read-only enrichment data; it does not alter production scoring.
"""
from __future__ import annotations
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.wade.taxonomy_resolver import resolve_taxonomy, SUPPORTED_FINDING_TYPES
from scripts.wade.false_positive_resolver import (
    resolve_fp_patterns, resolve_fp_notes,
)
from scripts.wade.language_resolver import resolve_customer_language
from scripts.wade.retrieval_service import WADERetrievalService, load_wade_retrieval_service
from scripts.wade.provider_resolver import normalize_provider, get_provider_name

BRAIN_VERSION = "8B"


@dataclass
class ReasoningContext:
    """Read-only advisory context assembled from the WADE knowledge base.

    All fields are populated from local retrieval — no cloud APIs, no
    production scoring modification.
    """
    finding_type: str
    retrieved_sources: list[dict] = field(default_factory=list)
    provider_context: list[dict] = field(default_factory=list)
    taxonomy_context: dict[str, str] = field(default_factory=dict)
    threat_intel_context: list[dict] = field(default_factory=list)
    false_positive_context: list[dict] = field(default_factory=list)
    customer_safe_language: dict[str, str] = field(default_factory=dict)
    supporting_chunks: list[dict] = field(default_factory=list)
    authority_tiers: list[str] = field(default_factory=list)
    reasoning_summary: str = ""
    retrieval_confidence: float = 0.0
    brain_version: str = BRAIN_VERSION
    created_at: str = ""

    # extra optional fields
    false_positive_patterns: list[str] = field(default_factory=list)
    false_positive_notes: str = ""
    provider_name: str | None = None


def _compute_confidence(
    security_results: list[dict],
    taxonomy: dict[str, str],
    finding_type: str,
) -> float:
    """Estimate retrieval confidence: 0.0–1.0 based on result quality."""
    if not security_results:
        return 0.0
    top_score = security_results[0].get("score", 0.0)
    has_taxonomy = taxonomy.get("cwe") not in ("CWE-unknown", None, "")
    is_known_type = finding_type in SUPPORTED_FINDING_TYPES
    base = min(top_score, 1.0)
    bonus = (0.2 if has_taxonomy else 0.0) + (0.1 if is_known_type else 0.0)
    return round(min(base + bonus, 1.0), 3)


def _build_summary(
    finding_type: str,
    taxonomy: dict[str, str],
    fp_patterns: list[str],
    provider: str | None,
    n_chunks: int,
) -> str:
    cwe = taxonomy.get("cwe", "unknown")
    owasp = taxonomy.get("owasp", "unknown")
    severity = taxonomy.get("severity_guidance", "")
    provider_part = f" for provider={provider}" if provider else ""
    fp_note = f" {len(fp_patterns)} known FP pattern(s)." if fp_patterns else ""
    return (
        f"WADE advisory context for '{finding_type}'{provider_part}: "
        f"{cwe} / {owasp}. {severity} "
        f"Retrieved {n_chunks} supporting chunks from local knowledge base.{fp_note}"
    )


def build_reasoning_context(
    finding_type: str,
    provider: str | None = None,
    symptom: str = "",
    svc: WADERetrievalService | None = None,
    k: int = 5,
) -> ReasoningContext:
    """Build a ReasoningContext for the given finding type and optional provider.

    Args:
        finding_type: One of the 22 supported WADE finding categories.
        provider: Optional CDN/WAF provider name (e.g. 'cloudflare', 'vercel').
        symptom: Optional symptom string for provider context query.
        svc: Optional pre-built WADERetrievalService (created if not provided).
        k: Number of chunks to retrieve per query.

    Returns:
        A populated ReasoningContext (advisory, read-only).
    """
    if svc is None:
        svc = load_wade_retrieval_service()

    canon_provider = normalize_provider(provider)

    # Retrieve from knowledge base
    security_results = svc.get_security_guidance(finding_type, k=k)
    provider_results = (
        svc.get_provider_context(finding_type, provider=provider, symptom=symptom, k=k)
        if provider else []
    )
    taxonomy_results = svc.get_taxonomy_mapping(finding_type, k=k)
    ti_results = svc.get_threat_intel_policy(finding_type, k=k)
    fp_results = svc.get_false_positive_patterns(finding_type, k=k)
    language_results = svc.get_customer_safe_language(finding_type, k=k)

    # Combine all retrieved chunks (de-dup by chunk_id)
    seen: set[str] = set()
    all_chunks: list[dict] = []
    for chunk in (
        security_results + provider_results + taxonomy_results
        + ti_results + fp_results + language_results
    ):
        cid = chunk.get("chunk_id", "")
        if cid and cid not in seen:
            seen.add(cid)
            all_chunks.append(chunk)

    # Collect authority tiers
    authority_tiers = sorted(
        {c.get("authority_tier", "") for c in all_chunks if c.get("authority_tier")}
    )

    # Build structured context fields
    taxonomy = resolve_taxonomy(finding_type)
    fp_patterns = resolve_fp_patterns(finding_type)
    fp_notes = resolve_fp_notes(finding_type)
    lang = resolve_customer_language(finding_type)
    confidence = _compute_confidence(security_results, taxonomy, finding_type)
    summary = _build_summary(
        finding_type, taxonomy, fp_patterns, canon_provider, len(all_chunks)
    )

    return ReasoningContext(
        finding_type=finding_type,
        retrieved_sources=security_results,
        provider_context=provider_results,
        taxonomy_context=taxonomy,
        threat_intel_context=ti_results,
        false_positive_context=fp_results,
        customer_safe_language=lang,
        supporting_chunks=all_chunks,
        authority_tiers=authority_tiers,
        reasoning_summary=summary,
        retrieval_confidence=confidence,
        brain_version=BRAIN_VERSION,
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        false_positive_patterns=fp_patterns,
        false_positive_notes=fp_notes,
        provider_name=get_provider_name(provider) if provider else None,
    )
