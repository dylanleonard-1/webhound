"""Phase 8B: WADE retrieval layer — advisory knowledge-base access.

This package provides read-only retrieval of WADE knowledge-base context.
It does NOT modify production scoring, severity, suppression, or reporting.

Public API:
    load_wade_retrieval_service() → WADERetrievalService
    build_reasoning_context(finding_type, provider=None) → ReasoningContext
"""
from scripts.wade.retrieval_service import WADERetrievalService, load_wade_retrieval_service
from scripts.wade.context_builder import ReasoningContext, build_reasoning_context
from scripts.wade.taxonomy_resolver import (
    SUPPORTED_FINDING_TYPES, resolve_taxonomy,
)
from scripts.wade.provider_resolver import normalize_provider, resolve_provider_query
from scripts.wade.false_positive_resolver import resolve_fp_patterns, resolve_fp_query
from scripts.wade.language_resolver import resolve_customer_language, resolve_risk_summary

__all__ = [
    "WADERetrievalService",
    "load_wade_retrieval_service",
    "ReasoningContext",
    "build_reasoning_context",
    "SUPPORTED_FINDING_TYPES",
    "resolve_taxonomy",
    "normalize_provider",
    "resolve_provider_query",
    "resolve_fp_patterns",
    "resolve_fp_query",
    "resolve_customer_language",
    "resolve_risk_summary",
]
