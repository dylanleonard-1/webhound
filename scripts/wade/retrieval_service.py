"""Phase 8B: WADE retrieval service.

Wraps hybrid retrieval with 6 WADE-specific query functions.
Advisory only — no production scoring changes, no cloud APIs.

Usage:
    svc = load_wade_retrieval_service()
    results = svc.get_security_guidance("missing_csp")
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import TYPE_CHECKING

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from scripts.ai.hybrid_retrieval import load_retriever, HybridRetriever
    _RETRIEVER_AVAILABLE = True
except Exception:
    _RETRIEVER_AVAILABLE = False
    HybridRetriever = None  # type: ignore[assignment,misc]

from scripts.wade.taxonomy_resolver import resolve_taxonomy, SUPPORTED_FINDING_TYPES
from scripts.wade.provider_resolver import resolve_provider_query, normalize_provider
from scripts.wade.false_positive_resolver import resolve_fp_query


class WADERetrievalService:
    """Provides 6 knowledge-base retrieval methods for WADE advisory context."""

    def __init__(self, retriever: "HybridRetriever | None") -> None:
        self._r = retriever

    def _retrieve(self, query: str, k: int = 5) -> list[dict]:
        """Run lexical retrieval (always available) with dense upgrade if possible."""
        if self._r is None:
            return []
        try:
            if self._r.dense_available:
                return self._r.retrieve(query, k=k, mode="hybrid")
            return self._r.retrieve(query, k=k, mode="lexical_only")
        except Exception:
            return []

    def get_security_guidance(
        self,
        finding_type: str,
        k: int = 5,
    ) -> list[dict]:
        """Retrieve security guidance chunks for a finding type.

        Returns ranked chunks covering CWE rationale, OWASP mapping,
        and remediation evidence from the knowledge base.
        """
        tax = resolve_taxonomy(finding_type)
        query = tax.get("query", finding_type.replace("_", " "))
        return self._retrieve(query, k=k)

    def get_provider_context(
        self,
        finding_type: str,
        provider: str | None = None,
        symptom: str = "",
        k: int = 5,
    ) -> list[dict]:
        """Retrieve provider-specific context chunks.

        Especially useful for WAF challenge pages, CDN header injection,
        and provider deployment-protection findings.
        """
        query = resolve_provider_query(finding_type, provider, symptom)
        return self._retrieve(query, k=k)

    def get_threat_intel_policy(
        self,
        finding_type: str = "threat_intel_match",
        k: int = 5,
    ) -> list[dict]:
        """Retrieve threat intelligence policy and evaluation guidance.

        Covers shared CDN IP classification, GreyNoise/AbuseIPDB context,
        and WADE's TI-match suppression policies.
        """
        query = (
            "threat intelligence policy AbuseIPDB GreyNoise VirusTotal "
            "shared CDN IP false positive suppression WADE"
        )
        return self._retrieve(query, k=k)

    def get_taxonomy_mapping(
        self,
        finding_type: str,
        k: int = 5,
    ) -> list[dict]:
        """Retrieve CWE/OWASP taxonomy chunks for a finding type.

        Returns authoritative taxonomy reference material from the knowledge base.
        """
        tax = resolve_taxonomy(finding_type)
        cwe = tax.get("cwe", "")
        owasp = tax.get("owasp", "")
        query = f"{cwe} {owasp} {tax.get('query', finding_type.replace('_', ' '))}"
        return self._retrieve(query, k=k)

    def get_false_positive_patterns(
        self,
        finding_type: str,
        k: int = 5,
    ) -> list[dict]:
        """Retrieve false-positive pattern chunks for a finding type.

        Returns knowledge-base evidence about known benign conditions that
        produce this finding type.
        """
        query = resolve_fp_query(finding_type)
        return self._retrieve(query, k=k)

    def get_customer_safe_language(
        self,
        finding_type: str,
        k: int = 5,
    ) -> list[dict]:
        """Retrieve customer-communication chunks for a finding type.

        Returns reference material about explaining this finding in language
        appropriate for non-technical stakeholders.
        """
        query = (
            f"{finding_type.replace('_', ' ')} customer remediation risk "
            "security report explanation non-technical"
        )
        return self._retrieve(query, k=k)


def load_wade_retrieval_service() -> WADERetrievalService:
    """Create a WADERetrievalService backed by the local hybrid retriever."""
    if not _RETRIEVER_AVAILABLE:
        return WADERetrievalService(None)
    try:
        retriever = load_retriever()
        return WADERetrievalService(retriever)
    except Exception:
        return WADERetrievalService(None)
