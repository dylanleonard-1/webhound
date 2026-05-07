# WebHound — scanner/webhound/threat_intel/enrichment_service.py
# Provider-agnostic threat intelligence enrichment service.
#
# Wraps the local DomainClassifier with a structured interface for plugging in
# external threat intel providers (VirusTotal, URLHaus, AbuseIPDB, etc.) later.
# Currently: local-only classification. No external API calls are made.
#
# Design:
#   BaseProvider — abstract interface each external provider implements
#   ProviderResult — structured output from one provider
#   EnrichmentResult — merged verdict from local + all providers
#   EnrichmentService — orchestrates classification and merging

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .domain_classifier import (
    DomainClass,
    DomainClassification,
    DomainClassifier,
    _CLASS_RANK,
    _classify_from_score,
)


# ---------------------------------------------------------------------------
# Provider result model
# ---------------------------------------------------------------------------


@dataclass
class ProviderResult:
    """Structured output from a single threat intel provider.

    ``reputation_score`` uses a 0.0–10.0 scale (10 = most malicious).
    ``is_malicious`` and ``is_suspicious`` are the provider's own verdict flags.
    ``error`` is set when the provider lookup failed; other fields may be None.
    """

    provider: str
    domain: str
    reputation_score: float | None          # 0.0–10.0; None if unknown
    confidence: float                        # Provider's own confidence [0.0–1.0]
    categories: list[str]                    # e.g. ["phishing", "malware"]
    is_malicious: bool | None               # Provider verdict; None = no verdict
    is_suspicious: bool | None
    raw: dict[str, Any]                      # Verbatim provider response payload
    checked_at: datetime
    error: str | None = None                 # Set on lookup failure


# ---------------------------------------------------------------------------
# Enrichment result model — merged from local + external providers
# ---------------------------------------------------------------------------


@dataclass
class EnrichmentResult:
    """Merged verdict combining local classification and all provider results."""

    domain: str
    local: DomainClassification
    external: list[ProviderResult]           # One entry per provider; may be empty
    final_classification: DomainClass
    final_score: float                       # 0.0–10.0
    final_confidence: float                  # [0.0–1.0]
    verdict: str                             # Human-readable classification label
    checked_at: datetime


# ---------------------------------------------------------------------------
# Abstract provider interface
# ---------------------------------------------------------------------------


class BaseProvider(ABC):
    """Abstract base class for external threat intelligence providers.

    Subclasses implement :meth:`enrich` to call their respective API and
    return a :class:`ProviderResult`.  The ``name`` attribute must be set to a
    unique, slug-style identifier (e.g. ``"virustotal"``, ``"urlhaus"``).

    Implementations are expected to:
    - Handle rate limiting and retry internally
    - Return ``ProviderResult(error=...)`` on failure rather than raising
    - Cache results where appropriate to avoid redundant API calls
    """

    name: str = ""

    @abstractmethod
    async def enrich(self, domain: str) -> ProviderResult:
        """Query the provider for a domain verdict.

        No network calls should be made if ``domain`` has a cached result
        that has not yet expired.
        """
        ...


# ---------------------------------------------------------------------------
# Enrichment service
# ---------------------------------------------------------------------------


class EnrichmentService:
    """Orchestrates local domain classification and (future) external enrichment.

    Providers registered at construction time are called when
    ``await enrich_domain(domain)`` is invoked.  With no providers (the
    default), all operations are local-only — no network activity occurs.

    Usage::

        service = EnrichmentService()           # local-only, zero network calls
        result = service.classify_domain("bit.ly")
        # DomainClass.SUSPICIOUS

        service_with_vt = EnrichmentService(providers=[VirusTotalProvider(...)])
        enriched = await service_with_vt.enrich_domain("evil.tk")
    """

    def __init__(self, providers: list[BaseProvider] | None = None) -> None:
        self._classifier = DomainClassifier()
        self._providers: list[BaseProvider] = providers or []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def has_external_providers(self) -> bool:
        """True when at least one external provider is registered."""
        return bool(self._providers)

    def provider_names(self) -> list[str]:
        """Names of all registered providers."""
        return [p.name for p in self._providers]

    # ------------------------------------------------------------------
    # Synchronous helpers — local classification only
    # ------------------------------------------------------------------

    def classify_domain(self, domain: str) -> DomainClassification:
        """Classify a domain using local heuristics only (no network)."""
        return self._classifier.classify(domain)

    def classify_url(self, url: str) -> DomainClassification:
        """Extract the hostname from *url* and classify it locally."""
        hostname = urlparse(url).hostname or ""
        return self._classifier.classify(hostname)

    def score_domain(self, domain: str) -> float:
        """Return the numeric risk score [0.0–10.0] for a domain."""
        return self._classifier.classify(domain).score

    def explain_classification(self, result: DomainClassification) -> str:
        """Return a human-readable explanation of a classification result."""
        lines: list[str] = [
            f"Domain:         {result.domain}",
            f"Classification: {result.classification.value}",
            f"Score:          {result.score:.1f} / 10.0",
            f"Confidence:     {result.confidence:.0%}",
        ]
        if result.registerable_domain:
            lines.append(f"Registered:     {result.registerable_domain}")
        if result.tld:
            lines.append(f"TLD:            .{result.tld}")
        if result.is_punycode:
            lines.append("IDN/Punycode:   yes")
        if result.is_url_shortener:
            lines.append("URL shortener:  yes")
        if result.signals:
            lines.append("Signals:")
            for s in result.signals:
                lines.append(f"  • {s}")
        else:
            lines.append("Signals:        none")
        return "\n".join(lines)

    def merge_local_and_external_results(
        self,
        local: DomainClassification,
        external_results: list[ProviderResult],
    ) -> EnrichmentResult:
        """Merge a local classification with zero or more provider results.

        Resolution rules (applied in priority order):
        1. Any provider flagging ``is_malicious=True`` → MALICIOUS_INDICATOR
        2. Any provider flagging ``is_suspicious=True`` and local is UNKNOWN/COMMON_BENIGN
           → elevate to SUSPICIOUS
        3. External reputation scores that exceed the local score raise the class
        4. Multiple agreeing sources boost confidence (up to +0.20)
        """
        now = datetime.now(timezone.utc)

        if not external_results:
            return EnrichmentResult(
                domain=local.domain,
                local=local,
                external=[],
                final_classification=local.classification,
                final_score=local.score,
                final_confidence=local.confidence,
                verdict=local.classification.value,
                checked_at=now,
            )

        # Collect non-error external verdicts
        valid = [r for r in external_results if r.error is None]

        # Rule 1: any definitive malicious verdict → MALICIOUS_INDICATOR
        if any(r.is_malicious for r in valid if r.is_malicious is not None):
            final_class = DomainClass.MALICIOUS_INDICATOR
        # Rule 2: suspicious elevation
        elif (
            any(r.is_suspicious for r in valid if r.is_suspicious is not None)
            and _CLASS_RANK[local.classification] < _CLASS_RANK[DomainClass.SUSPICIOUS]
        ):
            final_class = DomainClass.SUSPICIOUS
        else:
            # Rule 3: use the higher-ranked of local vs max external score
            ext_scores = [r.reputation_score for r in valid if r.reputation_score is not None]
            if ext_scores:
                max_ext_score = max(ext_scores)
                ext_class = _classify_from_score(max_ext_score, set())
                if _CLASS_RANK[ext_class] > _CLASS_RANK[local.classification]:
                    final_class = ext_class
                else:
                    final_class = local.classification
            else:
                final_class = local.classification

        # Final score: max across all sources
        ext_scores = [r.reputation_score for r in valid if r.reputation_score is not None]
        final_score = round(min(max([local.score] + ext_scores), 10.0), 2) if ext_scores else local.score

        # Confidence boost from multiple agreeing sources (cap +0.20)
        agreements = len(valid)
        confidence_boost = min(0.08 * agreements, 0.20)
        final_confidence = round(min(local.confidence + confidence_boost, 0.98), 2)

        return EnrichmentResult(
            domain=local.domain,
            local=local,
            external=external_results,
            final_classification=final_class,
            final_score=final_score,
            final_confidence=final_confidence,
            verdict=final_class.value,
            checked_at=now,
        )

    # ------------------------------------------------------------------
    # Async entry point (for future external provider calls)
    # ------------------------------------------------------------------

    async def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Classify a domain locally and call all registered providers.

        With no providers registered, this is equivalent to a local-only
        classification and makes zero network calls.
        """
        local = self.classify_domain(domain)

        if not self._providers:
            return self.merge_local_and_external_results(local, [])

        # Call providers concurrently when they exist (future implementation)
        external_results: list[ProviderResult] = []
        for provider in self._providers:
            try:
                result = await provider.enrich(domain)
                external_results.append(result)
            except Exception as exc:
                external_results.append(ProviderResult(
                    provider=provider.name,
                    domain=domain,
                    reputation_score=None,
                    confidence=0.0,
                    categories=[],
                    is_malicious=None,
                    is_suspicious=None,
                    raw={},
                    checked_at=datetime.now(timezone.utc),
                    error=str(exc),
                ))

        return self.merge_local_and_external_results(local, external_results)
