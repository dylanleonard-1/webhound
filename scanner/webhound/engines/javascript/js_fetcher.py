# WebHound — scanner/webhound/engines/javascript/js_fetcher.py
# Fetch external script bodies and run pattern / obfuscation analysis over them.
#
# Closes the biggest passive-scan blind spot: we collect external script URLs
# but normally never see what they contain. A malicious CDN-hosted script —
# or a third-party library with a backdoored payload — is invisible from URL
# alone. This module GETs each unique external script (size-capped, parallel,
# deduplicated by content hash) and applies the same pattern engine we run
# over inline scripts.

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

from .js_analyzer import _PATTERNS, _PATTERN_CONFIDENCE, _SNIPPET_LEN, _FA as _ANALYZER_FA

if TYPE_CHECKING:
    from webhound.core.http_client import SafeHttpClient
    from .js_collector import JsCollection

_ENGINE = "fetched_js_analyzer"

# Cap on body size we'll ingest per script (1 MB). Above this we record the
# size but don't run pattern checks — large bundles are usually framework
# code anyway, and we'd rather not OOM the scanner on a malicious 100MB
# script that consists of repeated bytes.
_MAX_SCRIPT_BYTES = 1 * 1024 * 1024

# Cap on the number of scripts we fetch per page. Large SPA pages can have
# dozens of unique CDN URLs; we'd rather analyze a representative sample than
# stall the scan. Scripts are processed in collection order.
_MAX_SCRIPTS_PER_PAGE = 25

# Concurrency cap on parallel fetches. SafeHttpClient enforces its own
# per-host rate limit, so we keep this modest.
_MAX_CONCURRENT_FETCHES = 6


@dataclass(frozen=True)
class FetchedScript:
    """An external script we successfully fetched."""

    src: str           # Resolved script src URL
    page_url: str      # Page where the script was referenced
    body: str          # Decoded body content
    content_hash: str  # SHA-256 of body, for dedup
    size_bytes: int


class JsFetcherEngine:
    """Fetches external script bodies, then runs the inline-script pattern
    engine over them.

    Usage::

        async with SafeHttpClient(options) as client:
            engine = JsFetcherEngine(client)
            findings = await engine.analyze(collection)

    Findings reference the source `src` URL in their metadata so the
    dashboard can show which external script tripped each rule.
    """

    NAME = _ENGINE

    def __init__(self, client: "SafeHttpClient") -> None:
        self._client = client

    async def fetch_bodies(self, collection: "JsCollection") -> list[FetchedScript]:
        """Fetch every distinct external script in the collection. Body
        download is bounded by `_MAX_SCRIPT_BYTES` and we cap total fetches
        per page at `_MAX_SCRIPTS_PER_PAGE`.

        Returns a list of FetchedScript records — order is not guaranteed.
        Scripts that returned an error / non-2xx / oversized body are silently
        dropped.
        """
        external = [s for s in collection.external_scripts if s.src]
        if not external:
            return []
        # Dedup by src URL within this page — the collector already does this,
        # but we double-check in case a caller passes us a raw list.
        seen_srcs: set[str] = set()
        targets: list[str] = []
        for s in external:
            assert s.src is not None
            if s.src in seen_srcs:
                continue
            seen_srcs.add(s.src)
            targets.append(s.src)
            if len(targets) >= _MAX_SCRIPTS_PER_PAGE:
                break

        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_FETCHES)

        async def _fetch_one(url: str) -> FetchedScript | None:
            async with semaphore:
                try:
                    response = await self._client.get(url)
                except Exception:
                    return None
            if response.failed or not response.is_success:
                return None
            body = response.body or ""
            if not body:
                return None
            size = len(body.encode("utf-8", errors="replace"))
            if size > _MAX_SCRIPT_BYTES:
                # Oversized: skip pattern checks but record. Future passes
                # could chunk-scan but for now we'd rather skip than burn
                # memory.
                return None
            h = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
            return FetchedScript(
                src=url,
                page_url=collection.origin_url,
                body=body,
                content_hash=h,
                size_bytes=size,
            )

        results = await asyncio.gather(*(_fetch_one(u) for u in targets), return_exceptions=False)

        # Dedup by content hash — two different CDN URLs serving the same file
        # are the same script for analysis purposes.
        deduped: dict[str, FetchedScript] = {}
        for r in results:
            if r is None:
                continue
            if r.content_hash in deduped:
                continue
            deduped[r.content_hash] = r
        return list(deduped.values())

    async def analyze(self, collection: "JsCollection") -> list[Finding]:
        """Fetch every external script in `collection` and apply the
        inline-script pattern engine over each body.
        """
        scripts = await self.fetch_bodies(collection)
        if not scripts:
            return []

        findings: list[Finding] = []
        for fs in scripts:
            findings.extend(_run_patterns_on_body(fs))
        return findings


# ---------------------------------------------------------------------------
# Pattern application — mirrors JsAnalyzerEngine.analyze() but for fetched
# bodies. Reuses the same _PATTERNS / _PATTERN_CONFIDENCE / _FA constants.
# ---------------------------------------------------------------------------


def _run_patterns_on_body(fs: FetchedScript) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for pat in _PATTERNS:
        if pat.name in seen:
            continue
        m = pat.pattern.search(fs.body)
        if not m:
            continue
        seen.add(pat.name)
        snippet = _extract_snippet(fs.body, m)
        confidence = _PATTERN_CONFIDENCE.get(pat.name, 0.65)
        ev = Evidence(
            evidence_type=EvidenceType.JAVASCRIPT,
            content=f"[external script {fs.src}]\n{snippet}",
            location=fs.page_url,
            source_engine=_ENGINE,
            extra={
                "pattern": pat.name,
                "script_src": fs.src,
                "script_hash": fs.content_hash,
                "script_size": fs.size_bytes,
            },
        )
        # The existing _FA preset table in js_analyzer.py is shared verbatim —
        # the pattern's risk profile is the same whether the code was inline
        # or fetched from a CDN.
        fa = _ANALYZER_FA.get(pat.name, FrameworkAlignment(
            owasp_top10=["A03:2021"],
            cwe_ids=["CWE-79"],
            nist_controls=["SI-10"],
        ))
        findings.append(Finding(
            title=f"External script body matches {pat.name} pattern",
            description=(
                f"WebHound fetched the external script `{fs.src}` and found a "
                f"`{pat.name}` pattern in its body. " + pat.description
            ),
            severity=pat.severity,
            category=FindingCategory.JAVASCRIPT,
            evidence=[ev],
            confidence=confidence,
            remediation=(
                "This finding refers to code WebHound retrieved from a third-"
                "party CDN, not code you wrote inline. Recommended response: "
                f"audit the source of `{fs.src}`. If it's a maintained library, "
                "pin to a specific version + Subresource Integrity hash so you "
                "know exactly which build is loaded. If you don't recognise "
                "the script, treat it as a compromise indicator.\n\n"
                "Underlying pattern remediation: " + pat.remediation
            ),
            framework=fa,
            scanner_engine=_ENGINE,
            metadata={
                "url": fs.page_url,
                "script_src": fs.src,
                "script_hash": fs.content_hash,
                "script_size_bytes": fs.size_bytes,
            },
        ))
    return findings


def _extract_snippet(content: str, match: re.Match) -> str:
    """Same context window as js_analyzer._extract_snippet, kept local so
    this module stays independent if js_analyzer's helper is renamed.
    """
    half = _SNIPPET_LEN // 2
    start = max(0, match.start() - half)
    end = min(len(content), match.end() + half)
    snippet = content[start:end].strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(content):
        snippet = snippet + "…"
    return snippet
