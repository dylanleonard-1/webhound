# WebHound — scanner/webhound/core/orchestrator.py
# Scanner orchestration: drives the full scan pipeline in safe-mode.
#
# Safe-mode guarantees:
#   - GET and HEAD requests only — no form submission, no POST/PUT/DELETE.
#   - JavaScript is never executed.
#   - External APIs are never called (no live threat intel).
#   - Engine errors are isolated: one failure never aborts the scan.
#   - max_pages, max_depth, and rate limits are always respected.

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

import httpx

from webhound.core.crawler import Crawler
from webhound.core.extractor import _is_html
from webhound.core.http_client import SafeHttpClient
from webhound.core.scan_context import ScanContext
from webhound.engines.compromise.hidden_iframes import HiddenIframesEngine
from webhound.engines.compromise.injected_js import InjectedJsEngine
from webhound.engines.compromise.seo_spam import SeoSpamEngine
from webhound.engines.compromise.suspicious_redirects import SuspiciousRedirectsEngine
from webhound.engines.cookies.cookie_scanner import CookieScannerEngine
from webhound.engines.forms.form_risk import FormRiskEngine
from webhound.engines.forms.input_analysis import InputAnalysisEngine
from webhound.engines.headers.cors import CorsEngine
from webhound.engines.headers.security_headers import SecurityHeadersEngine
from webhound.engines.javascript.js_analyzer import JsAnalyzerEngine
from webhound.engines.javascript.js_collector import JsCollectorEngine
from webhound.engines.javascript.obfuscation_detector import ObfuscationDetectorEngine
from webhound.engines.javascript.third_party_domains import ThirdPartyDomainEngine
from webhound.engines.recon.robots_sitemap import RobotsAndSitemapEngine
from webhound.engines.recon.sensitive_paths import SensitivePathsEngine
from webhound.engines.recon.technology import TechnologyEngine
from webhound.engines.tls_dns import dns_checker as _dns_module
from webhound.engines.tls_dns import tls_checker as _tls_module
from webhound.engines.tls_dns.dns_checker import DnsCheckerEngine
from webhound.engines.tls_dns.tls_checker import TlsCheckerEngine
from webhound.models.finding import Finding
from webhound.models.scan_result import ScanResult
from webhound.models.target import ScanOptions, Target


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


async def _safe(
    ctx: ScanContext,
    engine_name: str,
    fn: Any,
    *args: Any,
    **kwargs: Any,
) -> list[Finding]:
    """Call fn(*args, **kwargs), record any exception as a ScanError.

    Handles both synchronous callables and coroutine-returning callables.
    The engine is added to ``engines_run`` on a successful call regardless
    of whether it produced findings.
    """
    try:
        result = fn(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = await result
        findings: list[Finding] = result or []
        if engine_name not in ctx.scan_result.engines_run:
            ctx.scan_result.engines_run.append(engine_name)
        return findings
    except Exception as exc:
        ctx.record_error(engine_name, f"{type(exc).__name__}: {exc}")
        return []


def _add_findings(ctx: ScanContext, findings: list[Finding]) -> None:
    for f in findings:
        ctx.add_finding(f)


def _compute_risk_score(result: ScanResult) -> tuple[int, str]:
    """Compute a 0–100 website health score and a risk level label.

    Starts at 100 and deducts per finding severity:
      CRITICAL −30 | HIGH −15 | MEDIUM −7 | LOW −2 | INFO 0

    If any CRITICAL finding exists, score is capped at 59 (cannot be 'low' risk).
    """
    bd = result.severity_breakdown
    score = 100
    score -= bd.critical * 30
    score -= bd.high * 15
    score -= bd.medium * 7
    score -= bd.low * 2
    score = max(0, score)
    if bd.critical > 0:
        score = min(score, 59)

    if score >= 75:
        level = "low"
    elif score >= 50:
        level = "medium"
    elif score >= 25:
        level = "high"
    else:
        level = "critical"

    return score, level


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicate findings (same engine + title + evidence location)."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        loc = f.evidence[0].location if f.evidence else ""
        key = (f.scanner_engine, f.title, loc)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Full-pipeline website security scanner.

    Orchestrates crawling, artifact extraction, and all passive analysis
    engines in a safe-mode-first pipeline.  No forms are submitted, no
    JavaScript is executed, and no live threat intel APIs are called.

    Usage::

        scanner = Scanner("https://example.com")
        result = await scanner.scan()
        print(result.metadata["risk_score"])
    """

    def __init__(
        self,
        target: Target | str,
        *,
        options: ScanOptions | None = None,
        _transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if isinstance(target, str):
            target = Target.from_url(target, scan_options=options or ScanOptions())
        elif options is not None:
            target.scan_options = options
        self._target = target
        self._transport = _transport

        # Engines instantiated once; all are stateless.
        self._security_headers = SecurityHeadersEngine()
        self._cors = CorsEngine()
        self._cookies = CookieScannerEngine()
        self._tls = TlsCheckerEngine()
        self._dns = DnsCheckerEngine()
        self._js_collector = JsCollectorEngine()
        self._js_analyzer = JsAnalyzerEngine()
        self._obfuscation = ObfuscationDetectorEngine()
        self._third_party = ThirdPartyDomainEngine()
        self._technology = TechnologyEngine()
        self._sensitive_paths = SensitivePathsEngine()
        self._robots_sitemap = RobotsAndSitemapEngine()
        self._form_risk = FormRiskEngine()
        self._input_analysis = InputAnalysisEngine()
        self._injected_js = InjectedJsEngine()
        self._hidden_iframes = HiddenIframesEngine()
        self._seo_spam = SeoSpamEngine()
        self._suspicious_redirects = SuspiciousRedirectsEngine()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def scan(self) -> ScanResult:
        """Execute the full scan pipeline and return a completed ScanResult."""
        ctx = ScanContext(self._target)
        external_domains: set[str] = set()

        try:
            async with SafeHttpClient(self._target.scan_options, transport=self._transport) as client:
                # 1. Target-level engines that use the HTTP client
                await self._run_target_engines(ctx, client)

                # 2. BFS crawl
                crawler = Crawler(ctx, client)
                crawl_results = await crawler.crawl()

                # 3. Per-page engines
                for result in crawl_results:
                    await self._run_page_engines(result, ctx, external_domains)

            # 4. TLS / DNS — blocking I/O, run in thread pool
            await self._run_tls_dns(ctx)

        except Exception as exc:
            ctx.scan_result.mark_failed(str(exc))
            return ctx.scan_result

        # 5. Deduplicate and finalize
        ctx.scan_result.findings = _dedup_findings(ctx.scan_result.findings)
        result = ctx.finish()

        # 6. Risk scoring (needs recomputed aggregates from mark_complete)
        risk_score, risk_level = _compute_risk_score(result)
        result.metadata["risk_score"] = risk_score
        result.metadata["risk_level"] = risk_level
        result.metadata["external_domains"] = sorted(external_domains)
        result.metadata["external_domain_count"] = len(external_domains)

        return result

    # ------------------------------------------------------------------
    # Target-level engines (run once for the whole scan)
    # ------------------------------------------------------------------

    async def _run_target_engines(
        self, ctx: ScanContext, client: SafeHttpClient
    ) -> None:
        target = self._target

        _add_findings(ctx, await _safe(
            ctx, self._sensitive_paths.NAME,
            self._sensitive_paths.probe, target, client, ctx.scope,
        ))
        _add_findings(ctx, await _safe(
            ctx, self._robots_sitemap.NAME,
            self._robots_sitemap.analyze, target, client,
        ))

    # ------------------------------------------------------------------
    # Per-page engines
    # ------------------------------------------------------------------

    async def _run_page_engines(
        self,
        result: Any,  # CrawlResult
        ctx: ScanContext,
        external_domains: set[str],
    ) -> None:
        response = result.response
        artifacts = result.artifacts

        if response.failed:
            return

        # Response-based engines
        _add_findings(ctx, await _safe(ctx, self._security_headers.NAME, self._security_headers.analyze, response))
        _add_findings(ctx, await _safe(ctx, self._cors.NAME, self._cors.analyze, response))
        _add_findings(ctx, await _safe(ctx, self._cookies.NAME, self._cookies.analyze, response))

        if artifacts is None:
            return

        # Collect external domains from this page
        for link in artifacts.external_links:
            host = urlparse(link).hostname
            if host:
                external_domains.add(host.lower())

        html_body: str | None = (
            response.body
            if _is_html(response.content_type) and response.body
            else None
        )

        # Artifacts-based engines
        _add_findings(ctx, await _safe(ctx, self._technology.NAME, self._technology.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._js_analyzer.NAME, self._js_analyzer.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._obfuscation.NAME, self._obfuscation.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._third_party.NAME, self._third_party.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._injected_js.NAME, self._injected_js.analyze, artifacts, html_body=html_body))
        _add_findings(ctx, await _safe(ctx, self._hidden_iframes.NAME, self._hidden_iframes.analyze, artifacts, html_body=html_body))
        _add_findings(ctx, await _safe(ctx, self._seo_spam.NAME, self._seo_spam.analyze, artifacts, html_body=html_body))
        _add_findings(ctx, await _safe(ctx, self._suspicious_redirects.NAME, self._suspicious_redirects.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._form_risk.NAME, self._form_risk.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._input_analysis.NAME, self._input_analysis.analyze, artifacts))

    # ------------------------------------------------------------------
    # TLS / DNS (blocking I/O wrapped in thread pool)
    # ------------------------------------------------------------------

    async def _run_tls_dns(self, ctx: ScanContext) -> None:
        target = self._target
        hostname = target.hostname
        port = target.port or (443 if target.is_https else 80)

        # TLS
        try:
            cert_info = await asyncio.to_thread(
                _tls_module.probe_tls, hostname, port
            )
            _add_findings(ctx, await _safe(ctx, self._tls.NAME, self._tls.analyze, cert_info))
        except Exception as exc:
            ctx.record_error(self._tls.NAME, f"{type(exc).__name__}: {exc}")

        # DNS
        try:
            dns_records = await asyncio.to_thread(
                _dns_module.resolve_dns, hostname
            )
            _add_findings(ctx, await _safe(ctx, self._dns.NAME, self._dns.analyze, dns_records))
        except Exception as exc:
            ctx.record_error(self._dns.NAME, f"{type(exc).__name__}: {exc}")
