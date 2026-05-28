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
import os
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import tldextract as _tldextract

from webhound.core.crawler import Crawler
from webhound.core.extractor import _is_html
from webhound.core.http_client import SafeHttpClient
from webhound.core.scan_context import ScanContext
from webhound.engines.compromise.hidden_iframes import HiddenIframesEngine
from webhound.engines.compromise.injected_js import InjectedJsEngine
from webhound.engines.compromise.seo_spam import SeoSpamEngine
from webhound.engines.compromise.suspicious_redirects import SuspiciousRedirectsEngine
from webhound.engines.api_discovery.endpoint_discovery import EndpointDiscoveryEngine
from webhound.engines.threat_intel.external_domains import ThreatIntelEngine
from webhound.engines.cms.shopify import ShopifyEngine
from webhound.engines.cms.wix import WixEngine
from webhound.engines.cms.wordpress import WordpressEngine
from webhound.engines.cookies.cookie_scanner import CookieScannerEngine
from webhound.engines.forms.form_risk import FormRiskEngine
from webhound.engines.forms.input_analysis import InputAnalysisEngine
from webhound.engines.headers.cors import CorsEngine
from webhound.engines.headers.csp_engine import CspEngine
from webhound.engines.headers.security_headers import SecurityHeadersEngine
from webhound.engines.secrets.secret_scanner import SecretScannerEngine
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
from webhound.core.fp_filter import FPFilter
from webhound.core.session_context import SessionContext
from webhound.models.finding import Finding
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.core.finding_grouper import FindingGrouper
from webhound.wade.anomaly_scorer import AnomalyScorer
from webhound.wade.baseline_builder import BaselineBuilder, SiteBaseline
from webhound.wade.classifier import Classifier
from webhound.wade.confidence import adjust_findings_confidence
from webhound.wade.diff_engine import DiffEngine
from webhound.threat_intel.enrichment_service import EnrichmentService
from webhound.threat_intel.urlhaus_client import UrlhausClient
from webhound.threat_intel.virustotal_client import VirusTotalClient


# Per-engine wall-clock timeout; cancels a hung engine coroutine.
#
# The global default can be raised via WEBHOUND_DEFAULT_ENGINE_TIMEOUT. A
# per-engine override takes precedence via
# WEBHOUND_ENGINE_TIMEOUT_<UPPER_ENGINE_NAME>. Example to give the
# sensitive_paths engine 180 seconds:
#     WEBHOUND_ENGINE_TIMEOUT_SENSITIVE_PATHS=180
# The override is resolved per-call inside _safe(), so env-var changes take
# effect without restarting the worker.
_DEFAULT_ENGINE_TIMEOUT_SECONDS: float = float(
    os.getenv("WEBHOUND_DEFAULT_ENGINE_TIMEOUT", "60") or "60"
)


def _engine_timeout_for(name: str) -> float:
    """Resolve the wall-clock timeout for one engine. Per-engine env var wins."""
    if name:
        raw = os.getenv(f"WEBHOUND_ENGINE_TIMEOUT_{name.upper()}")
        if raw:
            try:
                v = float(raw)
                if v > 0:
                    return v
            except ValueError:
                pass
    return _DEFAULT_ENGINE_TIMEOUT_SECONDS


def _build_enrichment_service() -> EnrichmentService | None:
    """Construct an EnrichmentService from env-configured providers.

    Returns None when no providers are configured, so ThreatIntelEngine
    falls back to local-only classification. Reads:
      VIRUSTOTAL_API_KEY  — enables VirusTotal v3 domain lookups.
      ENABLE_URLHAUS=1    — enables abuse.ch URLhaus (no key required).
    """
    providers = []
    if os.getenv("VIRUSTOTAL_API_KEY"):
        providers.append(VirusTotalClient(allow_network=True))
    if os.getenv("ENABLE_URLHAUS") == "1":
        providers.append(UrlhausClient(allow_network=True))
    if not providers:
        return None
    return EnrichmentService(providers=providers)


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
    Async callables are wrapped with asyncio.wait_for to enforce a per-engine
    timeout so one hung engine cannot stall the entire scan.
    Records timing and per-engine outcome in ``ctx.tracker``.
    """
    started_at = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    timeout_s = _engine_timeout_for(engine_name)
    try:
        result = fn(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = await asyncio.wait_for(result, timeout=timeout_s)
        findings: list[Finding] = result or []
        duration_ms = (time.perf_counter() - t0) * 1000
        if engine_name not in ctx.scan_result.engines_run:
            ctx.scan_result.engines_run.append(engine_name)
        ctx.tracker.record_run(
            engine_name, findings, duration_ms, started_at, datetime.now(timezone.utc)
        )
        return findings
    except asyncio.TimeoutError:
        duration_ms = (time.perf_counter() - t0) * 1000
        err = f"engine timeout after {timeout_s:.0f}s"
        ctx.record_error(engine_name, err)
        ctx.tracker.record_error(
            engine_name, err, duration_ms, started_at, datetime.now(timezone.utc)
        )
        return []
    except Exception as exc:
        duration_ms = (time.perf_counter() - t0) * 1000
        err = f"{type(exc).__name__}: {exc}"
        ctx.record_error(engine_name, err)
        ctx.tracker.record_error(
            engine_name, err, duration_ms, started_at, datetime.now(timezone.utc)
        )
        return []


def _add_findings(ctx: ScanContext, findings: list[Finding]) -> None:
    for f in findings:
        ctx.add_finding(f)


def _breakdown_from_grouped(grouped: list[GroupedFinding]) -> SeverityBreakdown:
    """Build a SeverityBreakdown from grouped findings (one entry per unique issue)."""
    bd = SeverityBreakdown()
    for gf in grouped:
        match gf.severity:
            case Severity.CRITICAL:
                bd.critical += 1
            case Severity.HIGH:
                bd.high += 1
            case Severity.MEDIUM:
                bd.medium += 1
            case Severity.LOW:
                bd.low += 1
            case Severity.INFO:
                bd.info += 1
    return bd


def _compute_risk_score(result: ScanResult) -> tuple[int, str]:
    """Compute a 0–100 risk score where 0 = safe and 100 = critical.

    Uses grouped findings when available (same site-wide issue counts once,
    not once per page).  Behavioral findings from the WADE engine are excluded
    from the breakdown so that a structural page change between scans cannot
    inflate the security risk label.

    Tier contributions with per-tier caps (no single tier dominates):
      CRITICAL  +30 each, cap +85  |  HIGH    +15 each, cap +40
      MEDIUM    +7 each,  cap +30  |  LOW     +2 each,  cap +10

    Label thresholds:
      0–19 → safe  |  20–39 → low  |  40–59 → medium
      60–79 → high  |  80–100 → critical

    Downward guards (prevent labels without sufficient evidence):
      "critical" requires at least one CRITICAL finding.
      "high"     requires at least one HIGH or CRITICAL finding.

    Upward guards (prevent misleadingly mild labels):
      Any CRITICAL finding forces label to at least "high".
      Any HIGH finding forces label to at least "low".
    """
    # Prefer security-engine grouped findings; exclude WADE (behavioural engine).
    security_grouped = [
        gf for gf in result.grouped_findings if gf.scanner_engine != "wade"
    ] if result.grouped_findings else None

    if security_grouped:
        bd = _breakdown_from_grouped(security_grouped)
    elif result.grouped_findings:
        bd = _breakdown_from_grouped(result.grouped_findings)
    else:
        bd = result.severity_breakdown

    risk = 0
    risk += min(bd.critical * 30, 85)
    risk += min(bd.high * 15, 40)
    risk += min(bd.medium * 7, 30)
    risk += min(bd.low * 2, 10)
    risk = min(100, risk)

    if risk <= 19:
        level = "safe"
    elif risk <= 39:
        level = "low"
    elif risk <= 59:
        level = "medium"
    elif risk <= 79:
        level = "high"
    else:
        level = "critical"

    # Downward guards
    if level == "critical" and bd.critical == 0:
        level = "high"
    if level == "high" and bd.critical == 0 and bd.high == 0:
        level = "medium"

    # Upward guards
    if bd.critical > 0 and level in ("safe", "low", "medium"):
        level = "high"
    if bd.high > 0 and level == "safe":
        level = "low"

    return risk, level


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
        previous_baseline: SiteBaseline | None = None,
        session_context: SessionContext | None = None,
    ) -> None:
        if isinstance(target, str):
            target = Target.from_url(target, scan_options=options or ScanOptions())
        elif options is not None:
            target.scan_options = options
        self._target = target
        self._transport = _transport
        self._previous_baseline: SiteBaseline | None = previous_baseline
        self._session_context: SessionContext | None = session_context
        self._current_baseline: SiteBaseline | None = None

        # Engines instantiated once; all are stateless.
        self._security_headers = SecurityHeadersEngine()
        self._cors = CorsEngine()
        self._csp = CspEngine()
        self._secret_scanner = SecretScannerEngine()
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
        self._wordpress = WordpressEngine()
        self._shopify = ShopifyEngine()
        self._wix = WixEngine()
        self._endpoint_discovery = EndpointDiscoveryEngine()
        self._threat_intel = ThreatIntelEngine(
            enrichment_service=_build_enrichment_service(),
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def scan(self) -> ScanResult:
        """Execute the full scan pipeline and return a completed ScanResult."""
        ctx = ScanContext(self._target)
        external_domains: set[str] = set()
        external_script_domains: set[str] = set()
        crawl_results: list = []
        _http_stats: dict[str, Any] = {}
        _crawl_duration_seconds: float = 0.0

        try:
            async with SafeHttpClient(
                self._target.scan_options,
                transport=self._transport,
                session_context=self._session_context,
            ) as client:
                # 1. Target-level engines that use the HTTP client
                await self._run_target_engines(ctx, client)

                # 2. BFS crawl (timed separately for throughput metrics)
                crawler = Crawler(ctx, client)
                _crawl_t0 = time.perf_counter()
                crawl_results = await crawler.crawl()
                _crawl_duration_seconds = time.perf_counter() - _crawl_t0

                # 3. Per-page engines
                for result in crawl_results:
                    await self._run_page_engines(
                        result, ctx, external_domains, external_script_domains
                    )

                # Capture HTTP stats before the client closes
                _http_stats = client.fetch_stats.to_dict()

            # 4. TLS / DNS — blocking I/O, run in thread pool
            await self._run_tls_dns(ctx)

            # 5. WADE — build baseline; optionally compare against previous
            self._run_wade(ctx, crawl_results)

        except Exception as exc:
            ctx.scan_result.mark_failed(str(exc))
            return ctx.scan_result

        # 6. Deduplicate
        ctx.scan_result.findings = _dedup_findings(ctx.scan_result.findings)

        # 7. False-positive suppression — reduce confidence on known CDN/platform patterns
        ctx.scan_result.findings = FPFilter().filter(ctx.scan_result.findings)

        result = ctx.finish()

        # 8. Group findings for clean reporting and fair risk scoring
        result.grouped_findings = FindingGrouper().group(result.active_findings)

        # 9. Risk scoring — uses grouped findings to avoid penalising repeated issues
        risk_score, risk_level = _compute_risk_score(result)
        result.metadata["risk_score"] = risk_score
        result.metadata["risk_level"] = risk_level
        result.metadata["external_domains"] = sorted(external_domains)
        result.metadata["external_domain_count"] = len(external_domains)
        result.metadata["external_script_domains"] = sorted(external_script_domains)
        result.metadata["external_script_domain_count"] = len(external_script_domains)
        result.metadata["fetch_stats"] = _http_stats
        result.metadata["crawl_duration_seconds"] = round(_crawl_duration_seconds, 3)

        # Propagate scan-wide retry/skip counters to top-level fields
        result.retry_count = _http_stats.get("retried", 0)
        result.skip_count = _http_stats.get("skipped", 0)

        return result

    @property
    def current_baseline(self) -> SiteBaseline | None:
        """The WADE baseline built from the most recent :meth:`scan` call."""
        return self._current_baseline

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
        external_script_domains: set[str],
    ) -> None:
        response = result.response
        artifacts = result.artifacts

        if response.failed:
            return

        # Response-based engines
        _add_findings(ctx, await _safe(ctx, self._security_headers.NAME, self._security_headers.analyze, response))
        _add_findings(ctx, await _safe(ctx, self._cors.NAME, self._cors.analyze, response))
        _add_findings(ctx, await _safe(ctx, self._cookies.NAME, self._cookies.analyze, response))
        _add_findings(ctx, await _safe(ctx, self._csp.NAME, self._csp.analyze, response))

        if artifacts is None:
            return

        # Collect external link domains from this page
        for link in artifacts.external_links:
            host = urlparse(link).hostname
            if host:
                external_domains.add(host.lower())

        # Collect all external script source domains (trusted and unknown alike)
        for script in artifacts.scripts:
            if script.is_external_domain and script.src:
                host = urlparse(script.src).hostname
                if host:
                    external_script_domains.add(host.lower())

        html_body: str | None = (
            response.body
            if _is_html(response.content_type) and response.body
            else None
        )

        # JsCollector — collects/structures JS resources (no findings output)
        _jsc_start = datetime.now(timezone.utc)
        _jsc_t0 = time.perf_counter()
        try:
            self._js_collector.collect(artifacts)
            _jsc_dur = (time.perf_counter() - _jsc_t0) * 1000
            if self._js_collector.NAME not in ctx.scan_result.engines_run:
                ctx.scan_result.engines_run.append(self._js_collector.NAME)
            ctx.tracker.record_run(
                self._js_collector.NAME, [], _jsc_dur, _jsc_start, datetime.now(timezone.utc)
            )
        except Exception as exc:
            _jsc_dur = (time.perf_counter() - _jsc_t0) * 1000
            _jsc_err = f"{type(exc).__name__}: {exc}"
            ctx.record_error(self._js_collector.NAME, _jsc_err)
            ctx.tracker.record_error(
                self._js_collector.NAME, _jsc_err, _jsc_dur, _jsc_start, datetime.now(timezone.utc)
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
        _add_findings(ctx, await _safe(ctx, self._secret_scanner.NAME, self._secret_scanner.analyze, artifacts, html_body=html_body))
        _add_findings(ctx, await _safe(ctx, self._wordpress.NAME, self._wordpress.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._shopify.NAME, self._shopify.analyze, artifacts, html_body=html_body))
        _add_findings(ctx, await _safe(ctx, self._wix.NAME, self._wix.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._endpoint_discovery.NAME, self._endpoint_discovery.analyze, artifacts))
        _add_findings(ctx, await _safe(ctx, self._threat_intel.NAME, self._threat_intel.analyze, artifacts))

    # ------------------------------------------------------------------
    # WADE — Website Anomaly Detection Engine
    # ------------------------------------------------------------------

    def _run_wade(self, ctx: ScanContext, crawl_results: list) -> None:
        """Build a WADE baseline and, if a previous baseline is available, compare."""
        wade_start = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        if not crawl_results:
            ctx.tracker.record_skip("wade", "no crawl results available")
            ctx.scan_result.metadata["wade_baseline_generated"] = False
            ctx.scan_result.metadata["wade_baseline_version"] = None
            ctx.scan_result.metadata["wade_compared_to_previous"] = False
            ctx.scan_result.metadata["wade_anomaly_count"] = 0
            return

        baseline = BaselineBuilder().build(crawl_results, ctx.scan_result)
        self._current_baseline = baseline
        ctx.scan_result.metadata["wade_baseline_generated"] = True
        ctx.scan_result.metadata["wade_baseline_version"] = baseline.scan_id

        if self._previous_baseline is None:
            ctx.tracker.record_skip("wade", "no previous baseline supplied")
            ctx.scan_result.metadata["wade_compared_to_previous"] = False
            ctx.scan_result.metadata["wade_anomaly_count"] = 0
            return

        try:
            diff_items = DiffEngine().diff_site(baseline.pages, self._previous_baseline)
            anomalies = AnomalyScorer().score(diff_items)
            findings = Classifier().classify(anomalies)
            adjust_findings_confidence(findings, anomalies)

            for f in findings:
                ctx.add_finding(f)

            duration_ms = (time.perf_counter() - t0) * 1000
            ctx.tracker.record_run(
                "wade", findings, duration_ms, wade_start, datetime.now(timezone.utc)
            )
            ctx.scan_result.metadata["wade_compared_to_previous"] = True
            ctx.scan_result.metadata["wade_anomaly_count"] = len(findings)
        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000
            err = f"{type(exc).__name__}: {exc}"
            ctx.record_error("wade", err)
            ctx.tracker.record_error("wade", err, duration_ms, wade_start, datetime.now(timezone.utc))
            ctx.scan_result.metadata["wade_compared_to_previous"] = False
            ctx.scan_result.metadata["wade_anomaly_count"] = 0

    # ------------------------------------------------------------------
    # TLS / DNS (blocking I/O wrapped in thread pool)
    # ------------------------------------------------------------------

    async def _run_tls_dns(self, ctx: ScanContext) -> None:
        target = self._target
        hostname = target.hostname
        port = target.port or (443 if target.is_https else 80)

        # TLS
        _tls_start = datetime.now(timezone.utc)
        _tls_t0 = time.perf_counter()
        try:
            cert_info = await asyncio.to_thread(
                _tls_module.probe_tls, hostname, port
            )
            _add_findings(ctx, await _safe(ctx, self._tls.NAME, self._tls.analyze, cert_info))
        except Exception as exc:
            _tls_dur = (time.perf_counter() - _tls_t0) * 1000
            _tls_err = f"{type(exc).__name__}: {exc}"
            ctx.record_error(self._tls.NAME, _tls_err)
            ctx.tracker.record_error(
                self._tls.NAME, _tls_err, _tls_dur, _tls_start, datetime.now(timezone.utc)
            )

        # DNS — SPF/DMARC live at the apex domain, not the www subdomain.
        _ext = _tldextract.extract(hostname)
        dns_domain = (
            f"{_ext.domain}.{_ext.suffix}"
            if _ext.domain and _ext.suffix
            else hostname
        )
        _dns_start = datetime.now(timezone.utc)
        _dns_t0 = time.perf_counter()
        try:
            dns_records = await asyncio.to_thread(
                _dns_module.resolve_dns, dns_domain
            )
            _add_findings(ctx, await _safe(ctx, self._dns.NAME, self._dns.analyze, dns_records))
        except Exception as exc:
            _dns_dur = (time.perf_counter() - _dns_t0) * 1000
            _dns_err = f"{type(exc).__name__}: {exc}"
            ctx.record_error(self._dns.NAME, _dns_err)
            ctx.tracker.record_error(
                self._dns.NAME, _dns_err, _dns_dur, _dns_start, datetime.now(timezone.utc)
            )
