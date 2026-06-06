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
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import tldextract as _tldextract

logger = logging.getLogger(__name__)


def _safe_hostname(url: str | None) -> str | None:
    """Best-effort hostname extraction used by browser-pass plumbing.
    Returns None when ``url`` is falsy or malformed."""
    if not url:
        return None
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None

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
    """Compute the 0–100 risk score. Phase-7: delegates to the
    centralized :mod:`webhound.core.risk_scoring` module — the
    trust-weighted model for annotated results, the legacy
    quality-weighted model for everything else. Kept as a thin alias
    because tests and callers import it from here."""
    from webhound.core.risk_scoring import compute_risk_score
    risk, level, _breakdown = compute_risk_score(result)
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
        # Scan-wide host inventory: each per-page contribution is gathered
        # during the per-page engine loop so the post-crawl threat-intel
        # pass operates on the deduplicated, scan-wide host set rather
        # than re-classifying the same vendor host once per page.
        host_contributions: list = []
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
                # Phase-6C: post-crawl passes correlate static and
                # rendered views through the context.
                ctx.crawl_results = crawl_results

                # 3. Per-page engines
                for result in crawl_results:
                    await self._run_page_engines(
                        result, ctx, external_domains,
                        external_script_domains, host_contributions,
                    )

                # Capture HTTP stats before the client closes
                _http_stats = client.fetch_stats.to_dict()

            # 3b. Optional Playwright browser pass — opt-in via
            # ScanOptions.browser_enabled (set by ENTERPRISE profile).
            # Captures fetch/XHR/WebSocket/EventSource/iframe traffic
            # that the static crawler can't see on SPA / Next.js /
            # React / Vue / Angular pages. Best-effort: missing
            # Playwright install / missing Chromium / per-page errors
            # all degrade gracefully — telemetry is recorded for
            # whatever pages succeeded and the rest of the scan
            # proceeds normally.
            browser_telemetries: list = []
            if self._target.scan_options.browser_enabled:
                try:
                    await self._run_browser_pass(
                        ctx, crawl_results, browser_telemetries,
                        host_contributions,
                    )
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "browser pass failed; static crawl results "
                        "intact", exc_info=True,
                    )

            # 3c. Phase-5B canonical inventory extension. Walk every
            # crawled page's response and append a synthetic
            # PageHostContribution carrying the CSP source-list hosts
            # (vendors the page is *allowed* to load from, even if no
            # element references them) + the redirect-chain hops the
            # static crawler followed. Pure post-processing — does not
            # touch network. Best-effort; ignored on failure.
            try:
                from webhound.core.url_discovery import (
                    build_response_inventory_contribution,
                )
                for r in crawl_results:
                    resp = getattr(r, "response", None)
                    if resp is None or getattr(resp, "failed", True):
                        continue
                    host_contributions.append(
                        build_response_inventory_contribution(
                            resp.url,
                            headers=getattr(resp, "headers", None) or {},
                            redirect_chain=getattr(
                                resp, "redirect_chain", None,
                            ) or [],
                        ),
                    )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "csp/redirect inventory extension failed",
                    exc_info=True,
                )

            # 4. TLS / DNS — blocking I/O, run in thread pool
            await self._run_tls_dns(ctx)

            # 4b. Scan-wide threat-intel inventory pass — runs once over
            # the aggregated host set so JS-discovered or
            # network-captured hosts that no single page's static HTML
            # referenced still get classified. Skips hosts the per-page
            # threat_intel engine already flagged so the two passes don't
            # double-emit. Safe to fail — per-page findings still ship.
            try:
                from webhound.core.url_discovery import aggregate_host_inventory
                inventory = aggregate_host_inventory(host_contributions)
                already = {
                    (f.metadata or {}).get("host")
                    for f in ctx.scan_result.findings
                    if f.scanner_engine == self._threat_intel.NAME
                    and (f.metadata or {}).get("host")
                }
                inv_findings = await self._threat_intel.analyze_inventory(
                    inventory, already_classified_hosts=already,
                )
                for finding in inv_findings:
                    ctx.scan_result.findings.append(finding)
                ctx.scan_result.metadata["scan_wide_host_count"] = len(inventory)
                ctx.scan_result.metadata["scan_wide_threat_intel_findings"] = (
                    len(inv_findings)
                )
                # Phase-5C: audit every inventory host against the local
                # classifier so the JSON export carries threat-intel
                # coverage stats + the per-host inventory entries get
                # vendor_classification / threat_intel_state populated.
                try:
                    from webhound.threat_intel.coverage import (
                        audit_threat_intel_coverage,
                    )
                    enriched_hosts = {
                        h for h in inventory.keys() if h in already
                    }
                    cov_report = audit_threat_intel_coverage(
                        inventory, already_enriched=enriched_hosts,
                    )
                    ctx.scan_result.metadata["threat_intel_coverage"] = (
                        cov_report.to_dict()
                    )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "threat-intel coverage audit failed",
                        exc_info=True,
                    )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "scan-wide threat-intel inventory pass failed; using "
                    "per-page findings only", exc_info=True,
                )

            # 4c. ASM-lite asset discovery (Phase-4) — only when the
            # active profile opts in via asm_enabled. Wraps the
            # passive subdomain pass + common-prefix DNS probe + asset
            # map aggregation. Stored under metadata.asset_map for the
            # dashboard. Off by default; ENTERPRISE profile turns it
            # on. Best-effort — any failure leaves the scan otherwise
            # intact and the metadata.asset_map flag absent.
            if self._target.scan_options.asm_enabled:
                try:
                    from webhound.core.url_discovery import (
                        aggregate_host_inventory,
                    )
                    _inv = aggregate_host_inventory(host_contributions or [])
                    await self._run_asm(
                        ctx, inventory_external_hosts=set(_inv.keys()),
                    )
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "ASM asset-discovery pass failed; scan output "
                        "unaffected", exc_info=True,
                    )

            # 5. WADE — build baseline; optionally compare against previous
            self._run_wade(ctx, crawl_results)

        except Exception as exc:
            ctx.scan_result.mark_failed(str(exc))
            return ctx.scan_result

        # 6. Deduplicate
        ctx.scan_result.findings = _dedup_findings(ctx.scan_result.findings)

        # 7. False-positive suppression — reduce confidence on known CDN/platform patterns
        ctx.scan_result.findings = FPFilter().filter(ctx.scan_result.findings)

        # 7b. Cross-engine correlation — adds cluster findings + corroboration
        # bumps when multiple engines independently point at the same threat
        # chain (e.g. weak CSP + risky third-party + obfuscated inline JS =
        # supply-chain compromise risk). Defensive: failures here must never
        # suppress the per-engine findings we already have.
        try:
            from webhound.core.correlation import (
                apply_correlation, correlate_findings,
            )
            corr_result = correlate_findings(ctx.scan_result.findings)
            ctx.scan_result.findings = apply_correlation(
                ctx.scan_result.findings, corr_result,
            )
        except Exception:  # noqa: BLE001
            logger.warning("correlation pass failed; using per-engine findings only",
                           exc_info=True)

        # 7c. Phase-7 trust policy + severity calibration. Annotates
        # every finding with finding_type / confidence_label, then
        # applies the demotion-only severity clamps (heuristics can't
        # be CRITICAL, headers are hardening, etc). Runs BEFORE
        # grouping so groups inherit calibrated severities. Failures
        # leave findings unannotated — the risk scorer then falls back
        # to the legacy algorithm, never crashes.
        try:
            from webhound.core.severity_calibrator import calibrate_findings
            from webhound.core.trust_policy import apply_trust_policy
            apply_trust_policy(ctx.scan_result.findings)
            demotions = calibrate_findings(ctx.scan_result.findings)
            ctx.scan_result.metadata["severity_calibration_demotions"] = (
                demotions
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "trust policy / calibration pass failed; scoring will "
                "use legacy algorithm", exc_info=True,
            )

        result = ctx.finish()

        # 8. Group findings for clean reporting and fair risk scoring
        result.grouped_findings = FindingGrouper().group(result.active_findings)

        # 8a. Annotate the grouped view too — grouping copies severity
        # from calibrated raw findings, but finding_type/confidence
        # labels live in metadata, which the grouper rebuilds.
        try:
            from webhound.core.trust_policy import apply_trust_policy
            apply_trust_policy(result.grouped_findings)
        except Exception:  # noqa: BLE001
            logger.debug("grouped trust annotation failed", exc_info=True)

        # 8b. Phase-5D evidence-quality audit. Advisory — does not
        # mutate findings. Report lands in
        # metadata.evidence_quality so the dashboard can render an
        # "evidence complete" / "evidence incomplete (N)" badge per
        # engine and the production-readiness module can use the
        # completeness ratio.
        try:
            from webhound.core.evidence_quality import audit_findings
            quality_report = audit_findings(result.active_findings)
            result.metadata["evidence_quality"] = quality_report.to_dict()
        except Exception:  # noqa: BLE001
            logger.debug(
                "evidence quality audit failed", exc_info=True,
            )

        # 8c. Phase-5H WADE quality review. Advisory only — flags
        # possible FPs, weak evidence, duplicates, missing
        # corroboration, suspicious scoring. Does not invent
        # findings, does not mutate severity/confidence. Report
        # lands in metadata.wade_quality_review.
        try:
            from webhound.wade.quality_review import review_scan
            wade_review = review_scan(result)
            result.metadata["wade_quality_review"] = wade_review.to_dict()
        except Exception:  # noqa: BLE001
            logger.debug(
                "WADE quality review failed", exc_info=True,
            )

        # 8d. Phase-5I production readiness scoring. Rolls every
        # audit signal into one 0-100 score + per-dimension
        # breakdown + actionable gap list.
        try:
            from webhound.reporting.production_readiness import score_scan
            readiness = score_scan(result)
            result.metadata["production_readiness"] = readiness.to_dict()
        except Exception:  # noqa: BLE001
            logger.debug(
                "production readiness scoring failed", exc_info=True,
            )

        # 9. Risk scoring — centralized (Phase-7). The transparent
        # breakdown lands in metadata so the dashboard can show WHY.
        from webhound.core.risk_scoring import compute_risk_score
        risk_score, risk_level, risk_breakdown = compute_risk_score(result)
        result.metadata["risk_score"] = risk_score
        result.metadata["risk_level"] = risk_level
        if risk_breakdown is not None:
            result.metadata["risk_breakdown"] = risk_breakdown.to_dict()
        result.metadata["external_domains"] = sorted(external_domains)
        result.metadata["external_domain_count"] = len(external_domains)
        result.metadata["external_script_domains"] = sorted(external_script_domains)
        result.metadata["external_script_domain_count"] = len(external_script_domains)
        result.metadata["fetch_stats"] = _http_stats
        result.metadata["crawl_duration_seconds"] = round(_crawl_duration_seconds, 3)

        # Propagate scan-wide retry/skip counters to top-level fields
        result.retry_count = _http_stats.get("retried", 0)
        result.skip_count = _http_stats.get("skipped", 0)

        # Phase-6C (Task 9): consolidated coverage summary — static +
        # browser views in one place for reporting / trust indicators.
        # Additive metadata; failures never disturb the result.
        try:
            static_forms = 0
            static_scripts = 0
            for r in crawl_results:
                arts = getattr(r, "artifacts", None)
                if arts is None:
                    continue
                static_forms += len(getattr(arts, "forms", None) or [])
                static_scripts += len(getattr(arts, "scripts", None) or [])
            bstats = ctx.browser.coverage_stats()
            result.metadata["coverage_summary"] = {
                "pages_crawled": result.urls_crawled,
                "browser_pages_rendered": bstats["browser_pages_rendered"],
                "browser_render_failures": bstats["browser_render_failures"],
                "static_scripts_collected": static_scripts,
                "browser_scripts_collected": bstats["browser_scripts_found"],
                "static_forms_discovered": static_forms,
                "rendered_forms_discovered": bstats["rendered_forms_found"],
                "api_endpoints_observed": len(
                    ctx.browser.get_all_api_endpoints()
                ),
                "third_party_domains_observed": len(set(
                    list(external_domains)
                    + ctx.browser.get_all_third_party_domains(
                        primary_host=self._target.hostname,
                    )
                )),
                "browser_client_routes_found": bstats[
                    "browser_client_routes_found"
                ],
                "skipped_out_of_scope_browser_urls": bstats[
                    "skipped_out_of_scope_browser_urls"
                ],
                "browser_pass_available": ctx.browser.available,
                "browser_pass_error": ctx.browser.error,
            }
        except Exception:  # noqa: BLE001
            logger.debug("coverage summary build failed", exc_info=True)

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
        host_contributions: list | None = None,
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

        # Capture this page's contribution to the scan-wide host inventory.
        # Defensive: import + build inside try so a malformed artifacts blob
        # never aborts the per-page engine loop.
        if host_contributions is not None:
            try:
                from webhound.core.url_discovery import PageHostContribution
                host_contributions.append(
                    PageHostContribution.from_artifacts(artifacts)
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "PageHostContribution.from_artifacts failed for %s",
                    getattr(artifacts, "url", "?"), exc_info=True,
                )

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
    # ASM-lite — passive subdomain discovery + DNS probe (Phase-4)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Playwright browser pass (Phase-5A)
    # ------------------------------------------------------------------

    async def _run_browser_pass(
        self,
        ctx: ScanContext,
        crawl_results: list,
        browser_telemetries: list,
        host_contributions: list,
    ) -> None:
        """Drive a headless Chromium against every successfully-crawled
        page, capture every fetch / XHR / WebSocket / EventSource /
        iframe artifact, and fold the discovered hosts back into the
        scan-wide ``host_contributions`` list so the existing
        threat-intel inventory pass + ASM aggregator see them.

        Best-effort. Per-page errors land in
        ``BrowserTelemetry.errors``; runner-level failures
        (Playwright not installed, Chromium missing) produce a
        deferred result that's logged and ignored. Either way, the
        rest of the scan completes."""
        from webhound.browser.models import (
            aggregate_browser_hosts,
        )
        from webhound.browser.playwright_runner import (
            browser_pass_enabled,
            run_browser_pass,
        )
        from webhound.core.url_discovery import PageHostContribution

        # The browser pass needs *real* navigation, so allow_network
        # is gated by the WEBHOUND_BROWSER_ENABLED operator env var in
        # addition to the profile flag. This means "the profile asked
        # for it AND the operator has opted in on this worker box".
        allow_net = browser_pass_enabled()

        page_urls = [
            r.response.url for r in crawl_results
            if getattr(r, "response", None)
            and not getattr(r.response, "failed", True)
        ]
        if not page_urls:
            return

        t0 = time.perf_counter()
        started_at = datetime.now(timezone.utc)
        result = await run_browser_pass(
            page_urls, allow_network=allow_net,
            user_agent=self._target.scan_options.user_agent,
            url_filter=ctx.scope.is_in_scope,
        )
        duration_ms = (time.perf_counter() - t0) * 1000.0

        # Attach the discovery container so engines + reporting access
        # browser data through ctx.browser instead of raw telemetries.
        from webhound.browser.models import BrowserDiscovery
        ctx.browser_discovery = BrowserDiscovery(
            telemetries=list(result.telemetries),
            deferred=result.deferred,
            error=result.error,
            skipped_urls=list(result.skipped_urls or []),
        )

        # Record diagnostics regardless of deferred/error state so
        # operators can see whether the pass ran.
        if result.deferred:
            ctx.tracker.record_skip(
                "browser", result.error or "deferred",
            )
        else:
            browser_telemetries.extend(result.telemetries)
            for tel in result.telemetries:
                # Each browser-observed external URL contributes to
                # the scan-wide host inventory as a new (url, kind)
                # pair attributed to this page. PageHostContribution
                # already knows how to dedupe inside
                # aggregate_host_inventory, so duplicates are fine.
                pairs = [
                    (art.url, art.initiator_kind or "browser")
                    for art in tel.artifacts
                    if art.url
                ]
                host_contributions.append(
                    PageHostContribution(
                        page_url=tel.page_url,
                        page_host=_safe_hostname(tel.page_url),
                        urls=pairs,
                    ),
                )
            ctx.tracker.record_run(
                "browser", [], duration_ms, started_at,
                datetime.now(timezone.utc),
            )
            if "browser" not in ctx.scan_result.engines_run:
                ctx.scan_result.engines_run.append("browser")

        # Phase-6A: run the rendered-DOM engine pass over whatever
        # pages produced a post-hydration HTML snapshot. Best-effort —
        # a failure here never disturbs the static findings.
        rendered_stats: dict[str, Any] = {}
        if not result.deferred:
            try:
                rendered_stats = await self._run_rendered_dom_engines(
                    ctx, result.telemetries, crawl_results,
                    host_contributions,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "rendered-DOM engine pass failed; static findings "
                    "intact", exc_info=True,
                )
            # Phase-6C (Task 5): inventory the API traffic the browser
            # actually fired. INFO/LOW only — observed traffic is
            # application behaviour, not a vulnerability.
            try:
                observed = await _safe(
                    ctx, self._endpoint_discovery.NAME,
                    self._endpoint_discovery.analyze_observed_requests,
                    ctx.browser.get_all_network_requests(),
                    primary_host=(self._target.hostname or "").lower(),
                )
                for f in observed:
                    ctx.add_finding(f)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "observed-API inventory failed", exc_info=True,
                )

        # Roll up browser-specific host inventory + Phase-6B coverage
        # counters for the JSON export. Discovery statistics only —
        # nothing here feeds risk scoring or findings.
        try:
            from webhound.browser.network_capture import summarize_network
            primary = (self._target.hostname or "").lower()
            browser_inv = aggregate_browser_hosts(
                browser_telemetries, primary_host=primary,
            )
            tels = result.telemetries
            net = summarize_network(tels, primary_host=primary)
            skipped = list(result.skipped_urls or [])
            ctx.scan_result.metadata["browser_pass"] = {
                "deferred": result.deferred,
                "error": result.error,
                "page_count": len(tels),
                "artifact_count": sum(len(t.artifacts) for t in tels),
                "host_count": len(browser_inv),
                "duration_ms": round(duration_ms, 2),
                "hosts": sorted(browser_inv.keys()),
                # Coverage counters (Phase-6B)
                "browser_pages_rendered": sum(
                    1 for t in tels if t.rendered_html
                ),
                "browser_render_failures": sum(
                    1 for t in tels if t.errors or not t.rendered_html
                ),
                "rendered_links_found": sum(
                    len(t.rendered_links) for t in tels
                ),
                "rendered_forms_found": sum(
                    len(t.rendered_forms) for t in tels
                ),
                "browser_scripts_found": sum(
                    len(t.rendered_scripts) for t in tels
                ),
                "browser_client_routes_found": sum(
                    len(t.client_routes) for t in tels
                ),
                "browser_console_errors": sum(
                    len(t.console_messages) for t in tels
                ),
                "browser_interactions": sum(
                    len(t.interactions) for t in tels
                ),
                "browser_blocked_interactions": sum(
                    t.blocked_interactions for t in tels
                ),
                "skipped_out_of_scope_browser_urls": len(skipped),
                "skipped_browser_urls": [
                    {"url": u, "reason": r} for u, r in skipped[:25]
                ],
                **net.to_dict(),
                **rendered_stats,
            }
        except Exception:  # noqa: BLE001
            logger.debug(
                "browser-pass metadata write failed", exc_info=True,
            )

    # ------------------------------------------------------------------
    # Rendered-DOM engine pass (Phase-6A)
    # ------------------------------------------------------------------

    # Engines that may run over rendered-DOM artifacts. Deliberately
    # conservative:
    #   * form engines       — lazy-loaded / JS-injected forms are the
    #     #1 thing the static crawler misses on SPAs.
    #   * hidden_iframes     — runtime-injected iframes are a
    #     compromise indicator the static pass can't see.
    #   * secret_scanner     — runtime config blobs rendered into the
    #     DOM (window.__ENV__ et al.) can expose real keys.
    #   * js_analyzer        — pattern engine over rendered inline
    #     scripts (hydration payloads the static HTML never carried).
    #   * third_party        — vendor domains that only attach after
    #     hydration (tag managers injecting tags).
    #   * endpoint_discovery — API references in rendered client code.
    # Header/CSP/cookie engines are EXCLUDED (the browser pass carries
    # no response headers — running them would fabricate "missing
    # header" findings). injected_js / obfuscation are EXCLUDED because
    # on an SPA *all* content is runtime-injected; running them on the
    # rendered DOM would manufacture false positives.

    async def _run_rendered_dom_engines(
        self,
        ctx: ScanContext,
        telemetries: list,
        crawl_results: list,
        host_contributions: list,
    ) -> dict[str, Any]:
        """Parse each page's post-hydration HTML through the existing
        Extractor and run the rendered-safe engine subset over it.

        Findings are tagged ``rendered_dom`` (tag + metadata
        evidence_source) so reporting can attribute them to the browser
        pass. Duplicates of static findings are collapsed later by
        ``_dedup_findings`` (same engine + title + evidence location).

        Returns coverage stats for the ``browser_pass`` metadata block:
        how many pages rendered, how many forms only the browser saw,
        and how many same-origin links the static crawler missed."""
        from uuid import uuid4
        from webhound.core.extractor import Extractor
        from webhound.core.http_client import HttpResponse
        from webhound.core.url_discovery import PageHostContribution

        extractor = Extractor()
        rendered_pages = 0
        rendered_form_count = 0
        rendered_findings: list[Finding] = []

        # Everything the static crawl already knows about, fragment-
        # stripped, so rendered-only links can be counted honestly.
        static_known: set[str] = set()
        for r in crawl_results:
            resp = getattr(r, "response", None)
            if resp is not None and not getattr(resp, "failed", True):
                static_known.add(resp.url.split("#", 1)[0])
            arts = getattr(r, "artifacts", None)
            if arts is not None:
                for link in getattr(arts, "all_links", None) or []:
                    static_known.add(link.split("#", 1)[0])

        primary = (self._target.hostname or "").lower()
        rendered_only_links: set[str] = set()

        for tel in telemetries:
            page_url = tel.final_url or tel.page_url

            # Rendered links: same-origin ones the static crawl never
            # saw are the SPA-route discovery win; all of them feed the
            # scan-wide host inventory.
            if tel.rendered_links:
                host_contributions.append(PageHostContribution(
                    page_url=page_url,
                    page_host=_safe_hostname(page_url),
                    urls=[(u, "rendered_link") for u in tel.rendered_links],
                ))
                for link in tel.rendered_links:
                    bare = link.split("#", 1)[0]
                    if (bare not in static_known
                            and (_safe_hostname(bare) or "") == primary):
                        rendered_only_links.add(bare)

            if not tel.rendered_html:
                continue

            synthetic = HttpResponse(
                request_id=uuid4(),
                original_url=page_url,
                url=page_url,
                status_code=200,
                headers={},
                body=tel.rendered_html,
                content_type="text/html",
                elapsed_ms=0.0,
                redirect_count=0,
                redirect_chain=[],
                captured_at=datetime.now(timezone.utc),
            )
            artifacts = extractor.extract(synthetic)
            if artifacts is None:
                continue
            rendered_pages += 1
            rendered_form_count += len(artifacts.forms)

            page_findings: list[Finding] = []
            page_findings += await _safe(
                ctx, self._form_risk.NAME,
                self._form_risk.analyze, artifacts,
            )
            page_findings += await _safe(
                ctx, self._input_analysis.NAME,
                self._input_analysis.analyze, artifacts,
            )
            page_findings += await _safe(
                ctx, self._hidden_iframes.NAME,
                self._hidden_iframes.analyze, artifacts,
                html_body=tel.rendered_html,
            )
            page_findings += await _safe(
                ctx, self._secret_scanner.NAME,
                self._secret_scanner.analyze, artifacts,
                html_body=tel.rendered_html,
            )
            page_findings += await _safe(
                ctx, self._js_analyzer.NAME,
                self._js_analyzer.analyze, artifacts,
            )
            page_findings += await _safe(
                ctx, self._third_party.NAME,
                self._third_party.analyze, artifacts,
            )
            page_findings += await _safe(
                ctx, self._endpoint_discovery.NAME,
                self._endpoint_discovery.analyze, artifacts,
            )
            rendered_findings.extend(page_findings)

        # Attribute every rendered-pass finding to its evidence source
        # so reporting and the dashboard can show "seen in the rendered
        # DOM" vs "seen in static HTML". The evidence itself carries a
        # human-readable discovery note (Task-6 wording) without
        # touching the original engine-produced evidence content.
        for f in rendered_findings:
            if "rendered_dom" not in (f.tags or []):
                f.tags = (f.tags or []) + ["rendered_dom"]
            f.metadata = {**(f.metadata or {}),
                          "evidence_source": "rendered_dom",
                          "discovery_note": "Discovered in rendered DOM"}
            for ev in f.evidence or []:
                ev.extra = {**(ev.extra or {}),
                            "evidence_source": "rendered_dom",
                            "discovered_in": "rendered DOM (browser pass)"}
            ctx.add_finding(f)

        return {
            "rendered_pages": rendered_pages,
            "rendered_form_count": rendered_form_count,
            "rendered_finding_count": len(rendered_findings),
            "rendered_only_link_count": len(rendered_only_links),
            "rendered_only_links": sorted(rendered_only_links)[:25],
        }

    async def _run_asm(
        self,
        ctx: ScanContext,
        *,
        inventory_external_hosts: set[str],
    ) -> None:
        """Run the opt-in ASM-lite pass. Gated by ``asm_enabled`` on the
        scan options. Discovered surface lands in
        ``scan_result.metadata.asset_map``; failures are logged but
        never raise out of this method (so the rest of the scan
        finishes either way).

        ``inventory_external_hosts`` is the deduped third-party host
        set the threat-intel pipeline already gathered — fed straight
        into :func:`asm.build_asset_map` so the asset map references
        every host the scan observed."""
        import tldextract as _tld
        from webhound.asm.asset_discovery import (
            build_asset_map,
            common_subdomain_check,
            passive_subdomain_discovery,
        )

        target_host = (self._target.hostname or "").lower()
        if not target_host:
            return
        ext = _tld.extract(target_host)
        registrable = (
            f"{ext.domain}.{ext.suffix}"
            if ext.domain and ext.suffix else target_host
        )
        asm_t0 = time.perf_counter()
        asm_start = datetime.now(timezone.utc)

        # 1. CT-log lookup. Bounded by httpx timeout inside the
        #    helper; offline-safe — passes through transport.
        allow_network = os.getenv(
            "WEBHOUND_ASM_ALLOW_NETWORK", "1",
        ) != "0"
        ct = await passive_subdomain_discovery(
            registrable, allow_network=allow_network,
        )

        # 2. Common-prefix DNS probe. Resolver is the asyncio loop's
        #    getaddrinfo — wrapped so a failed lookup is just a
        #    no-resolve rather than an exception.
        async def _resolve(host: str) -> bool:
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(
                    host, None,
                    family=0, type=0, proto=0, flags=0,
                )
                return bool(infos)
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception:  # noqa: BLE001
                return False

        probe = await common_subdomain_check(
            registrable, resolve=_resolve,
        )

        asset_map = build_asset_map(
            target_host,
            ct_subdomains=ct.hostnames,
            common_subdomains=probe.hostnames,
            external_hosts=inventory_external_hosts,
        )
        asm_duration = (time.perf_counter() - asm_t0) * 1000.0

        # Pop the asset map into scan-result metadata in a stable
        # JSON-shaped form. Sorted lists for deterministic serialisation.
        ctx.scan_result.metadata["asset_map"] = {
            "primary_host": asset_map.primary_host,
            "ct_subdomains": sorted(asset_map.ct_subdomains),
            "common_subdomains": sorted(asset_map.common_subdomains),
            "external_hosts": sorted(asset_map.external_hosts),
            "total_surface_count": asset_map.total_surface_count,
            "exposure_signals": asset_map.exposure_signals(),
            "ct_source": ct.source,
            "ct_deferred": ct.deferred,
            "ct_error": ct.error,
        }
        # Track the ASM pass in the engine tracker so the diagnostics
        # surface shows it ran (and how long it took).
        ctx.tracker.record_run(
            "asm", [], asm_duration, asm_start,
            datetime.now(timezone.utc),
        )
        if "asm" not in ctx.scan_result.engines_run:
            ctx.scan_result.engines_run.append("asm")

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
