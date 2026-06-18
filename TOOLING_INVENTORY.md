# WebHound Tooling Inventory — Phase 8X Audit
**Date:** 2026-06-17 | **Branch:** feat/tooling-phase-8x-integration-audit
**Status context:** 9B-B (PR #22) OPEN, NOT merged. Audit reflects main without 9B-B hardening.

---

## 1. SCANNER ENGINES (31 total — ALL production-wired)

| Engine | Class | Category | Pipeline Phase |
|--------|-------|----------|----------------|
| SecurityHeadersEngine | headers/security_headers.py | Headers | Target-level |
| CorsEngine | headers/cors.py | Headers | Target-level |
| CspEngine | headers/csp_engine.py | Headers | Target-level |
| JsCollectorEngine | javascript/js_collector.py | JavaScript | Per-page |
| JsAnalyzerEngine | javascript/js_analyzer.py | JavaScript | Per-page |
| JsFetcherEngine *(async)* | javascript/js_fetcher.py | JavaScript | Per-page |
| ObfuscationDetectorEngine | javascript/obfuscation_detector.py | JavaScript | Per-page |
| ThirdPartyDomainEngine | javascript/third_party_domains.py | JavaScript | Per-page |
| VulnerableLibsEngine | javascript/vulnerable_libs.py | JavaScript | Per-page + scan-wide |
| SourceMapProbeEngine *(async)* | javascript/source_map_probe.py | JavaScript | Per-page |
| CookieScannerEngine | cookies/cookie_scanner.py | Cookies | Target-level |
| FormRiskEngine | forms/form_risk.py | Forms | Per-page |
| InputAnalysisEngine | forms/input_analysis.py | Forms | Per-page |
| FormDiscoveryEngine | forms/form_discovery.py | Forms | Per-page |
| ParameterDiscoveryEngine | forms/parameter_discovery.py | Forms | Per-page |
| TlsCheckerEngine | tls_dns/tls_checker.py | TLS/DNS | Thread pool |
| DnsCheckerEngine | tls_dns/dns_checker.py | TLS/DNS | Thread pool |
| TakeoverProbeEngine | tls_dns/takeover_probe.py | TLS/DNS | Thread pool |
| TechnologyEngine | recon/technology.py | Recon | Per-page |
| SensitivePathsEngine | recon/sensitive_paths.py | Recon | Per-page |
| RobotsAndSitemapEngine *(async)* | recon/robots_sitemap.py | Recon | Per-page |
| WordpressEngine | cms/wordpress.py | CMS | Per-page |
| ShopifyEngine | cms/shopify.py | CMS | Per-page |
| WixEngine | cms/wix.py | CMS | Per-page |
| InjectedJsEngine | compromise/injected_js.py | Compromise | Per-page |
| HiddenIframesEngine | compromise/hidden_iframes.py | Compromise | Per-page |
| SeoSpamEngine | compromise/seo_spam.py | Compromise | Per-page |
| SuspiciousRedirectsEngine | compromise/suspicious_redirects.py | Compromise | Per-page |
| ThreatIntelEngine *(async)* | threat_intel/external_domains.py | Threat Intel | Per-page + scan-wide |
| EndpointDiscoveryEngine | api_discovery/endpoint_discovery.py | API Discovery | Per-page |
| WADE (baseline/diff/anomaly/classify) | wade/* via orchestrator._run_wade() | Anomaly Detection | Phase 5 |

---

## 2. SCANNER CORE MODULES

| Module | File | Purpose |
|--------|------|---------|
| Scanner (orchestrator) | core/orchestrator.py | 23-phase pipeline, main entry point |
| Crawler | core/crawler.py | BFS site traversal, artifact extraction |
| ScanContext | core/scan_context.py | Mutable per-scan state |
| SafeHttpClient | core/http_client.py | Rate-limited async HTTP |
| PageArtifacts | core/extractor.py | DOM element extraction from HTML |
| ScanProfiles | core/scan_profiles.py | quick/standard/deep/monitor/enterprise |
| SessionContext | core/session_context.py | Auth headers/cookies for authenticated scans |
| FPFilter | core/fp_filter.py | False-positive confidence reduction |
| Correlation | core/correlation.py | Cross-engine finding clustering |
| RiskScoring | core/risk_scoring.py | 0–100 risk score computation |
| SecurityStories | core/security_stories.py | Narrative threat chain builder |
| FindingGrouper | core/finding_grouper.py | Groups findings by issue |
| TrustPolicy | core/trust_policy.py | confirmed/heuristic/indicator annotation |
| SeverityCalibrator | core/severity_calibrator.py | Demotion-only severity clamping |
| SsrfGuard | core/ssrf_guard.py | Prevents internal IP scanning |

---

## 3. WADE MODULES

### Production-wired (via orchestrator._run_wade())
| Module | File | Role |
|--------|------|------|
| BaselineBuilder | wade/baseline_builder.py | Snapshot current crawl state |
| BaselineStore | wade/baseline_store.py | Persist/retrieve baselines |
| DiffEngine | wade/diff_engine.py | Compare baseline→current |
| AnomalyScorer | wade/anomaly_scorer.py | Score changes (anomaly level) |
| Classifier | wade/classifier.py | Anomalies → Findings |
| ConfidenceEngine | wade/confidence.py | Per-finding confidence scoring |
| ContextEngine | wade/context_engine.py | Page sensitivity weights |
| ChangeClassifier | wade/change_classifier.py | WADE 2.0 change intelligence |
| ChangeTypes | wade/change_types.py | Change type taxonomy |
| Timeline | wade/timeline.py | Change history per finding |
| Suppression | wade/suppression.py | Alert-fatigue suppression |
| VendorIntel | wade/vendor_intel.py | Vendor-change detection |
| QualityReview | wade/quality_review.py | Advisory metadata (non-actionable) |

### API integration (production, optional post-scan)
| File | Role |
|------|------|
| apps/api/services/wade_correlation.py | Cross-scan behavioural anomalies |
| apps/api/services/baselines.py | WADE baseline persistence |
| apps/api/routers/baselines.py | WADE API endpoints (GET baselines, wade-summary) |

### ISOLATED — not called from production scanner
| Module | File | Role |
|--------|------|------|
| RetrievalService | scripts/wade/retrieval_service.py | Hybrid knowledge retrieval |
| ContextBuilder | scripts/wade/context_builder.py | Advisory context assembly |
| TaxonomyResolver | scripts/wade/taxonomy_resolver.py | Finding-type taxonomy |
| ProviderResolver | scripts/wade/provider_resolver.py | Provider-specific guidance |
| FPResolver | scripts/wade/false_positive_resolver.py | FP pattern reference |
| LanguageResolver | scripts/wade/language_resolver.py | Customer-safe language |
| 9 reasoning modules | scripts/wade/reasoning/*.py | Attack chains, root cause, priority |

---

## 4. MCP INVENTORY

| MCP | Installed (.mcp.json) | Configured | Reachable | Used | Status |
|-----|-----------------------|------------|-----------|------|--------|
| claude-flow | **YES** | YES | YES | YES | GREEN — active |
| Filesystem | NO (documented only) | NO | NO | NO | RED — missing |
| GitHub | NO (documented only) | NO | NO | NO | RED — missing |
| Playwright | NO (documented only) | NO | NO | NO | RED — missing |
| Firecrawl | NO (documented only) | NO | NO | NO | RED — missing |
| Perplexity | NO (documented only) | NO | NO | NO | RED — missing |

**Evidence:** `.mcp.json` contains only claude-flow entry. Phase-1 MCPs are documented in `docs/ai/mcp/` but were never installed. 1 of 6 planned MCPs active.

---

## 5. SECURITY TOOLS AUDIT

**Verdict: ALL of the below were ingested as knowledge documentation (Phase 6C docs in `knowledge/detection-engineering/`). NONE are installed as binaries, called via subprocess, or integrated into the scanner pipeline.**

| Tool | Purpose | Installed | Called | Feeds Scanner | Feeds WADE | Status |
|------|---------|-----------|--------|---------------|------------|--------|
| Nuclei | Vulnerability templating | NO | NO | NO | NO | RED — knowledge-only |
| OWASP ZAP | Web proxy/scanner | NO | NO | NO | NO | RED — knowledge-only |
| sqlmap | SQL injection | NO | NO | NO | NO | RED — knowledge-only |
| XSStrike | XSS scanner | NO | NO | NO | NO | RED — knowledge-only |
| DalFox | XSS exploitation | NO | NO | NO | NO | RED — knowledge-only |
| libinjection | Injection lib | NO | NO | NO | NO | RED — knowledge-only |
| Semgrep | SAST | NO | NO | NO | NO | RED — knowledge-only |
| Gitleaks | Secret scanning | NO | NO | NO | NO | RED — knowledge-only |
| Trivy | Container security | NO | NO | NO | NO | RED — knowledge-only |
| Katana | Web crawler | NO | NO | NO | NO | RED — knowledge-only |
| httpx (ProjectDiscovery binary) | HTTP probe CLI | NO | NO | NO | NO | RED — knowledge-only |
| dnsx | DNS probe | NO | NO | NO | NO | RED — knowledge-only |
| subfinder | Subdomain enum | NO | NO | NO | NO | RED — knowledge-only |
| Amass | OSINT/subdomain | NO | NO | NO | NO | RED — knowledge-only |
| Firecrawl | Web scraping | NO | NO | NO | NO | RED — knowledge-only |

**Note:** `httpx` (Python library) IS production-integrated — 65 files use it as the HTTP client. The row above is the ProjectDiscovery `httpx` binary, which is knowledge-only. **Playwright** (browser engine) IS production-integrated (opt-in via `WEBHOUND_BROWSER_ENABLED`, lazy-loaded, safe-mode), but the Playwright MCP server is not installed.

---

## 5b. SCANNER ADVISOR MODULES (production-wired, within scanner)

| Module | File | Role |
|--------|------|------|
| ChangeExplainer | advisor/change_explainer.py | Plain-language WADE change narrative |
| RiskExplainer | advisor/risk_explainer.py | Severity/context explanation |
| PriorityExplainer | advisor/priority_explainer.py | Finding priority explanation |
| ActionPlan | advisor/action_plan.py | Remediation step builder |

*These are part of the scanner package itself (not scripts/wade/reasoning/) and are called when building the advisory section of a scan result. Output is computed at scan time but not stored in a separate DB field — it flows into finding descriptions and narratives.*

---

## 6. AI / GRAPH COMPONENTS

| Component | Location | Installed | Running | Wired to Production | Status |
|-----------|----------|-----------|---------|---------------------|--------|
| LightRAG (vector) | lightrag_storage/ | YES | PARTIAL | NO | YELLOW — local vector live, no prod path |
| LightRAG (graph) | lightrag_storage/ | YES | NO | NO | RED — stub LLM blocks graph extraction |
| Neo4j | docker-compose-neo4j.yml | Config only | NO | NO | RED — not running |
| Graphiti | scripts/ai/ | Scaffolded | NO | NO | RED — requires Neo4j + Ollama |
| Ollama | docker-compose.ai-brain.yml | Config only | NO | NO | RED — no models pulled |
| Claude (Anthropic) | apps/api/services/ai_summary.py | YES (SDK) | OPTIONAL | YES (summarization) | YELLOW — opt-in, not default |
| Knowledge corpus | corpus/ | YES | YES (static) | NO | YELLOW — built, not queried by prod |
| Obsidian vault | vault/WEBHOUND KNOWLEGE VAULT/ | YES | Manual | NO | YELLOW — curated, not automated |
| ruvector.db | ruvector.db (repo root) | YES | YES | NO | YELLOW — claude-flow agent memory only |

---

## 7. THREAT INTELLIGENCE MODULES (production-wired)

| Module | File | Status |
|--------|------|--------|
| VirusTotal client | threat_intel/virustotal_client.py | PRODUCTION (requires API key) |
| URLhaus client | threat_intel/urlhaus_client.py | PRODUCTION |
| FeedManager | threat_intel/feed_manager.py | PRODUCTION |
| DomainClassifier | threat_intel/domain_classifier.py | PRODUCTION |
| DomainReputation | threat_intel/domain_reputation.py | PRODUCTION |
| ScriptReputation | threat_intel/script_reputation.py | PRODUCTION |
| BrandImpersonation | threat_intel/brand_impersonation.py | PRODUCTION |
| SupplyChain | threat_intel/supply_chain.py | PRODUCTION |
| ThreatCorrelation | threat_intel/threat_correlation.py | PRODUCTION |
| EnrichmentService | threat_intel/enrichment_service.py | PRODUCTION |
| ReputationCache | threat_intel/reputation_cache.py | PRODUCTION |
| FeedNormalizer | threat_intel/feed_normalizer.py | PRODUCTION |

---

## 8. KNOWLEDGE LAYER

| Layer | Location | Size | Records | Production Path |
|-------|----------|------|---------|-----------------|
| Source (markdown) | knowledge/ | ~2 MB | 277 files | None — curated offline |
| Corpus (JSONL chunks) | corpus/normalized/ | 5.2 MB | ~4,600 | None — static artifact |
| Dense embeddings | corpus/indexes/dense/ | 1.70 MB | ~4,600 | None — static artifact |
| LightRAG vectors | lightrag_storage/ | 1.85 MB | partial | None — not queried by prod |
| Manifest | corpus/manifests/manifest.jsonl | — | ~1,000 docs | None |
| Obsidian vault | vault/WEBHOUND KNOWLEGE VAULT/ | 0.28 MB | 135 files | None |

---

## 9. INFRASTRUCTURE

| Component | Platform | Status |
|-----------|---------|--------|
| apps/api (FastAPI + Celery) | Railway | LIVE |
| apps/web (Next.js) | Vercel | LIVE |
| Database (PostgreSQL) | Railway / Supabase | LIVE |
| Scanner Python package | Deployed with API worker | LIVE |
| Celery scan worker | Railway | LIVE |
| Neo4j | Not deployed | MISSING |
| Ollama | Not deployed | MISSING |
| Graphiti | Not deployed | MISSING |
