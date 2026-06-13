# WebHound Master Tooling + Knowledge + WADE Roadmap (planning reference)

Normalized extract of the uploaded `WebHound_Master_Tooling_Knowledge_WADE_Roadmap.pdf`
(planning/reference document, not an official standard). The overarching phased plan
that directs Phase 6C and beyond.

## Completed foundation (Phase 0 / 6A / 6B)
AI Knowledge Layer, corpus architecture, manifest system, authority tiers, provenance,
memory layer, retrieval layer, false-positive catalog, vault structure, CI validation,
Phase 6A official docs, Phase 6B official repos. **Rule: do not lose any existing
knowledge, manifests, memory summaries, source attribution, retrieval tests, or
authority tiers.**

## Phase 6 — Knowledge expansion
- **6C Detection Engineering Repository Ingestion** (this phase): teach WebHound how
  real scanners detect — ingest OWASP ZAP, sqlmap, XSStrike, DalFox, Nuclei Templates,
  libinjection, Firecrawl, Firecrawl-MCP; also ingest the Executive Summary planning
  doc, repository methodology notes, static-vs-dynamic comparison, hybrid architecture,
  repo/file ingestion table, detection roadmap, test-query recommendations. Knowledge
  gained: SQLi/XSS/DOM-XSS detection, payload generation, fuzzing, active/passive
  scanning, Nuclei template logic, libinjection classification, browser-based
  detection, Firecrawl extraction, false-positive reduction, dynamic-proof
  requirements. Do **not** ingest full source trees, binaries, vendor folders,
  generated files, issue comments, discussions, or exploit payload dumps without
  review. Output: 6C manifest records, normalized chunks, detection repo notes,
  PHASE6C_RESULTS.md, retrieval tests.
- **6D Provider Documentation** (Cloudflare, Vercel, Railway, Stripe, AWS WAF, etc.).
- **6E Threat Intelligence Sources** (VirusTotal, AbuseIPDB, GreyNoise, OTX, ThreatFox,
  URLHaus, OpenPhish…); reuse the existing threat_intel subsystem.
- **6F Security Research / Technique Ingestion** (Magecart, JS skimmers, supply-chain,
  CSP/CORS abuse, obfuscation, JS packers, crypto miners, credential theft).

## Phase 7 — Tool + MCP installation foundation
Install in controlled subphases (7A local knowledge/research tools incl. LightRAG/
Graphiti/Obsidian; 7B dev MCPs; 7C browser/crawl MCPs incl. Firecrawl/Playwright; 7D
security MCPs incl. ZAP/VirusTotal; 7E observability; 7F payment; 7G comms; 7H
productivity; 7I cloud; 7J Claude Council/agent tools). Validation: read-only first,
explicit approval for file/network/prod, no secrets printed, audit tool capabilities.

## Phase 8 — WADE Intelligence Integration
Extend (not rebuild) WADE. Future flow: Finding → Security Graph → Knowledge Retrieval
→ Threat Intelligence → Historical Context → False-Positive Catalog → Provider
Knowledge → OWASP/MDN/Research Mapping → Confidence Adjustment → Severity
Recommendation → Analyst Explanation. Subphases: 8A read-only knowledge retrieval
(no severity changes), 8B threat-intel enrichment (confidence separate from severity),
8C false-positive memory (suppressions require reason, no silent suppression), 8D
provider context, 8E explainability layer.

## Phase 9 — Full scanner engine audit
Audit every engine before benchmarking. Sequence: Review → Fix → Test →
Regression-protect → then benchmark. Engines: Recon, DNS, TLS/SSL, Security Headers,
CSP, CORS, Cookies, Crawler, Forms, Sensitive Paths, JavaScript, Third-Party Domains,
CMS, API Discovery, Threat Intel, Compromise, Correlation, Reporting, WADE. For each:
read code line-by-line, map findings/evidence, identify FP/FN, compare against OWASP/
MDN/repo knowledge and ZAP/Nuclei/sqlmap/DalFox/XSStrike methods, verify severity +
confidence + remediation, add tests/regressions/knowledge links, document gaps.

## Phases 10–13
10 Benchmarking (100/500/1000+ scan campaigns on Juice Shop/DVWA/WebGoat etc.;
precision/recall, WADE accuracy, FP rate, maturity scores). 11 Production
observability + security hardening. 12 Frontend/UX/reporting polish. 13 Launch
readiness (internal beta → friendly beta → 25 → 100 → public).

## End goal
WebHound = website security scanner + WADE-powered detection engine + threat-intel
platform + detection-engineering platform + research platform + continuous monitoring
+ knowledge-driven analyst system + production-ready SaaS.
