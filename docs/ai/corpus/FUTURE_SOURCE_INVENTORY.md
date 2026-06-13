# Future Source Inventory (NOT ingested)

A planning list of sources the corpus *may* ingest in later phases. **Nothing here
is ingested in Phase 2.** Status legend:
- **existing** — already implemented in WebHound (reuse, don't rebuild).
- **partial** — partially present (e.g. normalizer but no client).
- **planned** — intended, not yet built.
- **unknown** — relevance/ToS/auth not yet verified.

License/ToS for every external source is **unverified until confirmed at ingestion
time** (Phase 5) — mark `license_terms: unknown`/`manual_required` until then.

## Official Docs (Tier A)
| Source | Status | Notes |
|--------|--------|-------|
| Playwright / Puppeteer docs | planned | browser automation; pairs with Playwright MCP |
| OWASP WSTG / ASVS / Cheat Sheets | planned | testing methodology + control standards |
| OWASP ZAP docs | planned | active-scan reference (Phase 10, authorized only) |
| ProjectDiscovery (Katana / httpx / Nuclei) | planned | recon/crawl/templated detection |
| OWASP Amass docs | planned | attack-surface mapping |
| Semgrep / Gitleaks docs | planned | SAST / secret-scan reference |
| Provider firewall docs — Cloudflare WAF, Vercel trusted-IP/deployment-protection, AWS WAF IP-set, Akamai, Fastly ACL, Azure Front Door WAF, Imperva, Sucuri | planned | **must match the provider-access registry** (Tier-A ground truth) |
| CSP / CORS / SRI / MDN | planned | web-security primitives for header/CSP engines |

## Official Repos (Tier C)
| Source | Status | Notes |
|--------|--------|-------|
| `modelcontextprotocol/servers` | planned | MCP reference servers |
| `microsoft/playwright-mcp` | planned | Playwright MCP |
| `firecrawl/firecrawl-mcp-server` | planned | Firecrawl MCP |
| `github/github-mcp-server` | planned | GitHub MCP |
| `HKUDS/LightRAG` | planned | Phase-4 retrieval/graph |
| `owasp-amass/amass`, `gitleaks/gitleaks` | planned | tool repos (docs/release-notes) |

## Threat Feeds (Tier D)
| Source | Status | Notes |
|--------|--------|-------|
| URLHaus | **existing** | live client `urlhaus_client.py` + normalizer — reuse |
| VirusTotal | **existing** | live client `virustotal_client.py` + normalizer — reuse |
| OpenPhish | **partial** | `normalize_openphish` exists; **no fetch client** |
| AbuseIPDB | **partial** | `normalize_abuseipdb` exists; **no fetch client**; needs `ABUSEIPDB_API_KEY` |
| PhishTank | **partial** | `normalize_phishtank` exists; client status unverified |
| ThreatFox | **planned** | no client, no normalizer — net-new (Phase 5) |
| AlienVault OTX | **planned** | no client, no normalizer — net-new; needs `OTX_API_KEY` |

> Phase-5 threat-feed work is **net-new only** and reuses `feed_normalizer` +
> `feed_manager` + `threat_indicator`. TI is **enrichment, not the sole
> decision-maker**. See `WEBHOUND_EXISTING_SYSTEMS_MAP.md`.

## Research Papers (Tier B)
| Source | Status | Notes |
|--------|--------|-------|
| Skimmer / Magecart / supply-chain research | planned | grounds JS-malware knowledge |
| Detection-engineering / false-positive literature | planned | grounds confidence/severity modeling |
| Browser-security / CSP-bypass research | planned | grounds header/CSP engines |

## Community Repositories (Tier E — workflow only, never security authority)
| Source | Status | Notes |
|--------|--------|-------|
| Community Claude skills / `awesome-claude-*` / agent frameworks (n8n-mcp, etc.) | planned/unknown | may inform workflow; **never** override Tier A; ToS unverified |

## Internal WebHound Knowledge (`trusted_local`)
| Source | Status | Notes |
|--------|--------|-------|
| `docs/` + `docs/ai/` (architecture, scanner-engines, wade, env, etc.) | **existing** | prefer pointers over copies (avoid drift) |
| Decision records / incident notes | planned | sanitized; no customer PII |
| The provider-access registry as provider ground truth | **existing** | `provider_access_registry.py` |

## Reminder
This is an inventory, not a backlog to execute. Ingestion happens only in an
approved later phase, item-by-item, with provenance + license verification.
