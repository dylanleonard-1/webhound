# Source Authority Tiers

The corpus ranks every source into one of five authority tiers. Tier governs which
source **wins** when sources disagree, and which sources may drive **operational/
security** decisions.

## Tiers

| Tier | What | Examples | May drive operational/security decisions? |
|------|------|----------|--------------------------------------------|
| **A** | Official vendor docs / specs / standards | Playwright/ProjectDiscovery docs; provider firewall docs (Cloudflare/Vercel/AWS WAF/Akamai/Fastly/Azure/Imperva/Sucuri); OWASP WSTG/ASVS/Cheat Sheets; CSP/CORS/SRI/MDN | **Yes — authoritative.** |
| **B** | Original research / academic / vendor research papers | peer-reviewed papers, vendor threat research, malware analyses | **Yes**, with Tier A. |
| **C** | Official repos / release notes | tool repos' README/docs/examples/release-notes (Nuclei, Katana, httpx, Amass, Gitleaks, MCP servers, LightRAG) | **Mostly** — official, but below A/B for security claims. |
| **D** | Threat feeds / provider KBs | URLHaus, VirusTotal, ThreatFox, OpenPhish, OTX, AbuseIPDB; provider knowledge-base articles | **Enrichment only** — never the *sole* decision-maker. |
| **E** | Community repos / skills / workflows / agent frameworks | community Claude skills, awesome-lists, n8n/agent frameworks, design skills | **No.** Informs *workflow* only. |

## The override rule
**Tier A overrides Tier E.** Community content (Tier E) may inform *how we work*
(workflow, tooling ergonomics) but **never becomes security authority**. When a
community repo and an official doc disagree on security/operational behavior, the
official doc wins, always.

## Provider remediation
Provider allowlisting / remediation guidance uses **official provider docs (Tier
A)** only — never community write-ups, never an LLM summary without a Tier-A
source. This matches the existing provider-access framework, which encodes
provider behavior from official sources.

## Threat intel
Tier D feeds are **enrichment**: they raise/lower confidence and add context, but a
finding is never created/suppressed on a single feed signal alone. This mirrors the
runtime threat_intel design ("TI is enrichment, not the sole decision-maker").

## Unknowns
If a source's authority/behavior is unknown, mark it `unverified` /
`needs_review` (and `license_terms: unknown` / `manual_required`). **Never invent**
authority, endpoints, keys, permissions, or provider behavior.
