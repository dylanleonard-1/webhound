# WebHound Architecture — Summary (pointer-first)

Curated, pointer-first summary. Links to the real code/docs rather than copying
them (avoids drift). Authoritative source = the repo itself + `docs/architecture.md`.

## Shape
Monorepo with four runtimes:
- **API** — `apps/api/` (FastAPI; pydantic `Settings` in `apps/api/config.py`).
- **Web** — `apps/web/` (Next.js; the dashboard, onboarding, PlatformAccessWizard).
- **Worker** — `worker/` (Celery; runs scans).
- **Scanner engine** — `scanner/webhound/` (the detection engines + analysis).

Deploy: API/worker on **Railway**, web on **Vercel**, **Postgres 16** + **Redis 7**
(see `knowledge/webhound/deployment/` and `infra/`).

## Scanner engines
`scanner/webhound/engines/`: `recon`, `crawler`/browser, `headers` (security
headers, CSP, CORS), `cookies`, `tls_dns`, `javascript` (+ obfuscation),
`api_discovery`, `cms`, `compromise`, `secrets`, `threat_intel`. Orchestrated by
`scanner/webhound/core/orchestrator.py`; correlation in `core/correlation.py`.
Per-engine knowledge: `knowledge/scanner-engines/`.

## WADE (drift / anomaly)
`scanner/webhound/wade/` + `apps/api/services/wade_correlation.py` — baseline a
site and detect meaningful change/compromise over time. See
[`../wade/WADE_FOUNDATION.md`](../wade/WADE_FOUNDATION.md).

## Provider Access Framework
`apps/api/services/provider_access_registry.py` (10 providers), `platform_access.py`,
`cloudflare*.py`, `vercel*.py`. **Cloudflare = API automation; Vercel = guided/
manual.** See [`../provider-access/PLATFORM_ACCESS_FRAMEWORK.md`](../provider-access/PLATFORM_ACCESS_FRAMEWORK.md).

## Threat-intel subsystem
`scanner/webhound/threat_intel/` (URLHaus + VirusTotal live; OpenPhish/AbuseIPDB
partial; ThreatFox/OTX missing). See
[`../threat-intel/THREAT_INTEL_CURRENT_STATE.md`](../threat-intel/THREAT_INTEL_CURRENT_STATE.md).

## Security Graph
`scanner/webhound/graph/` — per-scan, runtime `SecurityGraph` of findings/entities.
**Distinct** from the Phase-4 knowledge graph (`corpus/graph/`).

## Validation / benchmark
`scanner/validation/` (ground-truth lab: precision/recall/coverage/regression) +
`scanner/webhound/benchmark/harness.py`. Reused (not rebuilt) in Phases 7/9/10.

## Support / tickets
`apps/api/services/support.py` / `support_ticket.py` / `tickets.py`; models
`support_ticket`, `internal_note`. Platform-access escalation:
`/platform-access/support-ticket`.

## AI summariser (existing Claude path)
`apps/api/services/ai_summary.py`, gated by `WEBHOUND_AI_ENABLED` +
`ANTHROPIC_API_KEY`. The knowledge layer reuses this — no parallel AI config.

## Static scanner egress IPs
`162.220.234.240`, `152.55.180.240`, `152.55.180.241` (Railway Static Outbound).
Surfaced on `/scanner/identity`; customers allowlist these. Config default in
`apps/api/config.py` (`scanner_outbound_ips`).

**Review status:** curated (seeded Phase 3). **Authority:** trusted_local.
