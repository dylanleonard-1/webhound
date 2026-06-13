# `corpus/raw/docs/` — Official vendor docs & standards (Tier A)

**Purpose:** as-fetched official documentation and standards — the highest
authority for operational/security guidance.

**Allowed:** official vendor docs (Playwright, ProjectDiscovery, provider firewall
docs, etc.), standards/specs (OWASP WSTG/ASVS/Cheat Sheets, CSP/CORS/SRI, MDN),
each with a provenance manifest record and a license/ToS that permits storage.

**Prohibited:** community blog posts as if authoritative, secrets/PII, anything
license-forbidden. Community material belongs to Tier E, not here.

**Source authority:** **Tier A** — overrides Tier C/D/E. Provider remediation must
cite Tier A provider docs.

**Ingestion expectations:** Phase 5 only; **empty now**.

**Retention expectations:** usually `permanent`/`long`; re-fetch + re-hash on
version change (freshness matters for provider docs).
