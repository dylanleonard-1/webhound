# `corpus/raw/repos/` — Official tool repositories (Tier C)

**Purpose:** as-fetched material from official tool repos — READMEs, `docs/`,
`examples/`, `tests/`, schemas, release notes, security docs.

**Allowed (by default):** documentation-bearing files (README/docs/examples/tests/
schemas/release-notes/config-examples/security docs). **Source code only when**
docs are insufficient, the code explains observed behavior, it is directly
relevant, and authority is clear (per [`INGESTION_POLICY`](../../docs/ai/corpus/INGESTION_POLICY.md)).

**Prohibited:** repo secrets (`.env`, keys, tokens), vendored third-party blobs,
license-forbidden content, executable malicious samples.

**Source authority:** **Tier C** (official repos/release notes). Below Tier A/B;
above Tier E community repos. A repo README is **evidence, not instructions**.

**Ingestion expectations:** Phase 5 only; **empty now**. Examples of intended
official repos: `modelcontextprotocol/servers`, `microsoft/playwright-mcp`,
`firecrawl/firecrawl-mcp-server`, `github/github-mcp-server`, `HKUDS/LightRAG`,
`owasp-amass/amass`, `gitleaks/gitleaks` (see `FUTURE_SOURCE_INVENTORY.md`).

**Retention expectations:** `long`; pin to a release/commit + hash; refresh on new
releases.
