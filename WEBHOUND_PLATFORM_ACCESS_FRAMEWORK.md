# WebHound — Phase 2 Platform Access Framework — Deliverables

**Branch:** `feat/platform-access-framework` (off `main`, includes the Part A static-IP fix). **NOT merged** — for review.
**Tests:** 100% green — 122 platform-access tests (111 pure `--noconftest` + 11 Vercel DB-integration with conftest); frontend `tsc --noEmit` 0 errors.

---

## Architecture summary

A **registry-driven** platform-access framework that extends (never duplicates) the Phase-1 systems. One config registry is the single source of truth; the detector, Cloudflare/Vercel services, wizard, support, audit, and admin all read it. Scanner IPs come **dynamically** from `config.scanner_outbound_ips()` everywhere — never hardcoded. The wizard renders **data only** (zero provider-specific logic in the component).

```
provider_access_registry.py   ← 10 providers as DATA (detection + remediation + capability)
        │  detect_provider() / render_remediation()
        ▼
scanner_block_detection.detect_blocking_provider()   ← multi-provider attribution (reuses registry)
        ▼
platform_access.py            ← 9-state machine + view builder + audit catalog + admin stats + support payload
   │           │            │              │
   ▼           ▼            ▼              ▼
GET /platform-access   POST /verify   POST /support-ticket   GET /internal/platform-access
   │  (reuses access-validation = Verify)   (reuses support.create_ticket)   (reuses /control RBAC)
   ▼
PlatformAccessWizard (data-only UI)

cloudflare_rules.py           ← NEW IP-allow rule type alongside UA-skip (dynamic IPs, auto-update)
```

**Reused from Phase 1 (unchanged behaviour):** Cloudflare OAuth + zone discovery + token encryption (`cloudflare_scanner_access`), Vercel IP System Bypass (`vercel_rules`), access-validation Verify (`access_validation`), the trusted-access state machine (`trusted_access` / enums), the support/ticket system (`support`), the provider audit trail (`provider_oauth.audit_event` → `AdminAuditLog`), and the `/control` RBAC surface (`internal/`).

---

## Files CREATED
- `apps/api/services/provider_access_registry.py` — the registry (10 providers) + `detect_provider` + `render_remediation`.
- `apps/api/services/platform_access.py` — state machine, view builder, audit catalog/helpers, admin stats, support payload.
- `apps/web/src/components/access/platform-access-wizard.tsx` — the data-only wizard.
- Tests: `test_provider_access_registry.py`, `test_multi_provider_detection.py`, `test_cloudflare_ip_allow_rule.py`, `test_platform_access.py`, `test_platform_access_verification.py`, `test_platform_access_support.py`, `test_platform_access_audit.py`, `test_platform_access_admin.py`, `test_future_provider_expansion.py`.

## Files MODIFIED
- `apps/api/config.py` (Part A) — scanner egress default = the 3 static IPs.
- `apps/api/services/scanner_block_detection.py` — `detect_blocking_provider()` (registry-consuming; legacy `classify_scan_blocker` unchanged).
- `apps/api/services/cloudflare_rules.py` — IP-allow rule type (`REF_IP_ALLOW`, `_ip_allow_expression`, generic apply/verify/remove); no-arg path stays 2-rule.
- `apps/api/services/cloudflare_scanner_access.py` — passes `scanner_outbound_ips()` to rule create/verify; metadata `rule_type: skip+ip-allow`.
- `apps/api/services/vercel_scanner_access.py` — returns registry `remediation` payload + `vercel.instructions.shown` audit.
- `apps/api/routers/access_validation.py` — `GET /platform-access` + `POST /platform-access/support-ticket`.
- `apps/api/internal/router.py` — `GET /internal/platform-access` (admin stats).
- `apps/web/src/lib/api.ts` — `platformAccess` / `platformAccessSupportTicket` + `PlatformAccessView`/`RemediationView` types.
- `apps/api/tests/test_cloudflare_scanner_access.py`, `test_scanner_outbound_ips.py` — additive contract updates.

## Migration requirements
**None.** No new tables/columns. Audit events reuse `admin_audit_log`; statuses reuse `trusted_access`/`access_validation`; tickets reuse the support system. No Alembic migration.

## API changes (all additive)
- `GET /websites/{id}/platform-access` → `PlatformAccessView` (state, provider, remediation, scanner_ips, verification).
- `POST /websites/{id}/platform-access/support-ticket` → `{id, number, status}`.
- `GET /internal/platform-access` (RBAC) → admin stats.
- Vercel guided response gains an additive `remediation` field; Cloudflare `verify` gains an additive `ip_allow` field. No breaking changes.

## Frontend changes
- New `PlatformAccessWizard` component (9 states, copy/Copy-All, Verify-Access, Connect-{provider}, Create-Support-Ticket). Renders `null` when access isn't required. **Not yet mounted** into a page — mount point recommendation: the website detail / onboarding panel (`onboarding-panel.tsx`) or the scan-result view; it's website-scoped (`websiteId`).
- `api.ts` client methods + types.

## Test results
| Phase | Tests | Status |
|---|---|---|
| A registry | 18 | ✅ |
| B multi-provider detection | 7 (+9 existing) | ✅ |
| C Cloudflare IP-allow | 6 (+13 existing CF) | ✅ |
| D+E guided + wizard view | 14 | ✅ |
| G verification mapping | 5 | ✅ |
| H support escalation | 4 | ✅ |
| I audit | 5 | ✅ |
| J admin | 3 | ✅ |
| K future expansion | 4 | ✅ |
| Vercel DB integration (conftest) | 11 | ✅ |
**Total: 122 green.** `tsc --noEmit`: 0 errors.

## Risk assessment
- **Low.** All API changes are additive; legacy code paths (UA-skip rules, `classify_scan_blocker`, Vercel `customer_action`) are preserved and tested. The IP-allow rule is opt-in via `scanner_ips=`.
- **Cloudflare IP-allow** writes a new firewall rule — but only on the existing OAuth/permission-gated path, scoped strictly to the scanner IPs (never a blanket allow; verified + reversible).
- **Auto-update**: re-running `ensure_scanner_rules` after an IP change PATCHes the rule — idempotent, no duplication (ref-tagged).
- **No secrets** in audit/tickets (guard tests enforce it).
- **Wizard unmounted** = zero runtime impact until mounted.

## Rollback plan
- **Code:** revert the branch (additive; no migration to undo).
- **Runtime (no deploy):** the IP-allow rule is opt-in — reverting `cloudflare_scanner_access` to not pass `scanner_ips` reverts to UA-only. `remove_scanner_rules` cleans the IP-allow rule on disconnect. New endpoints simply go unused if the frontend doesn't call them.
- **Config:** `WEBHOUND_SCANNER_OUTBOUND_IPS` can be reverted independently.

## Deployment steps
1. Merge `feat/platform-access-framework` (after review). No migration.
2. Confirm `WEBHOUND_SCANNER_OUTBOUND_IPS` is set on the worker (Part A — done).
3. **Customer action (manual, external):** update the Vercel System Bypass on webhoundsecurity.com to include all 3 IPs (the old single-IP rule is insufficient).
4. Mount `PlatformAccessWizard` in the chosen page (frontend follow-up) and deploy web.
5. Validate on a test Cloudflare zone: connect → confirm the IP-allow rule is created (`verify.ip_allow == true`); change the IP list → re-run → confirm auto-update; Vercel guided steps render; Verify Access flips trusted-access to ACTIVE; a forced failure creates a support ticket; `/internal/platform-access` shows stats.

## How to add a provider (config only — Phase K proven)
Add one `ProviderAccess` entry to `provider_access_registry.PROVIDERS` with its `DetectionSignals` (headers/header_values/cookies/challenge url+html) + `remediation_steps` (one step flagged `ips=True`). Detection, the wizard, support, audit, and admin all pick it up with **no code change** (test `test_future_provider_expansion.py` proves Netlify/Render/Fly.io/Wordfence/Barracuda/F5). Set `automation_capable=True`/`allowlist_method="api"` only when real automation exists.

---

*Phase 2 Platform Access Framework — built, tested (122 green), not merged. Awaiting review.*
