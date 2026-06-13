# WebHound — Production Readiness Checkpoint

**Date:** 2026-06-12
**Branch merged:** `feat/platform-access-framework` → `main`
**Merge commit:** `5fc14f6` (`--no-ff`, all 3 fix/feature commits preserved)
**Pushed:** `origin/main` at `5fc14f6` (cc75d39..5fc14f6)
**Scope of this checkpoint:** the platform-access framework + onboarding-completion fix that just merged, assessed against the surrounding system. This is an honest snapshot, not a full external audit.

> This document does **not** cover the AI Knowledge Layer — that is a separate, separately-reviewed phase and has not been started.

---

## Production Ready

Components that are implemented, tested in this session, and gated by real boot-time safety checks.

- **Onboarding completion (deterministic).** The 6-step wizard now completes reliably. Monitoring-schedule creation is a single idempotent get-or-create seam (`verification.ensure_default_schedule`) invoked synchronously at every point onboarding needs it — all verification paths (DNS / meta / file / provider-connection / dev-skip) and monitoring activation. Completion no longer races the background automation task. Verified on SQLite **and** real Postgres (where the background task genuinely connects).
- **Domain ownership verification.** DNS-TXT, meta-tag, HTML-file, and connected-provider evidence paths, with a cross-account ownership-conflict guard. Auto-creates the daily monitoring schedule on first verification.
- **Cloudflare platform access — full automation.** The only provider with `automation_capable=True` / `allowlist_method="api"`: scanner IP-allow rule creation + verification via the Cloudflare API, scanner-access state machine, scope checks. Covered by `test_cloudflare_*` (40+ tests).
- **Multi-provider blocker detection.** Config-driven `provider_access_registry` detects 10 CDN/WAF providers (Cloudflare, Vercel, CloudFront, Akamai, Fastly, Azure Front Door, Imperva, Sucuri, AWS WAF, Google Cloud Armor) and emits guided, IP-templated remediation.
- **PlatformAccessWizard (frontend).** Data-driven, provider-agnostic visibility (`hidden` / `collapsed` / `expanded`) sourced entirely from the API; no provider logic in the client. Mounted on the website detail page. 10 unit tests; `tsc --noEmit` clean; production build succeeds.
- **Platform-access support escalation + audit.** Failed/blocked setups escalate to the ticket system with provider/website/scan context (no secrets); audit events recorded.
- **Scanner egress identity.** Fixed Railway Static Outbound IP set (`162.220.234.240,152.55.180.240,152.55.180.241`) surfaced publicly on `/scanner/identity` for customer allowlisting.
- **Boot-time production guardrails (`config.py`).** Refuses to start in production if: `SECRET_KEY` is default, `DATABASE_URL` is unset/non-Postgres, `REDIS_URL` invalid, `API_BASE_URL`/`FRONTEND_URL` not absolute, `DEV_ALLOW_UNVERIFIED_SCANS` set, `DEV_SKIP_DOMAIN_VERIFICATION` set (SSRF risk), or admin bypass flags set without the explicit `ADMIN_BYPASS_ALLOW_IN_PROD` two-key opt-in.

---

## Beta Features

Implemented and shipping, but with narrower automation or an operational prerequisite.

- **Vercel scanner access.** Detection, OAuth/connection, rules, and scanner-access state are implemented (`test_vercel_*`, 34 tests pass), but the registry marks Vercel `allowlist_method="manual"` — automated firewall-bypass is **not** turn-key (see Known Limitations re: "Seawall Config not found").
- **Manual-guidance remediation for the other 8 providers.** CloudFront, Akamai, Fastly, Azure Front Door, Imperva, Sucuri, AWS WAF, Google Cloud Armor are **detection + guided manual allowlisting** only (`automation_capable=False`). Correct and useful, but no one-click automation — by design for this phase.
- **Onboarding background automation conductor.** `run_automation_for_website` advances stages without customer action and pauses at gates. It is **best-effort** (opens its own DB session; failures are logged, never raised) — onboarding completion does not depend on it, but it is not a guaranteed-to-run pipeline.

---

## Experimental Features

Present in the tree but not part of this checkpoint's validated surface.

- **`/hologram-test`, `/demo-preview`, `/wade`** routes build but were not exercised here.
- **`scripts/bench/`, `scripts/prod_scan_metrics.py`** — local benchmarking/metrics helpers (untracked, not part of the merge).
- The various root-level `WEBHOUND_*.md` audit notes are working analyses, not validated product specs.

---

## Known Limitations

- **`DEV_SKIP_DOMAIN_VERIFICATION` is enabled in the local `.env`.** This is what made onboarding's missing-schedule bug reproduce locally. It is harmless in dev and **hard-blocked in production** by config validation, but any non-prod environment that copies this `.env` will skip real ownership proof. Ensure staging/prod do not carry it.
- **Vercel firewall-bypass automation prerequisite.** Per prior operational notes, the Vercel bypass flow fails with "Seawall Config not found" until the project's Firewall is enabled once in the Vercel dashboard. This is a manual first-touch step, not yet automated.
- **8 of 10 providers are manual-allowlist only.** Customers on Akamai/Imperva/Fastly/etc. get instructions, not automation.
- **Full API test suite is slow** (~16+ min, no `xdist`). This session scoped runs to the relevant files; a full-suite green was not executed end-to-end.
- **1 low-severity Dependabot alert** on the default branch (reported by GitHub on push). Not triaged here.
- **Real-Postgres test path is opt-in** (`TEST_DATABASE_URL`); CI defaults to in-memory SQLite for the request path, so the background-task-vs-real-DB interaction is only exercised when explicitly pointed at Postgres.

---

## Remaining Launch Blockers

None *introduced by this merge*. Onboarding completes, builds pass, and the validated suites are green. Before a production launch, confirm the following operational items (none are code defects in this branch):

1. **Environment hygiene:** staging/prod must NOT set `DEV_SKIP_DOMAIN_VERIFICATION` or `DEV_ALLOW_UNVERIFIED_SCANS` (config will refuse to boot if they do — verify it boots cleanly with the prod env).
2. **Scanner egress IPs current:** confirm the 3 Railway Static Outbound IPs in `config.py` still match actual worker egress before customers build allowlists against them.
3. **Full-suite CI green:** run the complete `apps/api` suite (not just the scoped files) in CI at least once on `main` to catch anything outside the onboarding/platform-access/cloudflare/vercel scope.
4. **Dependabot low alert:** triage/accept the 1 low vulnerability.

These are go-live verifications, not unfinished work in the merged code.

---

## Recommended Next Phase

In priority order, and explicitly **not** started here:

1. **One full CI run of the entire `apps/api` suite on `main`** to ratify the merge beyond the scoped smoke tests.
2. **Automate the Vercel firewall-bypass prerequisite** (or detect the "Seawall Config not found" state and surface a precise dashboard-enable step in the wizard) so Vercel reaches Cloudflare-level automation.
3. **Promote the next provider to API automation** (Fastly or CloudFront are good candidates) using the Cloudflare implementation as the template.
4. **Parallelize the API test suite** (`pytest-xdist`) and make the app import path DB/Redis-tolerant so the full suite is hermetic and fast.
5. *(Separate, separately-reviewed track)* **AI Knowledge Layer** — do not begin until its own review.
