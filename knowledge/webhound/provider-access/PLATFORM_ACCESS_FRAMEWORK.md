# Platform Access Framework — Summary (pointer-first)

Curated summary of WebHound's provider-access / scanner-allowlisting system. Ground
truth = the code (`apps/api/services/`) + `WEBHOUND_PLATFORM_ACCESS_FRAMEWORK.md`.

## Purpose
Let the WebHound scanner reach customer sites that sit behind a CDN/WAF, by helping
the customer allowlist the scanner (by IP and/or via provider API), and surface the
state to the customer in the dashboard.

## Components (code)
- **Provider registry** — `provider_access_registry.py`: config-driven catalog of
  **10 providers** with `automation_capable` + `allowlist_method` per provider.
- **PlatformAccessWizard** — `apps/web/src/components/access/platform-access-wizard.tsx`,
  mounted on the website detail page; data-driven, provider-agnostic visibility
  (`hidden`/`collapsed`/`expanded`) via `apps/web/src/lib/platform-access.ts`.
- **Platform access service** — `apps/api/services/platform_access.py` (+ endpoint
  `/websites/{id}/platform-access`).
- **Cloudflare** — `cloudflare*.py` (OAuth + rules + scanner-access state).
- **Vercel** — `vercel*.py` (OAuth + rules + scanner-access state).
- **Verification** — `verification.py` (DNS-TXT / meta / file / provider-connection)
  + `trusted_access.py`.
- **Support escalation** — `/platform-access/support-ticket`.

## Automation status (honest)
- **Cloudflare: automation SUPPORTED.** WebHound's Cloudflare integration can create
  the scanner bypass rule via the Cloudflare API (`automation_capable=True`,
  `allowlist_method="api"`).
- **Vercel: guided / manual is the current default.** Detection works; the
  customer adds the scanner IPs to a **System Bypass** (and/or Protection-Bypass)
  in the Vercel dashboard. The marketplace integration token is forbidden from
  firewall writes, so **full automation is NOT claimed**. (See the "Seawall Config"
  note in the gap analysis: the 404 is on the WAF-config endpoint, not the IP
  System Bypass.)
- **The other 8 providers: guided/manual only** (`automation_capable=False`) —
  detection + official-doc remediation guidance, no API automation.

## Scanner identity / static IPs
`/scanner/identity` publishes the scanner UA + the **3 static egress IPs**
(`162.220.234.240`, `152.55.180.240`, `152.55.180.241`) so customers can allowlist
by IP. Config: `apps/api/config.py` `scanner_outbound_ips`.

## Limitation (important for honesty)
Only Cloudflare has API automation today. **All other providers are guided/manual**
unless/until a verified API integration exists. Provider remediation uses
**official provider docs only** (Tier A) — see `knowledge/provider-docs/`.

**Review status:** curated (seeded Phase 3). **Authority:** trusted_local +
Tier-A provider docs for remediation.
