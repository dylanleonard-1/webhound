# Threat Intelligence for Third-Party Scripts

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Why Third-Party Scripts Are High Priority

Third-party scripts execute in the same browser context as the first-party page. A compromised `<script src="...">` or a malicious inject into a third-party tag manager can:
- Steal form inputs (credit cards, passwords, PII) — Magecart/skimmer attacks
- Redirect users to phishing pages
- Download malware via browser (drive-by download)
- Exfiltrate session tokens
- Mine cryptocurrency

## Sources Relevant for Script URL Checking

Priority order:
1. **Google Safe Browsing** — checks script host domain for MALWARE/SOCIAL_ENGINEERING. High precision.
2. **URLHaus** — checks if the script URL itself is a known malware distribution URL.
3. **ThreatFox** (`cc_skimming` threat type) — specifically flags card-skimming infrastructure. Highest priority for payment-page scripts.
4. **VirusTotal** — multi-engine check on the script's domain and URL.
5. **AbuseIPDB + GreyNoise** — IP context (lower weight — use for corroboration, not primary signal).

## Script Categories and Risk Levels

### Category A: First-party scripts (same domain/subdomain)
Risk: depends on site security posture; TI checks less applicable.
TI role: check if domain appears in TI as compromised.

### Category B: Known legitimate third-party SDKs
Examples: `analytics.google.com`, `js.stripe.com`, `cdn.jsdelivr.net`, `ajax.googleapis.com`
Risk: LOW from TI perspective (well-maintained, monitored).
TI role: still check URL exactly (subdomain takeovers, CDN path injection possible).
See provider-docs allowlist for known-legitimate script domains.

### Category C: Unknown or less-well-known CDNs / script hosts
Risk: MEDIUM — not well-monitored.
TI role: full URL + domain + IP check; check domain age (newly registered = suspicious).
Apply all TI sources.

### Category D: Obfuscated / encoded script URLs
Risk: HIGH — legitimate scripts don't need obfuscation.
TI role: decode URL before TI check; obfuscation itself is a signal.

### Category E: Scripts loaded from customer's own tag manager (GTM, Tealium)
Risk: MEDIUM — tag manager injects can be compromised even if the GTM domain is legitimate.
TI role: check the FINAL URL of each script injected via tag manager, not just the tag manager URL.

## Skimming / Magecart Detection

ThreatFox `cc_skimming` threat type specifically targets card skimming IOCs.

Signals to combine with TI:
- Script appears only on checkout/payment page (not other pages)
- Script URL newly appeared since last scan
- Script URL is ThreatFox `cc_skimming` type
- Script exfiltrates to a different domain (check CSP violations, network requests)

Composite: ThreatFox `cc_skimming` match on payment-page script = CRITICAL finding.

## Recommended Check Flow for Script URLs

1. Extract all `<script src="...">` URLs from the page
2. Follow redirects to get final URL
3. Check each final URL against:
   a. Known-legitimate allowlist (suppress)
   b. URLHaus (URL-level)
   c. ThreatFox (URL and domain, focus on `cc_skimming`)
   d. Google Safe Browsing (URL-level)
   e. VirusTotal (domain + URL)
4. For remaining unknowns: check domain age (whois), subdomain legitimacy
5. Apply confidence model (see threat-intel-confidence-model.md)
6. Apply page-context multiplier (checkout/login = 1.4x, other = 1.0x)

## Reporting to Customer

High-confidence script TI match:
> "A third-party script loaded on your [checkout/login] page — `[URL]` — has been identified as [threat type] by [source(s)] as of [date]. This script executes with full access to form data on this page. Immediate review is recommended."

Low-confidence:
> "A script hosted at `[domain]` has limited threat intelligence indicators (1 source, shared infrastructure). We recommend verifying this script's legitimacy with the providing vendor."
