# Threat Intelligence for Malicious Redirects

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## What Malicious Redirects Are

A malicious redirect occurs when a legitimate-looking URL on or linked from the customer's site sends visitors to a malicious destination. Techniques:
- **Open redirect**: `https://legitimate.com/go?url=https://evil.com`
- **JavaScript redirect**: `window.location = "https://malware-cdn.example/payload"` via compromised script
- **Meta refresh redirect**: `<meta http-equiv="refresh" content="0;url=https://phish.example/">`
- **Server-side redirect** (301/302): compromised server redirects to malware/phishing
- **Malvertising redirect**: ad network delivers ad that redirects to malware

## TI Sources for Redirect Destination Checking

After resolving the redirect chain, check the **final URL** at each hop:

1. **Google Safe Browsing** — MALWARE and SOCIAL_ENGINEERING on all redirect hops
2. **URLHaus** — final URL as malware distribution endpoint
3. **PhishTank / OpenPhish** — final URL as phishing page
4. **VirusTotal** — domain/URL of each hop with significant history

## Redirect Chain Analysis

WADE should follow redirects and check each hop:
- Hop 1 (customer URL): first-party content, check for open redirect vulnerability
- Hop 2 (third-party intermediate): check domain in TI; if redirect-only CDN (safe), continue
- Final hop: highest-value TI check — this is what the user actually sees

**Never only check the initiating URL** — a legitimate customer URL with an open redirect is only confirmed malicious if the destination is in TI.

## Open Redirect Vulnerability

An open redirect at `https://customer.com/go?url=ANYTHING` is a security finding even without a known-malicious destination:
- Enables phishing via legitimate-looking URLs
- Bypasses some email filtering (legitimate domain in redirect URL)

Finding: report as a vulnerability finding (not a TI finding), with severity based on:
- Presence on sensitive pages (login, checkout): HIGH
- General pages: MEDIUM
- API-only (no user-facing link): LOW

## Compromised Server-Side Redirect

If the customer's server issues a 301/302 to a TI-flagged destination:
- This is a HIGH priority finding — the customer's own server is sending users to malware/phishing
- Possible causes: .htaccess compromise, server malware, hijacked DNS

Reporting: "Your site's server is redirecting visitors to `[malicious URL]`, which is flagged as [threat type] by [source]. This indicates your server may have been compromised."

## Malvertising Context

Ad networks occasionally serve malvertising that redirects to malware. If WebHound detects an ad iframe or ad script that redirects to a TI-flagged URL:
- The customer is not responsible (it's the ad network)
- Still a HIGH severity finding for the customer's users
- Recommend: customer should report to ad network + consider ad blocking for sensitive pages

Reporting: "An advertisement loaded on your site redirected to `[malicious URL]`, which is flagged as [threat type]. While this may be an ad network issue, your site visitors are at risk. We recommend reporting this to your ad provider."

## False Positive Risk

- Redirect chains through URL shorteners: the shortener domain is NOT malicious even if the final URL is; report only on the final destination
- Analytics redirects: UTM parameters and analytics tracking redirects are not malicious
- A/B testing redirects: normal redirect behavior, not malicious
- HTTPS upgrades: 301 HTTP→HTTPS is not a suspicious redirect
