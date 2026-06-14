# Threat Intelligence for Customer Reporting

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Purpose

This document defines the language and framing WebHound MUST use when presenting TI-based findings to customers. The goal: actionable, accurate, measured communication that avoids alarming customers with false positives while clearly communicating real threats.

## Prohibited Language Patterns

The following phrases MUST NOT appear in customer-facing finding reports when evidence is insufficient:

| Prohibited | Reason |
|---|---|
| "Your website is hacked" | Cannot be asserted from TI data alone |
| "This domain is malicious" | Domain-level claim from URL-level evidence |
| "Critical threat confirmed" | "Confirmed" requires multi-source corroboration |
| "Malware detected on your site" | TI match ≠ malware on the site itself |
| "Your site is distributing malware" | Only assertable with URLHaus `online` + direct page load confirmation |
| "This IP is an attacker" | IP addresses are shared; one IP match ≠ targeted attack |
| "Immediately block / take down" | Exceeds WebHound's authority; this is a recommendation |

## Preferred Language Templates

### High-confidence URL match (GSB / URLHaus online / VT ≥5 engines)
> "This URL loaded by your site — `[url]` — has been flagged as [threat type] by [source(s)] as of [date]. This is a high-confidence finding. We recommend reviewing this resource immediately."

### Medium-confidence domain match
> "The domain `[domain]` appears in [N] threat intelligence source(s) with [confidence level] confidence. Some indicators suggest this domain has been associated with [threat category]. We recommend investigating whether this domain's presence on your site is expected."

### Low-confidence / shared IP match
> "The IP address `[ip]` serving this resource has been reported for abuse by [source] (confidence: low). This IP is [shared hosting / CDN infrastructure], so this may reflect activity from other sites on the same server. We recommend monitoring but no immediate action is required."

### Stale IOC (>90 days, offline/expired)
> "A historical threat intelligence record from [date] associates `[indicator]` with [threat type]. This record has not been confirmed recently. We recommend verifying current behavior before taking action."

### Shodan/Censys exposure (not threat)
> "This [IP/service] is visible on the internet with [service/port] open. This indicates a potential exposure that may increase attack surface, but does not indicate active malicious activity."

### Newly appeared resource with TI match
> "A resource that did not appear in our previous scan — `[url]` — is now loaded on your [checkout/login/page type] page and has TI matches in [sources]. The combination of new appearance and threat intelligence match warrants immediate review."

### Third-party script on sensitive page
> "A third-party script loaded on your [checkout/login] page — `[url]` — matches threat intelligence data from [source]. Third-party scripts on sensitive pages have elevated risk if compromised. We recommend verifying with the script provider."

## Confidence Disclosure

Always include:
1. Which TI sources reported the match
2. Confidence level (High / Medium / Low / Informational)
3. Indicator type (URL / domain / IP) and why it matters
4. Indicator age / last confirmed date
5. Any FP mitigating factors (shared hosting, stale IOC, CDN IP)

## Severity Calibration

| Scenario | Max Severity |
|---|---|
| GSB match on URL loaded by page | Critical |
| URLHaus `online` URL match on loaded resource | Critical |
| VT ≥5 engines on URL loaded on payment page | Critical |
| Domain match (dedicated malicious, recent, 2+ sources) on page resource | High |
| IP match on non-CDN host with GreyNoise `malicious` confirmation | Medium |
| AbuseIPDB score ≥75 on shared hosting IP | Informational |
| Single OTX pulse match | Informational |
| Shodan open port on IP | Exposure (separate category) |

## What to Recommend, Not Demand

WebHound findings are security recommendations, not mandates. Customer reporting should:
- Explain what was found and why it's a concern
- Explain what it could mean if it IS malicious (impact context)
- Recommend specific next steps ("contact the script provider", "review this URL in your CSP", "check your WAF logs")
- NOT use emergency/crisis framing unless composite confidence ≥0.85 and indicator type = URL/file hash

## Multi-Finding Context

When multiple TI findings appear in the same scan:
- Group by severity, not by source
- Explain relationships ("this IP hosts the domain flagged in finding #2")
- Distinguish: "X of N findings are from shared infrastructure and are likely low-risk"
- Highlight the highest-specificity finding as the lead item
