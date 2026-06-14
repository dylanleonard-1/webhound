# Threat Intelligence for WADE — Integration Rules

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Purpose

This document specifies how WADE (WebHound's scoring/analysis engine) MUST and MUST NOT use threat intelligence data. These rules prevent both false positives (over-alerting) and false negatives (under-alerting).

## WADE MUST NOT Rules

### MUST NOT auto-mark critical from shared IP reports
An IP with AbuseIPDB score ≥50 on a Data Center/CDN range is not a customer-site finding.
A customer's site being hosted on a shared IP with abuse reports does not make the customer's site malicious.

### MUST NOT mark critical from a single low-confidence source
One OTX pulse match, one low-reputation AbuseIPDB report, or a single minor-engine VT flag is insufficient.
Required: at least two independent sources or one high-authority source (GSB, URLHaus `online`).

### MUST NOT treat Shodan/Censys exposure as threat
A customer IP with an open port 3306 visible in Shodan = an exposure finding (misconfiguration), NOT a threat/malice finding. These are categorically different finding types.

### MUST NOT flag CDN edge IPs as malicious
If an IP belongs to Cloudflare, Fastly, Akamai, Vercel, AWS, GCP, Azure — and GreyNoise confirms RIOT — any AbuseIPDB/VT score on that IP is a false positive for the customer site.

### MUST NOT flag stale IOCs without current corroboration
URLHaus `offline` or `unknown` status + age >90 days = not a current threat.
ThreatFox IOC >6 months old = automatically expired by ThreatFox itself.
WADE should respect these source-native expiration signals.

### MUST NOT use AbuseIPDB whitelists as "safe" guarantees
Documentation states the whitelist is non-binary: *"generally should not be used as a basis for action."* A whitelisted IP with high score still merits review.

### MUST NOT auto-block based on GreyNoise `noise: true` alone
`noise: true` means the IP scans the internet. That does not mean it is attacking the customer. Many `noise: true` IPs are benign security scanners.

## WADE SHOULD Rules

### SHOULD escalate on multi-source URL-level matches
If the same third-party URL (loaded by the customer site) appears in URLHaus + VirusTotal ≥5 engines → this is a HIGH confidence finding regardless of domain reputation.

### SHOULD escalate on GSB matches for exact loaded URLs
Google Safe Browsing match for a URL that the customer site actually loads or redirects to = strong finding. GSB is high-precision and continuously maintained.

### SHOULD correlate GreyNoise to resolve AbuseIPDB ambiguity
When AbuseIPDB reports an IP and GreyNoise says `riot: true` → suppress IP finding (CDN/cloud infra).
When AbuseIPDB reports an IP and GreyNoise says `classification: malicious` → corroborating signal, increase confidence.
When AbuseIPDB reports an IP and GreyNoise returns 404 (never observed) → neutral on GreyNoise side.

### SHOULD weight by indicator recency
Active real-time checks (URLHaus `online`, GSB active match) are stronger than database entries.
VT `last_analysis_date` >7 days → re-scan if quota allows rather than trusting stale results.

### SHOULD use indicator type hierarchy for confidence
URL > domain (dedicated malicious) > IP:port > domain (compromised) > IPv4 (non-shared) > IPv4 (shared/CDN).
Never assign high confidence to an IPv4 finding on a known CDN range.

### SHOULD check third-party scripts on sensitive pages first
Resources loaded on checkout, login, or PII-input pages should be checked against TI before general content pages. A TI match on a payment-page script is a higher-priority finding.

### SHOULD apply the 6-factor minimum before escalating
Before labeling a finding "malicious" or "critical":
1. Source authority ≥0.65 (medium-high source)
2. Indicator type specificity ≥0.50 (URL or non-CDN IP or domain)
3. Indicator age ≤90 days
4. Not shared infrastructure (CDN, cloud, NAT)
5. Direct match (not just IP of hosting provider)
6. Either ≥2 independent sources OR one high-authority source (GSB, URLHaus online)

### SHOULD surface even low-confidence matches as informational
A single OTX pulse match or low-confidence AbuseIPDB score should be shown to the customer analyst with full context ("1 source, shared infrastructure likely") rather than either suppressed entirely or escalated incorrectly.

## Finding Severity Mapping

| Composite Confidence | Indicator Type | WADE Severity |
|---|---|---|
| ≥0.80 | URL | CRITICAL |
| ≥0.80 | Domain (dedicated malicious) | HIGH |
| 0.50–0.79 | URL | HIGH |
| 0.50–0.79 | Domain | MEDIUM |
| 0.50–0.79 | IP (non-CDN) | MEDIUM |
| 0.20–0.49 | Any | LOW (informational) |
| Any | IP (CDN/cloud/shared) | INFORMATIONAL only |
| Any | Shodan/Censys exposure | EXPOSURE (not threat) |

## Implementation Reference

Existing scanner package: `scanner/webhound/threat_intel/`
- `urlhaus.py` — URLHaus client (implemented)
- `virustotal.py` — VirusTotal client (implemented)
- AbuseIPDB normalizer exists (no client)
- OpenPhish normalizer exists (no client)

When adding new TI source clients: implement the confidence model factors as configuration, not hardcoded thresholds.
