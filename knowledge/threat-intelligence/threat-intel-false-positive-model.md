# Threat Intelligence False Positive Model

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Purpose

False positives are the primary risk in automated TI-based detection. This document catalogs the most common FP scenarios and how WADE should handle each.

## FP Scenario 1: Shared Hosting IPs

**Pattern**: AbuseIPDB score ≥50 on an IP that hosts hundreds of customer sites.

**Why it's a FP**: One abusive tenant on shared hosting generates abuse reports that apply to the IP. The customer's legitimate site shares the IP.

**Detection signals**:
- AbuseIPDB `usageType: Data Center/Web Hosting/Transit`
- Shodan/Censys shows many different domain `Server` headers on same IP
- GreyNoise `riot: true` (if it's a known shared hosting provider)
- Reverse DNS shows hosting provider (e.g., `server.bluehost.com`)

**Correct handling**: Do NOT report the IP as malicious for the customer. Instead: note "shared hosting IP with abuse reports — likely other tenants". Recommend customer-specific URL-level checks.

## FP Scenario 2: CDN / Proxy IPs

**Pattern**: Cloudflare edge IP, Fastly cache node, Akamai PoP flagged in AbuseIPDB or VirusTotal.

**Why it's a FP**: Millions of legitimate sites use these IPs. Some hosted sites may be malicious, but the CDN IP itself is infrastructure.

**Detection signals**:
- GreyNoise `riot: true, name: "Cloudflare"` (or Fastly, Akamai, etc.)
- ASN belongs to known CDN: AS13335 (Cloudflare), AS54113 (Fastly), AS20940 (Akamai), AS16509 (AWS)
- `x-vercel-id` / `server: Vercel` / `via: varnish` response headers

**Correct handling**: CDN IP match = definitive FP. Suppress IP-level finding; check URL-level for malicious specific paths only.

## FP Scenario 3: Dynamic Cloud IPs

**Pattern**: AWS/GCP/Azure IP with AbuseIPDB reports.

**Why it's a FP**: Cloud IPs are recycled. A previously abusive IP now hosts a legitimate Lambda function or Cloud Run service. The abuse reports are from a previous tenant.

**Detection signals**:
- AbuseIPDB `usageType: Data Center/Web Hosting/Transit`
- ASN is major cloud provider (AWS AS16509, GCP AS15169, Azure AS8075)
- AbuseIPDB `lastReportedAt` > 30 days ago

**Correct handling**: Check `lastReportedAt`. If >30 days and no current-behavior evidence, suppress or downgrade.

## FP Scenario 4: Parked / Sold Domains

**Pattern**: Domain in TI database was malicious, then parked or sold to a new registrant.

**Why it's a FP**: Old IOC persists in TI feed after domain changes hands.

**Detection signals**:
- VirusTotal `last_analysis_date` is old
- Current DNS resolution shows parking page or generic content
- WHOIS creation date ≠ TI first seen (domain re-registered)
- ThreatFox IOC expiration policy: IOCs >6 months automatically expired

**Correct handling**: Check IOC age vs current site behavior. If IOC is stale (>90 days) and site appears legitimate, downgrade confidence significantly.

## FP Scenario 5: Expired / Reused Infrastructure

**Pattern**: IP or domain used by malicious actor, infrastructure decommissioned and reassigned.

**Why it's a FP**: Internet infrastructure reuse is common. IP blocks are reallocated; domains are re-registered.

**Detection signals**:
- ThreatFox IOC age >6 months (platform auto-expires these)
- URLHaus `status: offline` (URL no longer serving malware)
- VirusTotal `last_analysis_date` >90 days with recent clean scans

**Correct handling**: Do NOT act on `offline` URLHaus records or expired ThreatFox IOCs as current threats.

## FP Scenario 6: Stale TI Records

**Pattern**: TI source hasn't re-checked the indicator recently.

**Why it's a FP**: Malware URL was taken down; TI source still lists it as malicious.

**Detection signals**:
- URLHaus `status: offline` or `status: unknown`
- VirusTotal `last_analysis_date` old with recent `harmless` engine verdicts
- GSB `cacheDuration` expired (re-query returns no match)

**Correct handling**: Use `status` and `last_analysis_date` fields. Prefer sources that actively re-check URLs (URLHaus, GSB) over passive lists.

## FP Scenario 7: Low-Confidence Community Reports

**Pattern**: Single AbuseIPDB reporter, one OTX pulse from unknown author, low-reputation source.

**Why it's a FP**: Community contribution quality varies; automated scanners, vendetta reporters, errors all generate noise.

**Detection signals**:
- AbuseIPDB `numDistinctUsers: 1`
- OTX pulse from user with <10 followers, no references
- VirusTotal: only 1 experimental/minor engine flags

**Correct handling**: Apply minimum thresholds — AbuseIPDB requires numDistinctUsers ≥3; VT requires ≥5 established engines; OTX requires corroboration from another source.

## FP Scenario 8: Typosquatting Lookalikes

**Pattern**: TI database contains `paypa1.com`; customer site loads from `paypal.com` (legitimate). Scanner fuzzy-matches.

**Why it's a FP**: Incorrect indicator matching.

**Correct handling**: Always use exact-match comparisons for domain/URL indicators. Normalized form comparison only.

## FP Scenario 9: URL-Level vs Domain-Level Maliciousness

**Pattern**: URLHaus flags `example.com/malware.exe` but customer site loads `example.com/styles.css` (different path on same domain).

**Why it's a FP**: Only the specific path was malicious, not the whole domain. The domain may be a legitimate site with one compromised path.

**Detection signals**:
- URLHaus uses `abused_legit_*` tags for compromised legitimate sites
- `abused_legit_malware`: legitimate site distributing malware from one path

**Correct handling**: Match at URL level. If only a specific path is flagged and customer loads a different path, report as "domain in TI for specific path — verify path matches" not "malicious domain".

## FP Scenario 10: One Bad Path on a Legitimate Domain (Script Loading)

**Pattern**: `cdn.jquery.com/jquery.min.js` appears in a TI feed because a malicious page once used it as a resource.

**Why it's a FP**: The resource itself is legitimate; the malicious page happened to load it.

**Correct handling**: ThreatFox and URLHaus focus on malware distribution URLs, not resources loaded by malicious pages. Check whether the URL is itself the threat or just a dependency of a threat.

## FP Scenario 11: Internet-Noise / Scanner IPs

**Pattern**: Shodan research bot, security scanner IP appears in AbuseIPDB.

**Why it's a FP**: Security researchers, Shodan, Censys, and other legitimate scanners generate abuse reports from users who don't want to be scanned.

**Detection signals**:
- GreyNoise `riot: true, classification: benign, name: "Shodan"` (or similar)
- GreyNoise `noise: true` but `classification: benign`

**Correct handling**: GreyNoise RIOT classification overrides AbuseIPDB reports for scanner IPs. Do not block Shodan, Censys, or security researcher IPs.

## FP Scenario 12: Benign Third-Party Analytics / CDN Scripts

**Pattern**: Customer loads Google Analytics, Hotjar, Intercom, Stripe.js — one of these domains appears in a threat feed due to a completely unrelated incident.

**Why it's a FP**: Well-known legitimate services occasionally appear in threat feeds due to abuse of a subdomain, a DDoS attack against them, or researcher testing.

**Detection signals**:
- VirusTotal: domain has established positive reputation
- GreyNoise RIOT for known business services
- The flagged URL is a canonical SDK URL (`analytics.google.com/analytics.js`)

**Correct handling**: Maintain an internal allowlist of known legitimate third-party script domains (see provider-docs). Suppress TI findings against allowlisted domains unless finding is URL-specific and confirmed malicious.
