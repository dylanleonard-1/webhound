# URL vs Domain vs IP Confidence

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Core Principle

Specificity determines confidence. A match at URL level is always stronger than domain level, which is always stronger than IP level — unless the IP match is on dedicated malicious infrastructure (not shared).

## URL-Level Confidence

**Definition**: The full URL path (scheme + host + path + query) matches a TI indicator.

**Strength**: HIGHEST — URL is the exact attack surface.

**Example**: `https://evil.com/payload.zip` matches URLHaus.

**Confidence**: Full confidence per source authority. A URL-level URLHaus `online` match = near-certain active malware distribution.

**When to promote to domain-level**: Only if the entire domain is explicitly classified as malicious (URLHaus `abused_legit_malware` = NO; ThreatFox `payload_delivery` domain type = YES for that domain).

**Caveats**:
- URL query parameters may differ (normalization required)
- HTTP vs HTTPS variants should both be checked
- URL encoding variants should be canonicalized before matching

## Domain-Level Confidence

**Definition**: The domain (or subdomain) of a URL matches a TI indicator.

**Two scenarios with very different confidence**:

### Scenario A: Dedicated Malicious Domain
Domain was registered specifically for malicious activity (e.g., `malware-cdn.evil-actor.com`, newly registered domain in ThreatFox as `payload_delivery`).
- **Confidence**: HIGH — the whole domain is malicious, every URL on it is suspect.
- **Signals**: Newly registered (<30 days), no legitimate use case, ThreatFox `domain` type.

### Scenario B: Compromised Legitimate Domain
Domain is a known legitimate site where one path was compromised (URLHaus `abused_legit_malware`).
- **Confidence**: MEDIUM for the specific path, LOW for the domain broadly.
- **Signals**: URLHaus `abused_legit_*` tag, VirusTotal domain has mixed positive reputation + one malicious URL.
- **WADE rule**: Do NOT classify the whole domain as malicious. Find the specific path match.

## IP-Level Confidence

**Definition**: The IP address resolves to a host in a TI database.

**Strength**: LOWEST — IPs are always shared to some degree.

**Three scenarios**:

### Scenario A: Dedicated Attack Infrastructure
IP is exclusively used by a known threat actor (small C2 VPS, not a CDN/shared hosting).
- **Confidence**: MEDIUM-HIGH — a dedicated malicious server.
- **Signals**: GreyNoise `classification: malicious`, ThreatFox `botnet_cc` ip:port, not in shared hosting ASN, few other domains resolve to this IP.

### Scenario B: Shared Hosting / Cloud / CDN
IP hosts many parties.
- **Confidence**: VERY LOW — almost certainly a FP for this specific customer.
- **Signals**: AbuseIPDB `usageType: Data Center`, GreyNoise `riot: true`, Shodan shows many different `Server` headers.

### Scenario C: ISP / Residential
Dynamic IP assigned to end-users.
- **Confidence**: LOW — IP rotates; reports from previous holder.
- **Signals**: `usageType: ISP/Residential`, AbuseIPDB reports may be from abuse by previous IP holder.

## Matching Hierarchy in Practice

When checking a customer-site resource at `https://cdn.example.com/script.js` hosted at `1.2.3.4`:

1. **Check URL first**: Does `https://cdn.example.com/script.js` appear in any TI database?
   - If YES + source confidence high → HIGH confidence finding
2. **Check domain second**: Is `cdn.example.com` or `example.com` in TI as a dedicated malicious domain?
   - If YES + newly registered + dedicated malicious → HIGH confidence
   - If YES but compromised legitimate → MEDIUM confidence, note path-specificity
3. **Check IP last**: Is `1.2.3.4` in AbuseIPDB or VirusTotal?
   - Check GreyNoise for shared-infrastructure determination
   - If CDN/cloud → suppress; if dedicated + `malicious` → MEDIUM confidence

## Cross-Level Corroboration

When URL matches at multiple levels (URL + domain + IP all flagged by different sources):
- Each independent level adds confidence (see threat-intel-confidence-model.md Factor 4)
- Three-level match → multiply individual confidences (e.g., 0.85 × 0.80 × 0.60 = 0.41) — but add bonus for multi-level corroboration

## Domain vs Subdomain

A TI match on `evil.com` does NOT automatically apply to `safe-cdn.evil.com` (legitimate CDN use of a wildcard domain by a different party).
A TI match on `ads.evil.com` does NOT automatically apply to `evil.com` (subdomain may be a compromised subdomain of an otherwise clean site).

Always verify at the most specific level available.
