# Threat Intelligence Confidence Model

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Purpose

This model defines how WADE should calculate confidence in a threat intelligence finding. No single source or signal should auto-trigger a critical finding. Confidence must be composed from multiple independent factors.

## The 12 Confidence Factors

### Factor 1: Source Authority
Weight: HIGH

| Source Authority | Score |
|---|---|
| Google Safe Browsing (match) | 0.90 |
| URLHaus `online` status | 0.85 |
| ThreatFox (vetted IOC) | 0.85 |
| PhishTank (community-verified) | 0.80 |
| VirusTotal ≥10 engine detections | 0.85 |
| VirusTotal 5–9 detections | 0.70 |
| VirusTotal 1–4 detections | 0.35 |
| AbuseIPDB score ≥75 (not shared hosting) | 0.65 |
| GreyNoise `classification: malicious` | 0.60 |
| OpenPhish paid feed match | 0.75 |
| OTX single-pulse match | 0.30 |
| AbuseIPDB score 25–74 | 0.30 |
| Shodan/Censys (exposure data) | 0.10 |

### Factor 2: Indicator Type Specificity
Weight: HIGH

- Full URL match: 1.0 (highest — exact hit)
- Domain match (dedicated malicious domain): 0.8
- Domain match (compromised legitimate): 0.4 (URL-level finding, not domain)
- IP:port match: 0.6
- IPv4 match (shared hosting/CDN): 0.15
- File hash (SHA256): 0.95
- File hash (MD5): 0.80

### Factor 3: Indicator Age
Weight: MEDIUM

| Age | Multiplier |
|---|---|
| <7 days old | 1.0 |
| 7–30 days | 0.85 |
| 30–90 days | 0.65 |
| 90–180 days | 0.40 |
| >180 days | 0.20 |

ThreatFox automatically expires IOCs at 6 months — if querying ThreatFox and IOC is recent, age factor is favorable by definition.

### Factor 4: Number of Independent Confirming Sources
Weight: HIGH (multiplicative benefit)

| # Independent Sources | Confidence Boost |
|---|---|
| 1 source | 1.0x (baseline) |
| 2 independent sources agree | 1.5x |
| 3+ independent sources agree | 2.0x |

"Independent" means different organizations (URLHaus + VirusTotal counts; URLHaus + ThreatFox = same vendor family, counts as 1.3x). Google Safe Browsing is always independent.

### Factor 5: Direct vs Indirect Match
Weight: MEDIUM

- Direct: indicator is literally present on the customer site (URL loaded in page, script tag, redirect destination) → full confidence
- Indirect: indicator found via IP of hosting server, ASN of CDN, domain registrar → reduce confidence by 0.5x

### Factor 6: Shared Infrastructure Penalty
Weight: HIGH (downward)

If the indicator is a known shared infrastructure IP (CDN, cloud, shared hosting):
- GreyNoise `riot: true`: multiply confidence by 0.1
- `usageType: Data Center/Web Hosting/Transit` in AbuseIPDB: multiply by 0.3
- Known CDN ASN (Cloudflare AS13335, Fastly AS54113, Akamai AS20940, AWS AS16509): multiply by 0.15

### Factor 7: User-Controlled Third-Party Domain
Weight: HIGH (upward for script URLs)

A third-party URL loaded by the customer page (e.g., `<script src="https://...">` or analytics) that matches TI is a stronger finding than a background IP match:
- Customer directly serves or loads the indicator → upward factor 1.5x
- Background network infra match → no upward factor

### Factor 8: Sensitive Page Context
Weight: MEDIUM (upward)

If the TI-matching resource appears on:
- Checkout / payment page: 1.4x
- Login / authentication page: 1.3x
- Form with PII input: 1.3x
- General content page: 1.0x

### Factor 9: Newly Observed Since Baseline
Weight: MEDIUM (upward)

If the indicator was not present in a previous scan of the same site:
- Newly appeared + TI match: 1.3x (new introduction is suspicious)
- Present in all scans (long-standing): 1.0x (possibly benign legacy)

### Factor 10: High-Confidence-Malicious vs Only-Suspicious Classification
Weight: HIGH

- Confirmed malicious (URLHaus `online`, GSB match, VT ≥5): use high-confidence path
- Only suspicious (low-confidence OTX pulse, single VT engine, AbuseIPDB 30–50): use informational path — do not auto-escalate

### Factor 11: Crowdsourced vs Commercial vs Official vs Community
Weight: MEDIUM

| Data Source Type | Base Reliability |
|---|---|
| Official/automated (GSB, URLHaus active check) | High |
| Commercial (OpenPhish paid, VT premium) | High |
| Community-curated + vetted (PhishTank verified) | Medium-High |
| Crowdsourced + moderated (AbuseIPDB with ≥5 reporters) | Medium |
| Community-contributed unvetted (OTX single author) | Low |

### Factor 12: Recency at Query Time
Weight: MEDIUM

- `URLHaus: status = online` at time of scan: highest recency confidence
- `GSB: cacheDuration not expired`: current result
- `VT last_analysis_date` > 7 days ago: reduce confidence (stale scan)
- `AbuseIPDB lastReportedAt` > 30 days ago: reduce confidence

## Composite Score Calculation

```
composite = source_authority_score
          × indicator_type_specificity
          × age_multiplier
          × (1 + (confirming_sources - 1) × 0.5)
          × direct_indirect_factor
          × shared_infra_penalty
          × third_party_upward_factor
          × sensitive_page_factor
          × newly_observed_factor
```

Clip to [0.0, 1.0].

## Thresholds

| Composite Score | WADE Action |
|---|---|
| ≥0.80 | HIGH confidence finding — report as malicious/suspicious with strong evidence |
| 0.50–0.79 | MEDIUM confidence — report as "should be reviewed" with context |
| 0.20–0.49 | LOW confidence — note as "TI match with limited confidence, shared infrastructure likely" |
| <0.20 | INFORMATIONAL only — do not surface to customer as a finding |
