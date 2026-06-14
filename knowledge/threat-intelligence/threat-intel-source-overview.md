# Threat Intelligence Source Overview

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Purpose

This document catalogs all threat intelligence sources integrated or planned for WebHound's WADE scoring system. It summarizes what each source measures, its indicator focus, and how to weight it in multi-source confidence calculations.

## Source Matrix

| Source | Type | Indicator Focus | Auth Required | Free Tier | Rate Limit | Coverage |
|---|---|---|---|---|---|---|
| URLHaus | Malware URLs | URL, domain, IP, hash | API key (free) | Yes | Not published | Active malware distribution |
| ThreatFox | Malware IOCs | URL, domain, IP:port, hash | API key (free) | Yes | Not published | C2, payload delivery, skimming |
| OpenPhish | Phishing URLs | URL | Org account | Community feed | Moderate | Active phishing pages |
| PhishTank | Phishing URLs | URL | API key (free) | Yes | Few/day anon | Community-verified phishing |
| OTX | Threat campaigns | All types | API key (free) | Yes | Not published | Broad TI, variable quality |
| AbuseIPDB | Abusive IPs | IPv4/IPv6 | API key (free) | 1k check/day | 1k/day std | Community-reported IP abuse |
| VirusTotal | Multi-engine | URL, domain, IP, hash | API key (free) | 4 req/min, 500/day | 4/min | Broadest coverage, 70+ engines |
| Google Safe Browsing | Web safety | URL | API key (free) | ~10k/day | Not published | Malware, phishing, UwS |
| GreyNoise | Internet noise | IPv4 | Optional (free) | 50/week | 50/week | Scanner/background noise IPs |
| Shodan | Exposure | IPv4, service banners | API key (paid useful) | Very limited | Credit-based | Internet-wide port/service scan |
| Censys | Exposure | IPv4, TLS certs | API ID+secret | ~250/month | Monthly quota | Internet-wide scan + certs |
| MISP | Federated TI | All types | Instance invite | Own instance | Varies | Community-shared campaigns |

## Source Categories

### Malware Distribution / C2
URLHaus, ThreatFox — best for URLs actively distributing malware or being used as C2 endpoints.

### Phishing
OpenPhish, PhishTank, Google Safe Browsing (SOCIAL_ENGINEERING type) — best for active phishing URLs.

### Multi-Engine / Broad Reputation
VirusTotal — aggregates 70+ engines; broadest coverage for any indicator type.

### IP Reputation
AbuseIPDB — community-reported abuse; high FP risk on shared hosting.
GreyNoise — internet background noise classification; essential for distinguishing scanners from targeted threats.

### Exposure Assessment (Not Malice)
Shodan, Censys — what services are exposed on an IP; NOT whether it's malicious.

### Campaign Context / Threat Intelligence Sharing
OTX, MISP — structured threat intelligence with campaign context, TTP mappings, threat actor attribution.

## WebHound Existing Clients

| Source | Client Status |
|---|---|
| URLHaus | ✅ Implemented (`scanner/webhound/threat_intel/urlhaus.py`) |
| VirusTotal | ✅ Implemented (`scanner/webhound/threat_intel/virustotal.py`) |
| AbuseIPDB | ⚠️ Normalizer exists, no API client |
| OpenPhish | ⚠️ Normalizer exists, no API client |
| ThreatFox | ❌ Not implemented |
| PhishTank | ❌ Not implemented |
| Google Safe Browsing | ❌ Not implemented |
| GreyNoise | ❌ Not implemented |
| Shodan | ❌ Not implemented |
| Censys | ❌ Not implemented |
| OTX | ❌ Not implemented |
| MISP | ❌ Not implemented (requires instance access) |

## Multi-Source Prioritization for WADE

When multiple sources agree: confidence multiplies. When only one source flags: use with caution.

Priority for automated findings:
1. Google Safe Browsing match (high precision, high volume coverage)
2. URLHaus `online` match + ThreatFox match (both abuse.ch = corroborated)
3. VirusTotal ≥5 engine detections
4. PhishTank verified phishing URL
5. AbuseIPDB score ≥75 + GreyNoise not-RIOT + numDistinctUsers ≥5

Priority for context-only (do NOT auto-flag):
- OTX single-pulse match (variable quality)
- AbuseIPDB score alone on shared hosting IP
- Shodan/Censys exposure data (tells you about attack surface, not malice)
- GreyNoise `noise: true` on RIOT IP (scanner = benign)
