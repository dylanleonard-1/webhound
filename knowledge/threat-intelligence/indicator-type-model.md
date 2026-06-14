# Indicator Type Model

Category: TI knowledge synthesis | WebHound Phase 6E
Updated: 2026-06-13

## Indicator Types and Source Coverage

### URL (full URL string)
**Highest specificity.** A malicious URL match is the strongest possible TI signal — it names exactly what was found on the customer's site.

Sources: URLHaus, ThreatFox, OpenPhish, PhishTank, VirusTotal, Google Safe Browsing, OTX

Confidence factors:
- Exact URL match (not prefix match): highest confidence
- Prefix match (matching URL pattern): moderate confidence
- Source has confirmed the URL is `online`/`active`: highest confidence
- URL is only flagged by one community source (OTX): lower confidence

False positive risk: LOW — URL-level specificity rarely produces FPs on legitimate traffic.

### Domain
**High specificity** for dedicated malicious domains. Lower specificity for compromised legitimate domains.

Sources: URLHaus (host), ThreatFox (domain type), VirusTotal (domains), AbuseIPDB (indirect), OTX, MISP

Confidence factors:
- Domain registered <30 days ago + malicious reputation: high confidence
- Known malicious malware domain (URLHaus/ThreatFox `malware_download`): high confidence
- Legitimate domain compromised (URLHaus `abused_legit_*`): URL-level, not domain-level finding

False positive risk: MEDIUM — legitimate domains appear in TI due to compromise or shared hosting. Always check if the entire domain is malicious or only specific paths.

### IPv4 / IPv6
**Lowest specificity.** IP addresses are shared infrastructure — multiple parties use same IPs.

Sources: AbuseIPDB, GreyNoise, URLHaus (host query), VirusTotal, Shodan, Censys, OTX, ThreatFox (ip:port)

Confidence factors:
- IP:port match (ThreatFox botnet_cc): moderate confidence (specific service on IP)
- AbuseIPDB score ≥75 + numDistinctUsers ≥10 + not RIOT: moderate confidence
- GreyNoise `classification: malicious`: moderate confidence (active attacker)
- Shodan/Censys exposure data: NOT a malice signal

False positive risk: HIGH — shared hosting, CDN edge IPs, cloud ranges, NAT, VPN exits all cause FPs.

### File Hash (MD5/SHA256)
**Highest specificity for malware.** A hash match = the exact binary is in TI database.

Sources: URLHaus (payload), ThreatFox, VirusTotal, OTX, MISP

Confidence factors:
- SHA256 match (collision-resistant): near-certain malware identification
- VirusTotal ≥5 engine detections on hash: high confidence
- URLHaus payload hash: confirmed malware sample distribution

False positive risk: VERY LOW — cryptographic hash collision extremely improbable. However: test samples, security researcher files, crackme files may match.

### Malware Family
**Contextual indicator** — not directly actionable without other IOC types.

Sources: ThreatFox (Malpedia labels), URLHaus (signature), VirusTotal (categories), OTX (tags), MISP (malware-type attribute)

Use: associate detected IOCs with a named malware family for context/severity escalation.

### Hostname / FQDN
Similar to domain but may be more specific (subdomain). Sources: MISP, OTX.

### ASN
Network ownership context. Not a malice indicator — useful for geographic/organizational context.
Sources: GreyNoise, AbuseIPDB (ISP field), Shodan (asn field), Censys (autonomous_system).

### Certificate Fingerprint / Subject
TLS certificate analysis — for identifying phishing infrastructure reusing certificates.
Sources: Censys (strongest), VirusTotal (TLS history), Shodan (ssl.cert).

## Source-to-Indicator Type Coverage Matrix

| Source | URL | Domain | IPv4 | Hash | Family | Hostname | Certificate |
|---|---|---|---|---|---|---|---|
| URLHaus | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| ThreatFox | ✅ | ✅ | ✅ (ip:port) | ✅ | ✅ | ❌ | ❌ |
| OpenPhish | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| PhishTank | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| OTX | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| AbuseIPDB | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| VirusTotal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| GSB | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| GreyNoise | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Shodan | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Censys | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| MISP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
