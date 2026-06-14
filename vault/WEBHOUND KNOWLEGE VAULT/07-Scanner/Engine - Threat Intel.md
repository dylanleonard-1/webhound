---
title: "Engine: Threat Intel"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Threat Intel

## Purpose
Enriches scanner findings with external threat intelligence: IP reputation, domain reputation, malware associations, botnet membership, VirusTotal data.

## Inputs
- IPs and domains discovered during scan
- Finding severity context

## Outputs
- Reputation scores per IP/domain
- ThreatIndicator records
- Enriched finding metadata (`evidence` JSON field)

## Sources
- VirusTotal (domain/IP reputation)
- GreyNoise (shared CDN IPs — reduces FP for CDN-shared IPs)
- Internal TI corpus (9 official_threat_intel_doc records)

## Related Taxonomy
- CWE-693 (Protection Mechanism Failure) for sites loading malicious domains
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- GreyNoise "shared CDN" classification → reduces TI finding confidence
  (CDN IPs shared across many customers shouldn't trigger infra compromise findings)
- [[08-WADE/index|WADE]]

## Knowledge Corpus
- 9 official_threat_intel_doc records in manifest

## DB Objects
- `ThreatIndicator` model → `models/threat_indicator.py`
- `services/threat_intel.py`

## See Also
- [[09-Threat Intelligence/index|Threat Intel Index]] · [[07-Scanner/Engine - Compromise Detection|Compromise Detection]]

#webhound #scanner #threat-intel
