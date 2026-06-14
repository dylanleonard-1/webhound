# VirusTotal — Source Note

Provider: VirusTotal (Google) | Focus: Multi-engine malware/URL analysis
Auth: Free API key (4/min, 500/day) | Existing client: scanner/webhound/threat_intel/virustotal.py

## Key Detection Facts
- 70+ AV engines + 10+ sandboxes
- last_analysis_stats: {malicious, suspicious, harmless, undetected}
- reputation: community score (positive=trusted, negative=malicious)
- Relationship API: domain->IPs, file->URLs, URL->files (infrastructure pivoting)
- Indicator types: URL, domain, IPv4, file hash

## WebHound Use
- Multi-engine threshold: 5+ malicious detections for high confidence
- 1-4 detections: ambiguous; check which engines (experimental vs established)
- last_analysis_date: re-scan if >7 days old for active investigation
- Existing client already implemented
