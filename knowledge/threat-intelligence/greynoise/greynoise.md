# GreyNoise — Source Note

Provider: GreyNoise Intelligence | Focus: Internet background noise classification
Auth: Optional (free community: 50 searches/week) | Existing client: NOT implemented

## Key Detection Facts
- noise: true = IP observed scanning internet (last 90 days)
- riot: true = known legitimate business service IP (CDN, cloud, security tools)
- classification: benign/malicious/unknown
- 404 = IP never observed scanning (not in GreyNoise dataset)

## WebHound Use
- Use to resolve AbuseIPDB ambiguity: riot=true overrides abuse score
- malicious classification + not-riot = corroborating signal for IP findings
- Community API sufficient for basic resolution (50/week = adequate for most scans)
