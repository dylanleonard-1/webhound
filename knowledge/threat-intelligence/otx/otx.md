# AlienVault OTX — Source Note

Provider: LevelBlue (formerly AlienVault) | Focus: Community threat intelligence pulses
Auth: Free API key | Existing client: NOT implemented
Note: Site is JS-heavy SPA; docs not machine-readable

## Key Detection Facts
- Pulse = grouped IOC collection around a threat campaign
- Indicator types: domain, hostname, IPv4, IPv6, URL, hash, CVE, email, mutex, CIDR
- No formal confidence score -- assess by: author reputation, reference quality, TLP level
- expiration field on indicators: respect for freshness filtering
- TLP markings: WHITE/GREEN/AMBER/RED

## WebHound Use
- Use for campaign context after high-confidence IOC match
- Do NOT use OTX single-pulse match alone as a customer-facing finding
- Cross-reference pulses with URLHaus/VT/GSB before reporting
