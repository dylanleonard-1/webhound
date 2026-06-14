# MISP — Source Note

Provider: MISP Project (open source) | Focus: Federated threat intelligence sharing
Auth: Instance invite required | Existing client: NOT implemented

## Key Detection Facts
- to_ids flag: ONLY attributes with to_ids=true should trigger automated action
- distribution levels: 0=org only to 3=all communities
- Event threat_level_id: 1=High, 2=Medium, 3=Low
- Attribute types: 100+ (domain, ip-src/dst, url, md5, sha256, filename, mutex, CVE...)
- Galaxy: pre-built threat actor / malware family / ATT&CK TTP context

## WebHound Use
- Requires invitation to a MISP instance (not a public SaaS API)
- If accessible: use as high-context TI source for campaign attribution
- Always filter: only to_ids=true + distribution >= 1 + recent first_seen
- Quality varies widely by contributing organization
