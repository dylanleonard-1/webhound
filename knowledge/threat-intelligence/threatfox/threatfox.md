# ThreatFox — Source Note

Provider: abuse.ch ThreatFox | Focus: Malware IOCs (C2, skimming, payload delivery)
Auth: Free API key (same as URLHaus) | Existing client: NOT implemented

## Key Detection Facts
- IOC types: URL, domain, IP:port, MD5/SHA256
- Threat types: botnet_cc, payload_delivery, cc_skimming (Magecart)
- Confidence: 0-100 self-reported by submitter; treat <50 with caution
- IOCs expire after 6 months (automatic cleanup for cloud infra FP reduction)
- Malware families from Malpedia

## WebHound Use
- cc_skimming IOC on checkout-page script URL = CRITICAL (Magecart detection)
- botnet_cc ip:port match = C2 infrastructure finding (high severity if specific)
- Same API key as URLHaus — easy to add second client
