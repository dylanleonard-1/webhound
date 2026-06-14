# AbuseIPDB — Source Note

Provider: AbuseIPDB | Focus: Community-reported IP abuse
Auth: Free API key (1000/check/day std tier) | Existing client: Normalizer only

## Key Detection Facts
- abuseConfidenceScore: 0-100; hard minimum 25 (prevents single-report severity)
- numDistinctUsers: key FP signal -- 1 reporter = low confidence
- usageType: Data Center/Web Hosting = shared hosting FP risk
- isWhitelisted: non-binary; not a safe-harbor guarantee
- Test IP: 127.0.0.2 (simulates 15-min rate limit)

## WebHound Use
- Require numDistinctUsers >= 3 before including in findings
- Cross-reference with GreyNoise for shared-infra resolution
- Never use abuseConfidenceScore alone as a finding trigger
- Implement API client (normalizer exists but no client)
