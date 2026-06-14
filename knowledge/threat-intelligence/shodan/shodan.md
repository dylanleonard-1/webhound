# Shodan — Source Note

Provider: Shodan | Focus: Internet-wide exposure assessment
Auth: Paid API key useful | Existing client: NOT implemented

## Key Detection Facts
- /shodan/host/{ip}: free, no credits -- all services on an IP
- tags: compromised, malware, scanner, ics, tor, vpn
- Data represents exposure, NOT malice (critical distinction)
- cpe fields: cross-reference with CVEs for vulnerability context
- Banners may be weeks/months old -- always check timestamp

## WebHound Use
- Unexpected open ports on customer IP = exposure finding (not threat)
- tags: compromised/malware = elevated concern; verify with current behavior
- Categorize as EXPOSURE findings, not THREAT findings
