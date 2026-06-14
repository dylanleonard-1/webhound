# Censys — Source Note

Provider: Censys | Focus: Internet-wide scan + TLS certificate analysis
Auth: Free researcher (~250/month) | Existing client: NOT implemented

## Key Detection Facts
- Strong TLS/certificate focus (vs Shodan which is broader)
- /hosts/{ip}: services array with port, transport_protocol, service_name, software, tls
- autonomous_system.asn, autonomous_system.name for ASN context
- Certificate transparency: find all IPs for a cert, SANs for subdomain discovery
- Exposure data only -- no malice classification

## WebHound Use
- Certificate-based subdomain discovery for customer domain scope
- TLS certificate details: recently issued certs on lookalike domains (phishing infra)
- Like Shodan: categorize as EXPOSURE, not THREAT
