# URLHaus — Source Note

Provider: abuse.ch URLHaus | Focus: Active malware distribution URLs
Auth: Free API key (auth.abuse.ch) | Existing client: scanner/webhound/threat_intel/urlhaus.py

## Key Detection Facts
- Tracks URLs actively distributing malware (drive-by downloads, payload delivery)
- URL status: online=active, offline=inactive, unknown=unchecked
- Spamhaus DBL integration: flags phishing_domain, botnet_cc_domain, abused_legit_*
- Hash lookup: MD5, SHA256, IMPHASH, SSDEEP, TLSH for payload identification
- Batch downloads available hourly and daily (ZIP, password: infected)

## WebHound Use
- Check all third-party URLs from customer pages against URLHaus
- online status + URL-level match = high-confidence malware delivery finding
- abused_legit_* tag = legitimate domain compromised; scope finding to URL, not domain
- Existing client already implemented; no new auth setup needed
