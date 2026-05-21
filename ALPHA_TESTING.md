# WebHound — Closed Alpha Testing Program

**Status**: Closed alpha — invite-only  
**Cohort size**: 5–20 trusted testers  
**Scope**: Local Docker deployment only — no shared cloud instance

---

## What You're Testing

WebHound is a passive website security monitoring tool. It crawls pages you own, inspects HTTP headers, cookies, TLS configuration, and JavaScript sources, then surfaces actionable findings and tracks changes over time.

This alpha focuses on:
- Core scan pipeline (quick / standard profiles)
- API correctness and error handling
- Findings accuracy and false-positive rate
- Docker setup experience
- Frontend usability for the main flows

## What You Are NOT Testing

- Payment features (not built)
- Public cloud deployment (not available)
- New scanner engines (none added this phase)

---

## Before You Start — Read This

**You must only scan websites you own or have explicit written authorization to test.**

WebHound performs passive, read-only HTTP requests. It does not exploit vulnerabilities or submit forms. It is still your responsibility to ensure your use of this tool is lawful and authorized.

See `SECURITY_NOTICE.md` for the full policy and legal context.

---

## How to Participate

### 1. Accept the Invite

You received this repository link directly. Do not share it publicly. This is a private, closed test.

### 2. Set Up Your Environment

Follow `TESTER_SETUP.md` exactly. The entire stack runs locally in Docker — no accounts, no cloud, no billing.

Estimated setup time: 10–15 minutes on a modern machine with a stable internet connection (for Docker image pulls).

### 3. Run the Demo Flow

Follow the steps in `TESTER_SETUP.md` § Demo Flow to walk through the core user journey from login to scan to results to report download.

Use `example.com` as the scan target during your initial setup to verify everything works. Then test against a domain you own for more realistic findings.

### 4. Test Beyond the Happy Path

Alpha testing is most useful when testers go off-script. Things to try:

- Use wrong credentials at login
- Add an invalid URL as a website
- Cancel a running scan
- Run a second scan to see WADE baseline comparison
- Download all four report formats (JSON, SARIF, CSV, Markdown)
- Create and disable a weekly schedule
- Check that notifications appear after a scan completes

### 5. Report Bugs

Use the template in `BUG_REPORT_TEMPLATE.md` for every defect you find.

File bug reports as GitHub issues (if you have access) or email them to the maintainer with the template filled out.

### 6. Submit Feedback

After your session, complete the `FEEDBACK_TEMPLATE.md` and return it to the maintainer. This is as valuable as the bug reports.

---

## Important: Alpha Software Caveats

- **Findings may be incorrect.** False positives and false negatives are expected in alpha.
- **The API is not stable.** Response shapes may change between alpha builds.
- **Data does not persist across** `docker compose down -v`. Use `docker compose down` (no `-v`) to keep your data.
- **No email delivery.** Notifications are in-app only.
- **Domain verification is bypassed** in dev mode (`DEV_ALLOW_UNVERIFIED_SCANS=true` in `docker-compose.yml`). This is intentional for local testing and must not be used in any deployment that faces external traffic.

---

## Known Issues

See `KNOWN_LIMITATIONS.md` for the full list of intentional limitations and known bugs.

---

## Contact

Feedback and bug reports go to the maintainer who sent your invite.  
Do not post issues or screenshots on public channels — this is a private alpha.

---

## Timeline

This alpha cohort has no hard end date. The maintainer will announce when the program advances to closed beta. Testers in this cohort will be first invited to the beta.
