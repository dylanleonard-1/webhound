# WebHound — scanner/webhound/engines/tls_dns/dns_checker.py
# Passive DNS record analysis.
#
# Safe-mode: standard DNS queries only.
# No zone transfers (AXFR), no brute force, no recursive subdomain enumeration.
# resolve_dns() queries each record type once using dnspython (stdlib fallback available).

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "dns_checker"

_SPF_PLUS_ALL = re.compile(r"\+all\b", re.I)
_SPF_NEUTRAL_ALL = re.compile(r"\?all\b", re.I)

# Enterprise metadata per finding kind. DNS findings cluster around
# A05:2021 (Security Misconfiguration) for email-auth + delegation issues
# and A02:2021 (Cryptographic Failures) for DNSSEC / CAA / MTA-STS.
_FA: dict[str, FrameworkAlignment] = {
    "resolution_failure": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-350"], nist_controls=["SC-20"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", cvss_score=7.5,
        pci_dss=["A1.2.1"], iso_27001=["A.8.32"],
        exploitability=Exploitability.UNKNOWN,
    ),
    "spf_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-290"], nist_controls=["SC-20", "SI-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", cvss_score=6.5,
        pci_dss=["5.4.1"], iso_27001=["A.5.14", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "spf_plus_all": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-290"], nist_controls=["SC-20", "SI-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", cvss_score=6.5,
        pci_dss=["5.4.1"], iso_27001=["A.5.14", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "spf_neutral": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-290"], nist_controls=["SC-20", "SI-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.7,
        pci_dss=["5.4.1"], iso_27001=["A.5.14", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "dmarc_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-290"], nist_controls=["SC-20", "SI-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["5.4.1"], iso_27001=["A.5.14", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "dkim_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-290"], nist_controls=["SC-20", "SI-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.1,
        pci_dss=["5.4.1"], iso_27001=["A.5.14", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "mx_missing_with_spf": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-350"], nist_controls=["SC-20"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", cvss_score=3.1,
        iso_27001=["A.8.32"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "ns_single": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-350"], nist_controls=["SC-20"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", cvss_score=3.1,
        iso_27001=["A.8.14"], soc2=["CC9.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "cname_chain_long": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-350"], nist_controls=["SC-20"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L", cvss_score=4.3,
        iso_27001=["A.8.32"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "dnssec_missing": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-345"], nist_controls=["SC-20", "SC-21"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=5.9,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "caa_missing": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-295"], nist_controls=["SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.1,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "mta_sts_missing": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8", "SC-20"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.1,
        pci_dss=["4.2.1"], iso_27001=["A.5.14", "A.8.24"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "takeover_candidate": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-350"], nist_controls=["SC-20", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_score=10.0,
        pci_dss=["6.4.2"], iso_27001=["A.5.14", "A.8.9"], soc2=["CC7.1"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
}


@dataclass
class DnsRecords:
    """DNS records collected for a single domain.

    Attributes:
        domain: The queried domain name.
        a: IPv4 address records.
        aaaa: IPv6 address records.
        cname: CNAME target chain (ordered, as returned by resolver).
        mx: MX records (exchange hostnames, priority stripped).
        txt: TXT records for the domain itself.
        ns: NS records (nameserver hostnames).
        dmarc_txt: TXT records at ``_dmarc.{domain}``.
        caa: CAA records — controls which CAs may issue certs for the domain.
        dnskey: DNSKEY records — presence indicates DNSSEC signing.
        mta_sts_txt: TXT records at ``_mta-sts.{domain}``.
        tls_rpt_txt: TXT records at ``_smtp._tls.{domain}``.
        dkim_selectors_seen: List of selectors (e.g. "google", "default")
            for which we found a non-empty DKIM TXT record at
            ``{selector}._domainkey.{domain}``.
        resolution_error: Set if no A/AAAA/CNAME could be resolved.
    """

    domain: str

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    dmarc_txt: list[str] = field(default_factory=list)

    # Extended record types
    caa: list[str] = field(default_factory=list)
    dnskey: list[str] = field(default_factory=list)
    mta_sts_txt: list[str] = field(default_factory=list)
    tls_rpt_txt: list[str] = field(default_factory=list)
    dkim_selectors_seen: list[str] = field(default_factory=list)

    resolution_error: str | None = None

    @property
    def spf_records(self) -> list[str]:
        return [r.strip('"') for r in self.txt if r.strip('"').lower().startswith("v=spf1")]

    @property
    def has_a_or_aaaa(self) -> bool:
        return bool(self.a or self.aaaa)

    @property
    def has_dmarc(self) -> bool:
        return any(r.strip('"').lower().startswith("v=dmarc1") for r in self.dmarc_txt)

    @property
    def has_dnssec(self) -> bool:
        return bool(self.dnskey)

    @property
    def has_mta_sts(self) -> bool:
        return any(r.strip('"').lower().startswith("v=stsv1") for r in self.mta_sts_txt)

    @property
    def has_tls_rpt(self) -> bool:
        return any(r.strip('"').lower().startswith("v=tlsrptv1") for r in self.tls_rpt_txt)


def resolve_dns(domain: str, timeout: float = 5.0) -> DnsRecords:
    """Resolve DNS records for *domain*.

    Safe-mode: issues standard read-only queries (A, AAAA, CNAME, MX, TXT, NS).
    Requires ``dnspython``; falls back to stdlib socket for A/AAAA only.
    """
    try:
        import dns.resolver as _resolver
    except ImportError:
        return _stdlib_resolve(domain, timeout)

    # dnspython ≥ 2.0 relocated NXDOMAIN/NoAnswer/NoNameservers into dns.resolver.
    _NOT_FOUND = (
        _resolver.NXDOMAIN,
        _resolver.NoAnswer,
        _resolver.NoNameservers,
    )

    records = DnsRecords(domain=domain)
    resolver = _resolver.Resolver()
    resolver.lifetime = timeout

    def _query(qname: str, qtype: str) -> list[str]:
        try:
            return [str(r) for r in resolver.resolve(qname, qtype)]
        except _NOT_FOUND:
            return []
        except Exception:
            return []

    records.a = _query(domain, "A")
    records.aaaa = _query(domain, "AAAA")
    records.cname = _query(domain, "CNAME")
    records.mx = _query(domain, "MX")
    records.txt = _query(domain, "TXT")
    records.ns = _query(domain, "NS")
    records.dmarc_txt = _query(f"_dmarc.{domain}", "TXT")

    # Extended records — DNSSEC, CAA, mail-TLS policy
    records.caa = _query(domain, "CAA")
    records.dnskey = _query(domain, "DNSKEY")
    records.mta_sts_txt = _query(f"_mta-sts.{domain}", "TXT")
    records.tls_rpt_txt = _query(f"_smtp._tls.{domain}", "TXT")

    # DKIM: we don't know the selector, but we can probe the well-known
    # selectors used by major mail providers. Anything non-empty proves
    # at least one provider is configured.
    for selector in _COMMON_DKIM_SELECTORS:
        if _query(f"{selector}._domainkey.{domain}", "TXT"):
            records.dkim_selectors_seen.append(selector)

    if not records.has_a_or_aaaa and not records.cname:
        records.resolution_error = (
            f"No A, AAAA, or CNAME records found for '{domain}'"
        )

    return records


# Common DKIM selectors used by major mail providers. Probing every conceivable
# selector would take forever, so we restrict to a curated list. The order
# matters only for the "first match wins" early-exit in the test.
_COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "google",           # Google Workspace
    "selector1",        # Microsoft 365
    "selector2",        # Microsoft 365 (rotation)
    "mailo",            # Microsoft 365 (alternate)
    "default",          # generic
    "mail",             # generic
    "k1",               # MailChimp / Mandrill / various
    "k2",               # MailChimp rotation
    "s1",               # SendGrid
    "s2",               # SendGrid rotation
    "amazonses",        # SES
    "scph0124",         # CleverReach / SparkPost (date-based)
    "pm",               # Postmark
    "mta1", "mta2",     # Postmark / Mandrill
    "dkim",             # generic
    "fdkim1",           # Fastmail
)

# Subdomain-takeover candidate targets — CNAME tails that, if the underlying
# service was deprovisioned, an attacker could re-register. Each entry is a
# (domain_suffix, vendor_name) pair so we can name the risk in the finding.
_TAKEOVER_CANDIDATES: tuple[tuple[str, str], ...] = (
    (".herokudns.com",       "Heroku"),
    (".herokuapp.com",       "Heroku"),
    (".s3.amazonaws.com",    "AWS S3"),
    (".s3-website",          "AWS S3"),
    (".cloudfront.net",      "AWS CloudFront"),
    (".github.io",           "GitHub Pages"),
    (".azurewebsites.net",   "Azure App Service"),
    (".trafficmanager.net",  "Azure Traffic Manager"),
    (".cloudapp.azure.com",  "Azure Cloud Services"),
    (".pantheonsite.io",     "Pantheon"),
    (".myshopify.com",       "Shopify"),
    (".tumblr.com",          "Tumblr"),
    (".wordpress.com",       "WordPress.com"),
    (".surge.sh",             "Surge.sh"),
    (".netlify.app",         "Netlify"),
    (".netlify.com",         "Netlify"),
    (".vercel.app",          "Vercel"),
    (".readthedocs.io",      "Read the Docs"),
    (".helpjuice.com",       "Helpjuice"),
    (".helpscoutdocs.com",   "Help Scout Docs"),
    (".uservoice.com",       "UserVoice"),
    (".zendesk.com",         "Zendesk"),
    (".freshdesk.com",       "Freshdesk"),
    (".tictail.com",         "Tictail (defunct)"),
    (".campaignmonitor.com", "Campaign Monitor"),
    (".tilda.ws",            "Tilda"),
    (".strikinglydns.com",   "Strikingly"),
    (".webflow.io",          "Webflow"),
)


def _stdlib_resolve(domain: str, timeout: float) -> DnsRecords:
    """Minimal fallback using stdlib ``socket`` when dnspython is not installed."""
    socket.setdefaulttimeout(timeout)
    records = DnsRecords(domain=domain)
    try:
        results = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in results:
            addr = sockaddr[0]
            if ":" in addr:
                if addr not in records.aaaa:
                    records.aaaa.append(addr)
            else:
                if addr not in records.a:
                    records.a.append(addr)
    except socket.gaierror as exc:
        records.resolution_error = str(exc)
    return records


class DnsCheckerEngine:
    """Passive analysis of DNS records for security issues.

    Call ``analyze(records)`` with a pre-collected :class:`DnsRecords` object.
    Safe-mode: reads provided data only — no network calls inside the engine.
    """

    NAME = _ENGINE

    def analyze(self, records: DnsRecords) -> list[Finding]:
        url = f"https://{records.domain}"
        findings: list[Finding] = []

        findings.extend(self._check_resolution_failure(records, url))
        findings.extend(self._check_spf_missing(records, url))
        findings.extend(self._check_spf_risky(records, url))
        findings.extend(self._check_dmarc_missing(records, url))
        findings.extend(self._check_dkim_missing(records, url))
        findings.extend(self._check_mx_missing(records, url))
        findings.extend(self._check_ns_count(records, url))
        findings.extend(self._check_cname_chain(records, url))
        findings.extend(self._check_dnssec(records, url))
        findings.extend(self._check_caa(records, url))
        findings.extend(self._check_mta_sts(records, url))
        findings.extend(self._check_takeover_candidates(records, url))

        return findings

    # ------------------------------------------------------------------
    # DNS resolution failure
    # ------------------------------------------------------------------

    def _check_resolution_failure(
        self, records: DnsRecords, url: str
    ) -> list[Finding]:
        if not records.resolution_error:
            return []
        ev = _dns_ev("A/AAAA", records.resolution_error, url)
        return [_finding(
            title=f"DNS for {records.domain} doesn't resolve",
            description=(
                f"We can't find any IP addresses for '{records.domain}'. The domain "
                "isn't pointing anywhere — visitors typing the name into a browser "
                "won't reach your site at all.\n"
                f"Error: {records.resolution_error}"
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Check your DNS settings at your registrar / DNS provider. Your "
                "authoritative nameserver should return A (IPv4) or AAAA (IPv6) "
                "records for the domain. If you just changed DNS recently, allow "
                "up to 48 hours for propagation."
            ),
            framework=_FA["resolution_failure"],
        )]

    # ------------------------------------------------------------------
    # SPF checks
    # ------------------------------------------------------------------

    def _check_spf_missing(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.spf_records:
            return []
        # If the domain has no MX records, it can't receive email — and SPF on
        # a non-sending domain is genuinely optional. Downgrade severity and
        # confidence in that case.
        domain_sends_email = bool(records.mx)
        ev = _dns_ev("SPF", "No TXT record starting with 'v=spf1' found", url)
        return [_finding(
            title=f"No SPF record — anyone can forge email from {records.domain}",
            description=(
                "SPF (Sender Policy Framework) is a DNS record that tells the world "
                f"which servers are allowed to send email from '{records.domain}'. "
                "Without it, anyone can send mail that says it came from your domain — "
                "the basis of most phishing campaigns that impersonate brands."
            ),
            severity=Severity.MEDIUM if domain_sends_email else Severity.LOW,
            url=url,
            evidence=ev,
            confidence=0.95 if domain_sends_email else 0.7,
            remediation=(
                "Add an SPF TXT record at the domain root:\n"
                "  v=spf1 include:_spf.yourprovider.com -all\n"
                "Where `_spf.yourprovider.com` is your email provider's SPF include "
                "(Google: _spf.google.com, Microsoft 365: spf.protection.outlook.com, "
                "etc.). Use `-all` for strict reject, `~all` for soft-fail during rollout."
            ),
            framework=_FA["spf_missing"],
        )]

    def _check_spf_risky(self, records: DnsRecords, url: str) -> list[Finding]:
        findings: list[Finding] = []
        for spf in records.spf_records:
            if _SPF_PLUS_ALL.search(spf):
                ev = _dns_ev("SPF", spf, url)
                findings.append(_finding(
                    title="Your SPF record allows anyone to send mail as you",
                    description=(
                        f"The SPF record for '{records.domain}' ends with `+all`, which "
                        "tells mail servers to ACCEPT email claiming to be from your "
                        "domain no matter where it came from. This completely cancels "
                        "SPF's protection — anyone in the world can send phishing email "
                        "that appears to come from you."
                    ),
                    severity=Severity.HIGH,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "Replace `+all` with `-all` (strict reject). If you're worried "
                        "about breaking legitimate mail during the transition, use `~all` "
                        "(soft-fail) for a week while you watch DMARC reports, then "
                        "switch to `-all`. List every legitimate sending source (your "
                        "email provider's include, marketing platform, etc) before the "
                        "`all` term."
                    ),
                    framework=_FA["spf_plus_all"],
                ))
            elif _SPF_NEUTRAL_ALL.search(spf):
                ev = _dns_ev("SPF", spf, url)
                findings.append(_finding(
                    title="Your SPF record doesn't actually reject anything",
                    description=(
                        f"The SPF record for '{records.domain}' uses `?all` (neutral). "
                        "Receivers treat unlisted senders as neither pass nor fail — "
                        "which means spoofed mail mostly gets delivered anyway. SPF is "
                        "running but not protecting you."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "Change `?all` to `-all` (hard fail) or `~all` (soft-fail). "
                        "Make sure every legitimate sending source is listed before the "
                        "`all` term — Google Workspace, Microsoft 365, your transactional "
                        "email vendor (SendGrid, Postmark, Mailgun), etc."
                    ),
                    framework=_FA["spf_neutral"],
                ))
        return findings

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    def _check_dmarc_missing(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.has_dmarc:
            return []
        ev = _dns_ev(
            "DMARC",
            f"No DMARC TXT record found at _dmarc.{records.domain}",
            url,
        )
        return [_finding(
            title=f"No DMARC record — you can't tell when mail gets spoofed",
            description=(
                f"DMARC is the policy that tells receiving servers what to do with "
                f"email from '{records.domain}' that fails SPF or DKIM. Without it, "
                "those servers fall back to their own guess (usually 'accept anyway'), "
                "and you have no visibility into how often anyone tries to spoof your "
                "domain."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                f"Add a DMARC TXT record at `_dmarc.{records.domain}`. Start in "
                "monitoring mode for 2-4 weeks to see what's happening:\n"
                f"  v=DMARC1; p=none; rua=mailto:dmarc-reports@{records.domain}\n"
                "Once reports look clean, tighten to `p=quarantine` then `p=reject`."
            ),
            framework=_FA["dmarc_missing"],
        )]

    # ------------------------------------------------------------------
    # MX records
    # ------------------------------------------------------------------

    def _check_mx_missing(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.mx:
            return []
        if not records.spf_records:
            return []
        ev = _dns_ev(
            "MX",
            f"SPF record present but no MX records found for {records.domain}",
            url,
        )
        return [_finding(
            title=f"No MX records for {records.domain} despite SPF configuration",
            description=(
                f"The domain '{records.domain}' has an SPF record (indicating email "
                "is configured) but no MX records. Mail sent to this domain has no "
                "delivery target, indicating a likely DNS misconfiguration."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Add MX records if the domain should receive email. "
                "If not, publish a null MX record (RFC 7505): '0 .' "
                "to explicitly indicate no mail acceptance."
            ),
            framework=_FA["mx_missing_with_spf"],
        )]

    # ------------------------------------------------------------------
    # NS redundancy
    # ------------------------------------------------------------------

    def _check_ns_count(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or not records.ns or len(records.ns) >= 2:
            return []
        ns_list = ", ".join(records.ns)
        ev = _dns_ev(
            "NS",
            f"Only {len(records.ns)} NS record found: {ns_list}",
            url,
        )
        return [_finding(
            title=f"Single nameserver configured for {records.domain}",
            description=(
                f"Only one NS record was found for '{records.domain}' ({ns_list}). "
                "A single nameserver is a single point of failure: if it becomes "
                "unavailable, the domain cannot be resolved."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Configure at least two geographically diverse nameservers. "
                "RFC 1034 requires a minimum of two NS records."
            ),
            framework=_FA["ns_single"],
        )]

    # ------------------------------------------------------------------
    # DKIM (best-effort selector probing)
    # ------------------------------------------------------------------

    def _check_dkim_missing(self, records: DnsRecords, url: str) -> list[Finding]:
        # Only flag if the domain sends email (has MX records) AND we didn't
        # find DKIM at any of the common selectors. False negatives are
        # possible — the org might use a custom selector we don't probe.
        if records.resolution_error or not records.mx:
            return []
        if records.dkim_selectors_seen:
            return []
        ev = _dns_ev(
            "DKIM",
            f"No DKIM TXT record found at any of {len(_COMMON_DKIM_SELECTORS)} common selectors",
            url,
        )
        return [_finding(
            title=f"No DKIM signature found for {records.domain}",
            description=(
                "DKIM puts a cryptographic signature on every outgoing email so "
                "receiving servers can verify it really came from you. We checked the "
                "well-known selectors used by Google Workspace, Microsoft 365, SendGrid, "
                "and similar providers and didn't find any. Your mail may pass SPF but "
                "still get filtered as spam by stricter receivers, and a strict DMARC "
                "policy will reject it outright."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.65,  # we only probe common selectors
            remediation=(
                "Set up DKIM at your email provider:\n"
                "  - Google Workspace: Apps -> Google Workspace -> Gmail -> Authenticate email.\n"
                "  - Microsoft 365: Security -> Email & collaboration -> DKIM.\n"
                "  - SendGrid / Postmark / etc: their docs walk through CNAME setup.\n"
                "If you use a less-common selector and DKIM is actually configured, this "
                "finding is a false negative — let us know."
            ),
            framework=_FA["dkim_missing"],
        )]

    # ------------------------------------------------------------------
    # CNAME chain depth
    # ------------------------------------------------------------------

    def _check_cname_chain(self, records: DnsRecords, url: str) -> list[Finding]:
        # 2-hop chains are normal for SaaS (app.heroku.com -> ec2 -> ip). Only
        # fire at 3+ hops where it starts looking unusual.
        if len(records.cname) < 3:
            return []
        chain = " -> ".join(records.cname)
        ev = _dns_ev("CNAME", f"CNAME chain ({len(records.cname)} hops): {chain}", url)
        return [_finding(
            title=f"DNS lookup for {records.domain} goes through many redirects",
            description=(
                f"DNS resolution for '{records.domain}' walks through "
                f"{len(records.cname)} CNAME records before reaching an IP "
                f"({chain}). Long chains slow page loads and increase the risk of "
                "subdomain takeover — if any link in the chain is owned by a vendor "
                "you stopped using, an attacker can claim that name and intercept "
                "your traffic."
            ),
            severity=Severity.INFO,
            url=url,
            evidence=ev,
            confidence=0.6,
            remediation=(
                "Check each link in the chain. If any points at a SaaS / hosting "
                "vendor you no longer use, remove the orphan CNAME at your DNS "
                "provider. Where possible, flatten the chain to one or two hops."
            ),
            framework=_FA["cname_chain_long"],
        )]


    # ------------------------------------------------------------------
    # DNSSEC
    # ------------------------------------------------------------------

    def _check_dnssec(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.has_dnssec:
            return []
        ev = _dns_ev("DNSKEY", "No DNSKEY record found", url)
        return [_finding(
            title=f"DNSSEC isn't enabled for {records.domain}",
            description=(
                "DNSSEC cryptographically signs your DNS records so that resolvers can "
                "verify they haven't been tampered with in transit. Without it, attackers "
                "controlling any network between visitors and your DNS provider can "
                "redirect traffic by spoofing DNS responses — a class of attack called "
                "DNS cache poisoning."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            confidence=0.85,
            remediation=(
                "Most modern DNS providers (Cloudflare, Route 53, NS1, DNSimple) offer "
                "one-click DNSSEC. After enabling it at the provider, add the DS record "
                "they generate to your registrar so the chain of trust is complete. "
                "Verify with: dig +dnssec @8.8.8.8 yourdomain.com"
            ),
            framework=_FA["dnssec_missing"],
        )]

    # ------------------------------------------------------------------
    # CAA records
    # ------------------------------------------------------------------

    def _check_caa(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.caa:
            return []
        ev = _dns_ev("CAA", "No CAA record found", url)
        return [_finding(
            title=f"No CAA record — any CA can issue certificates for {records.domain}",
            description=(
                "A CAA (Certification Authority Authorization) record tells the world "
                "which certificate authorities are allowed to issue certificates for "
                "your domain. Without one, any CA on the planet can issue a cert for "
                "your name — including a compromised or malicious CA. CAA is a "
                "PCI DSS 4.0 requirement and standard practice for any production domain."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Publish a CAA record listing only the CA(s) you actually use. Examples:\n"
                "  yourdomain.com.  CAA  0 issue \"letsencrypt.org\"\n"
                "  yourdomain.com.  CAA  0 issuewild \";\"   # block wildcard issuance\n"
                "  yourdomain.com.  CAA  0 iodef \"mailto:security@yourdomain.com\"\n"
                "Cloudflare, Google Workspace, and most managed DNS providers expose "
                "this in the UI."
            ),
            framework=_FA["caa_missing"],
        )]

    # ------------------------------------------------------------------
    # MTA-STS / TLS-RPT
    # ------------------------------------------------------------------

    def _check_mta_sts(self, records: DnsRecords, url: str) -> list[Finding]:
        # Only relevant for domains that receive mail.
        if records.resolution_error or not records.mx:
            return []
        # Only flag if neither MTA-STS nor TLS-RPT is published.
        if records.has_mta_sts or records.has_tls_rpt:
            return []
        ev = _dns_ev(
            "MTA-STS",
            "No MTA-STS (_mta-sts.{domain}) or TLS-RPT (_smtp._tls.{domain}) records",
            url,
        )
        return [_finding(
            title=f"No mail-transport encryption policy ({records.domain})",
            description=(
                "MTA-STS tells other mail servers that they must use TLS when delivering "
                "to you, and TLS-RPT collects reports when TLS fails. Without either, "
                "mail to your domain can be downgraded to plain text by a network attacker "
                "between sender and your MX, and you'd never know."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            confidence=0.85,
            remediation=(
                f"Publish a TXT record at `_mta-sts.{records.domain}`:\n"
                "  v=STSv1; id=20260101\n"
                f"Host a policy file at https://mta-sts.{records.domain}/.well-known/mta-sts.txt:\n"
                f"  version: STSv1\n  mode: testing\n  mx: *.{records.domain}\n  max_age: 86400\n"
                f"And add a TLS-RPT record at `_smtp._tls.{records.domain}`:\n"
                f"  v=TLSRPTv1; rua=mailto:tlsrpt@{records.domain}\n"
                "Start with mode=testing for two weeks before switching to enforce."
            ),
            framework=_FA["mta_sts_missing"],
        )]

    # ------------------------------------------------------------------
    # Subdomain takeover candidates
    # ------------------------------------------------------------------

    def _check_takeover_candidates(self, records: DnsRecords, url: str) -> list[Finding]:
        # The classic dangling-CNAME pattern: CNAME points to a SaaS / hosting
        # service, but the service-side name doesn't exist anymore. Detection:
        # the resolver returned a CNAME chain that ends at one of our known
        # takeover-candidate suffixes, AND the final A/AAAA lookup failed
        # (resolution_error set).
        if not records.cname or not records.resolution_error:
            return []
        # Find the deepest CNAME target (last in chain).
        tail = records.cname[-1].rstrip(".")
        matched_vendor: str | None = None
        for suffix, vendor in _TAKEOVER_CANDIDATES:
            if tail.lower().endswith(suffix):
                matched_vendor = vendor
                break
        if matched_vendor is None:
            return []
        ev = _dns_ev(
            "CNAME",
            f"CNAME for {records.domain} points to {tail} but does not resolve",
            url,
        )
        return [_finding(
            title=f"Subdomain takeover risk: orphan CNAME to {matched_vendor}",
            description=(
                f"`{records.domain}` has a CNAME pointing at `{tail}`, which is on "
                f"{matched_vendor}'s service domain — but the name doesn't resolve "
                "anymore, meaning the underlying app / bucket / page was probably "
                f"deleted. An attacker can register the same name on {matched_vendor} "
                f"and immediately receive all traffic to `{records.domain}`, complete "
                "with valid TLS via the vendor's edge."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.85,
            remediation=(
                f"Either: re-provision the resource on {matched_vendor} so the CNAME "
                f"target exists again, OR delete the orphan CNAME at your DNS provider "
                f"if you no longer use {matched_vendor}. Treat this as urgent — these "
                "takeovers are typically claimed within hours by automated tooling."
            ),
            framework=_FA["takeover_candidate"],
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dns_ev(record_type: str, content: str, url: str) -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.DNS_RECORD,
        content=content,
        location=url,
        source_engine=_ENGINE,
        extra={"record_type": record_type},
    )


def _finding(
    title: str,
    description: str,
    severity: Severity,
    url: str,
    evidence: Evidence,
    remediation: str | None = None,
    framework: FrameworkAlignment | None = None,
    confidence: float = 1.0,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=FindingCategory.DNS,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=framework or FrameworkAlignment(),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
