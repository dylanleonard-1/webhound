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
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "dns_checker"

_SPF_PLUS_ALL = re.compile(r"\+all\b", re.I)
_SPF_NEUTRAL_ALL = re.compile(r"\?all\b", re.I)


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


def resolve_dns(domain: str, timeout: float = 5.0) -> DnsRecords:
    """Resolve DNS records for *domain*.

    Safe-mode: issues standard read-only queries (A, AAAA, CNAME, MX, TXT, NS).
    Requires ``dnspython``; falls back to stdlib socket for A/AAAA only.
    """
    try:
        import dns.exception as _dnsexc
        import dns.resolver as _resolver
    except ImportError:
        return _stdlib_resolve(domain, timeout)

    records = DnsRecords(domain=domain)
    resolver = _resolver.Resolver()
    resolver.lifetime = timeout

    def _query(qname: str, qtype: str) -> list[str]:
        try:
            return [str(r) for r in resolver.resolve(qname, qtype)]
        except (_dnsexc.NXDOMAIN, _dnsexc.NoAnswer, _dnsexc.NoNameservers):
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

    if not records.has_a_or_aaaa and not records.cname:
        records.resolution_error = (
            f"No A, AAAA, or CNAME records found for '{domain}'"
        )

    return records


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
        findings.extend(self._check_mx_missing(records, url))
        findings.extend(self._check_ns_count(records, url))
        findings.extend(self._check_cname_chain(records, url))

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
            title=f"DNS resolution failed for {records.domain}",
            description=(
                f"DNS resolution returned no usable records for '{records.domain}': "
                f"{records.resolution_error}. "
                "The domain may not exist, be misconfigured, or have been removed."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Verify the domain's DNS configuration. Ensure A/AAAA records are "
                "published by the authoritative nameserver."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-350"],
                nist_controls=["SC-20"],
            ),
        )]

    # ------------------------------------------------------------------
    # SPF checks
    # ------------------------------------------------------------------

    def _check_spf_missing(self, records: DnsRecords, url: str) -> list[Finding]:
        if records.resolution_error or records.spf_records:
            return []
        ev = _dns_ev("SPF", "No TXT record starting with 'v=spf1' found", url)
        return [_finding(
            title=f"SPF record missing for {records.domain}",
            description=(
                f"No SPF (Sender Policy Framework) TXT record was found for "
                f"'{records.domain}'. Without SPF, attackers can forge email from "
                "this domain, enabling phishing and spam campaigns."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                "Add an SPF TXT record. Example: "
                "v=spf1 include:_spf.yourdomain.com -all"
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-290"],
                nist_controls=["SC-20", "SI-8"],
            ),
        )]

    def _check_spf_risky(self, records: DnsRecords, url: str) -> list[Finding]:
        findings: list[Finding] = []
        for spf in records.spf_records:
            if _SPF_PLUS_ALL.search(spf):
                ev = _dns_ev("SPF", spf, url)
                findings.append(_finding(
                    title=f"SPF record uses '+all' (pass all) for {records.domain}",
                    description=(
                        f"The SPF record '{spf}' ends with '+all', which instructs "
                        "receiving mail servers to accept email from ANY sender "
                        "on behalf of this domain. This completely negates SPF "
                        "protection and trivially enables email spoofing."
                    ),
                    severity=Severity.HIGH,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "Change '+all' to '-all' to reject all unauthorised senders, "
                        "or '~all' (softfail) as an intermediate step. "
                        "List all legitimate sending IPs/includes before 'all'."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-290"],
                        nist_controls=["SC-20", "SI-8"],
                    ),
                ))
            elif _SPF_NEUTRAL_ALL.search(spf):
                ev = _dns_ev("SPF", spf, url)
                findings.append(_finding(
                    title=f"SPF record uses '?all' (neutral) for {records.domain}",
                    description=(
                        f"The SPF record '{spf}' uses '?all' (neutral), which does "
                        "not prevent unauthorised senders. Mail from unlisted senders "
                        "is treated as neither pass nor fail."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "Change '?all' to '-all' (hard fail) or '~all' (softfail). "
                        "Enumerate all legitimate sending sources first."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A05:2021"],
                        cwe_ids=["CWE-290"],
                        nist_controls=["SC-20", "SI-8"],
                    ),
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
            title=f"DMARC record missing for {records.domain}",
            description=(
                f"No DMARC record was found at '_dmarc.{records.domain}'. "
                "Without DMARC, there is no policy to reject or quarantine spoofed "
                "email and no visibility into abuse of the domain."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                "Add a DMARC TXT record at _dmarc.{domain}. Start with monitoring: "
                "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com. "
                "Progressively tighten to p=quarantine then p=reject."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-290"],
                nist_controls=["SC-20", "SI-8"],
            ),
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
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-350"],
                nist_controls=["SC-20"],
            ),
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
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-350"],
                nist_controls=["SC-20"],
            ),
        )]

    # ------------------------------------------------------------------
    # CNAME chain depth
    # ------------------------------------------------------------------

    def _check_cname_chain(self, records: DnsRecords, url: str) -> list[Finding]:
        if len(records.cname) <= 1:
            return []
        chain = " -> ".join(records.cname)
        ev = _dns_ev("CNAME", f"CNAME chain ({len(records.cname)} hops): {chain}", url)
        return [_finding(
            title=f"Long CNAME chain for {records.domain}",
            description=(
                f"The domain '{records.domain}' resolves through "
                f"{len(records.cname)} CNAME records ({chain}). "
                "Long chains increase DNS lookup latency and may indicate subdomain "
                "takeover risk if any intermediate target becomes unregistered."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Flatten the CNAME chain where possible. Verify all intermediate "
                "targets are actively maintained to prevent subdomain takeover."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-350"],
                nist_controls=["SC-20"],
            ),
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
