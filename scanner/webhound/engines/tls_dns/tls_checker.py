# WebHound — scanner/webhound/engines/tls_dns/tls_checker.py
# Passive TLS certificate analysis.
#
# Safe-mode: read-only analysis only.
# probe_tls() performs a standard TLS handshake for certificate metadata collection.
# No exploitation, no bypass, no manipulation of certificates.

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "tls_checker"

_EXPIRY_CRITICAL_DAYS = 7
_EXPIRY_HIGH_DAYS = 14
_EXPIRY_MEDIUM_DAYS = 30

_WEAK_PROTOCOLS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"})


@dataclass
class TlsCertInfo:
    """Certificate metadata collected from a TLS handshake."""

    domain: str

    subject_cn: str | None = None
    sans: list[str] = field(default_factory=list)

    issuer_cn: str | None = None
    issuer_o: str | None = None

    not_before: datetime | None = None
    not_after: datetime | None = None

    protocol_version: str | None = None  # e.g. "TLSv1.3"

    is_self_signed: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    hostname_mismatch: bool = False

    connection_failed: bool = False
    error: str | None = None

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(timezone.utc)).days


def probe_tls(domain: str, port: int = 443, timeout: float = 10.0) -> TlsCertInfo:
    """Establish a TLS handshake to collect certificate metadata.

    Safe-mode: read-only, standard TLS handshake only.
    On certificate validation errors, falls back to a lenient context to
    collect what information is available without verifying the chain.
    """
    strict_ctx = ssl.create_default_context()
    ssl_error: str | None = None

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return _parse_cert_dict(domain, cert, ssock.version())
    except (ssl.SSLCertVerificationError, ssl.CertificateError) as exc:
        ssl_error = str(exc)
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as exc:
        return TlsCertInfo(domain=domain, error=str(exc), connection_failed=True)

    err_lower = ssl_error.lower()
    is_expired = "certificate has expired" in err_lower
    is_self_signed = "self signed" in err_lower or "self-signed" in err_lower
    hostname_mismatch = (
        "hostname" in err_lower
        or "doesn't match" in err_lower
        or "does not match" in err_lower
    )

    lenient_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    lenient_ctx.check_hostname = False
    lenient_ctx.verify_mode = ssl.CERT_NONE
    protocol_version: str | None = None
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with lenient_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol_version = ssock.version()
    except Exception:
        pass

    return TlsCertInfo(
        domain=domain,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
        hostname_mismatch=hostname_mismatch,
        protocol_version=protocol_version,
        error=ssl_error,
    )


class TlsCheckerEngine:
    """Passive analysis of TLS certificate metadata for security issues.

    Call ``analyze(cert_info)`` to receive a list of findings.
    Safe-mode: reads pre-collected certificate data only — no active probing.
    """

    NAME = _ENGINE

    def analyze(
        self,
        cert_info: TlsCertInfo,
        *,
        response_url: str | None = None,
        redirect_chain: list[str] | None = None,
    ) -> list[Finding]:
        url = f"https://{cert_info.domain}"
        findings: list[Finding] = []

        findings.extend(self._check_connection_failed(cert_info, url))
        findings.extend(self._check_expired(cert_info, url))
        findings.extend(self._check_not_yet_valid(cert_info, url))
        findings.extend(self._check_expiry_warning(cert_info, url))
        findings.extend(self._check_self_signed(cert_info, url))
        findings.extend(self._check_hostname_mismatch(cert_info, url))
        findings.extend(self._check_weak_protocol(cert_info, url))
        findings.extend(
            self._check_https_redirect(cert_info, response_url, redirect_chain)
        )

        return findings

    # ------------------------------------------------------------------
    # Connection failure
    # ------------------------------------------------------------------

    def _check_connection_failed(
        self, cert_info: TlsCertInfo, url: str
    ) -> list[Finding]:
        if not cert_info.connection_failed:
            return []
        ev = _cert_ev(cert_info, url, f"Connection error: {cert_info.error}")
        return [_finding(
            title=f"We couldn't reach {cert_info.domain} over HTTPS",
            description=(
                f"We tried to open an HTTPS connection to '{cert_info.domain}' and the "
                "connection failed. This can mean the site doesn't run HTTPS at all, the "
                "server is temporarily down, or a firewall is blocking us. It can also "
                f"just be a transient network glitch.\nError: {cert_info.error}"
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.7,  # could be transient
            remediation=(
                "Verify the server accepts TLS connections on port 443 and is reachable "
                "from the internet. If this is intermittent, the issue is likely outside "
                "WebHound — check your CDN, load balancer, or origin firewall."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-319"],
                nist_controls=["SC-8"],
            ),
        )]

    # ------------------------------------------------------------------
    # Certificate expiry
    # ------------------------------------------------------------------

    def _check_expired(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        if not cert_info.is_expired:
            return []
        detail = (
            f" (expired {cert_info.not_after.date()})" if cert_info.not_after else ""
        )
        ev = _cert_ev(cert_info, url, f"Certificate expired{detail}")
        return [_finding(
            title=f"Your SSL certificate has already expired",
            description=(
                f"The certificate for '{cert_info.domain}' expired{detail}. Every visitor "
                "now sees a giant red warning page from their browser saying the site is "
                "unsafe. Most leave immediately. This is a site-down emergency."
            ),
            severity=Severity.CRITICAL,
            url=url,
            evidence=ev,
            remediation=(
                "Renew the certificate right now. Long-term: set up automated renewal — "
                "Let's Encrypt (free) or your hosting provider's auto-renew feature both "
                "prevent this from recurring. The Certbot tool can handle most setups."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-298"],
                nist_controls=["SC-8", "SC-17"],
            ),
        )]

    def _check_not_yet_valid(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        if not cert_info.is_not_yet_valid:
            return []
        detail = (
            f" (starts {cert_info.not_before.date()})"
            if cert_info.not_before
            else ""
        )
        ev = _cert_ev(cert_info, url, f"Certificate not yet valid{detail}")
        return [_finding(
            title=f"Your certificate's start date is in the future",
            description=(
                f"The certificate says it doesn't start being valid until "
                f"{detail.replace('(starts ', '').replace(')', '')}. Browsers reject "
                "certificates dated in the future. Almost always this is a server-clock "
                "drift issue rather than an actual problem with the certificate."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Check that the server's clock is correct (NTP sync). If the clock is "
                "fine, the certificate was issued with a wrong notBefore date and needs "
                "to be reissued."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-298"],
                nist_controls=["SC-8", "SC-17"],
            ),
        )]

    def _check_expiry_warning(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        days = cert_info.days_until_expiry
        if days is None or days < 0:
            return []

        if days <= _EXPIRY_CRITICAL_DAYS:
            sev = Severity.CRITICAL
        elif days <= _EXPIRY_HIGH_DAYS:
            sev = Severity.HIGH
        elif days <= _EXPIRY_MEDIUM_DAYS:
            sev = Severity.MEDIUM
        else:
            return []

        label = f"{days} day{'s' if days != 1 else ''}"
        expiry_str = (
            str(cert_info.not_after.date()) if cert_info.not_after else "unknown"
        )
        ev = _cert_ev(
            cert_info,
            url,
            f"Certificate expires in {label} ({expiry_str})",
        )
        return [_finding(
            title=f"SSL certificate expires in {label}",
            description=(
                f"Your certificate for '{cert_info.domain}' expires on {expiry_str} — "
                f"{label} from now. When it expires, browsers will show a red warning to "
                "every visitor and most will leave. Set up automatic renewal so this can't "
                "happen by accident."
            ),
            severity=sev,
            url=url,
            evidence=ev,
            remediation=(
                "Renew the certificate before the expiry date. Set up automated renewal:\n"
                "  - Let's Encrypt + Certbot — free, the standard for self-hosted.\n"
                "  - Cloudflare / Vercel / Netlify — handle renewal automatically.\n"
                "  - Commercial CA (DigiCert, Sectigo) — usually has an auto-renew option.\n"
                "Alert internally at least 14 days before expiry."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-298"],
                nist_controls=["SC-8", "SC-17"],
            ),
        )]

    # ------------------------------------------------------------------
    # Self-signed certificate
    # ------------------------------------------------------------------

    def _check_self_signed(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        if not cert_info.is_self_signed:
            return []
        issuer_label = cert_info.issuer_cn or cert_info.issuer_o or "unknown"
        ev = _cert_ev(
            cert_info, url, f"Self-signed certificate: issuer='{issuer_label}'"
        )
        return [_finding(
            title=f"Your certificate isn't signed by a trusted authority",
            description=(
                f"The certificate for '{cert_info.domain}' is self-signed — the same "
                "entity issued it and signed it. Browsers don't trust it. Every visitor "
                "sees a giant red warning and most leave. Free, browser-trusted "
                "certificates are available from Let's Encrypt."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.85,  # self-signed detection from error parsing is solid
            remediation=(
                "Get a real certificate from a trusted certificate authority. Free "
                "options: Let's Encrypt (via Certbot), Cloudflare's edge certs, or "
                "your hosting provider's built-in TLS."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-295"],
                nist_controls=["SC-8", "SC-17"],
            ),
        )]

    # ------------------------------------------------------------------
    # Hostname mismatch
    # ------------------------------------------------------------------

    def _check_hostname_mismatch(
        self, cert_info: TlsCertInfo, url: str
    ) -> list[Finding]:
        if not cert_info.hostname_mismatch:
            return []
        cn_label = cert_info.subject_cn or "unknown"
        ev = _cert_ev(
            cert_info,
            url,
            f"Hostname '{cert_info.domain}' not in certificate CN or SANs (CN='{cn_label}')",
        )
        return [_finding(
            title=f"Your certificate isn't valid for this domain",
            description=(
                f"The certificate served on '{cert_info.domain}' was issued for a "
                f"different name (it says '{cn_label}'). Browsers will refuse the "
                "connection. This often happens when a www subdomain serves a cert "
                "issued only for the apex domain, or vice versa."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.85,
            remediation=(
                "Get a new certificate that includes every domain you serve. With "
                "Let's Encrypt or most CAs, you list each hostname in the Subject "
                "Alternative Name (SAN) field — both `example.com` and `www.example.com`, "
                "or a wildcard like `*.example.com`."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-297"],
                nist_controls=["SC-8", "SC-17"],
            ),
        )]

    # ------------------------------------------------------------------
    # Weak protocol version
    # ------------------------------------------------------------------

    def _check_weak_protocol(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        if not cert_info.protocol_version:
            return []
        if cert_info.protocol_version.upper() not in _WEAK_PROTOCOLS:
            return []
        ev = _cert_ev(
            cert_info, url, f"Protocol version: {cert_info.protocol_version}"
        )
        return [_finding(
            title=f"Server is still negotiating an obsolete TLS version ({cert_info.protocol_version})",
            description=(
                f"Your server agreed to communicate using {cert_info.protocol_version}. "
                "This version has known cryptographic weaknesses with public attacks "
                "(POODLE, BEAST, CRIME). Modern browsers refuse to load sites that "
                "negotiate this version, so visitors using up-to-date Chrome / Firefox / "
                "Safari may see an error instead of your site."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Disable TLS 1.0 and TLS 1.1 on your server. Support only TLS 1.2 and "
                "TLS 1.3. Configuration examples:\n"
                "  nginx:  ssl_protocols TLSv1.2 TLSv1.3;\n"
                "  Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                "  Cloudflare: Settings -> SSL/TLS -> Edge Certificates -> Minimum TLS Version"
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-326"],
                nist_controls=["SC-8"],
            ),
        )]

    # ------------------------------------------------------------------
    # HTTP → HTTPS redirect
    # ------------------------------------------------------------------

    def _check_https_redirect(
        self,
        cert_info: TlsCertInfo,
        response_url: str | None,
        redirect_chain: list[str] | None,
    ) -> list[Finding]:
        if not redirect_chain or not response_url:
            return []
        first_url = redirect_chain[0]
        if not first_url.startswith("http://"):
            return []
        if response_url.startswith("https://"):
            return []
        url = f"https://{cert_info.domain}"
        ev = Evidence(
            evidence_type=EvidenceType.REDIRECT,
            content=(
                f"HTTP request to '{first_url}' did not redirect to HTTPS. "
                f"Final URL: '{response_url}'"
            ),
            location=first_url,
            source_engine=_ENGINE,
        )
        return [_finding(
            title=f"Your site serves HTTP without redirecting to HTTPS",
            description=(
                f"A visitor who types '{first_url}' (or follows an old link) is served "
                "over plain HTTP and never sent to the HTTPS version. Their entire "
                "session — including any login form they submit on that page — can be "
                "read or modified by anyone on the same network (open WiFi, ISPs, etc)."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                "Configure your server (or CDN) to issue a 301 redirect from every HTTP "
                "URL to its HTTPS equivalent, then add a Strict-Transport-Security "
                "header on the HTTPS side so browsers refuse the HTTP version after the "
                "first visit."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A02:2021"],
                cwe_ids=["CWE-319"],
                nist_controls=["SC-8"],
            ),
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cert_ev(cert_info: TlsCertInfo, url: str, detail: str) -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.TLS_CERTIFICATE,
        content=detail,
        location=url,
        source_engine=_ENGINE,
        extra={
            "domain": cert_info.domain,
            "subject_cn": cert_info.subject_cn,
            "issuer_o": cert_info.issuer_o,
            "not_after": (
                cert_info.not_after.isoformat() if cert_info.not_after else None
            ),
            "protocol_version": cert_info.protocol_version,
        },
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
        category=FindingCategory.TLS,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=framework or FrameworkAlignment(),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )


def _parse_cert_dict(domain: str, cert: dict, version: str | None) -> TlsCertInfo:
    """Parse a getpeercert() dict into TlsCertInfo.

    Reached only after the *strict* TLS context has succeeded — so the chain
    validated, the host matched, and the cert is in date. We therefore do NOT
    re-derive is_expired / is_self_signed / hostname_mismatch from the parsed
    fields here; setting them would be dead code that contradicts the strict-
    success precondition.
    """
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))

    subject_cn: str | None = subject.get("commonName")
    issuer_cn: str | None = issuer.get("commonName")
    issuer_o: str | None = issuer.get("organizationName")

    sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]

    not_before: datetime | None = None
    not_after: datetime | None = None
    if nb := cert.get("notBefore"):
        not_before = datetime.strptime(nb.strip(), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    if na := cert.get("notAfter"):
        not_after = datetime.strptime(na.strip(), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )

    return TlsCertInfo(
        domain=domain,
        subject_cn=subject_cn,
        sans=sans,
        issuer_cn=issuer_cn,
        issuer_o=issuer_o,
        not_before=not_before,
        not_after=not_after,
        # Strict context succeeded — these are all False by definition. Leaving
        # the defaults (False) on TlsCertInfo so we don't accidentally re-derive
        # them from the parsed CN / DN with a fragile heuristic.
        protocol_version=version,
    )


def _hostname_matches(domain: str, cn: str | None, sans: list[str]) -> bool:
    """True if domain is covered by any SAN or the CN."""
    candidates = [*sans]
    if cn:
        candidates.append(cn)
    if not candidates:
        return False
    domain_lower = domain.lower()
    for candidate in candidates:
        c = candidate.lower()
        if c == domain_lower:
            return True
        if c.startswith("*."):
            bare = c[2:]
            if domain_lower.endswith(f".{bare}"):
                return True
    return False
