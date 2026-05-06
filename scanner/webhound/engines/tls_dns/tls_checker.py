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
            title=f"TLS connection failed for {cert_info.domain}",
            description=(
                f"Unable to establish a TLS connection to '{cert_info.domain}'. "
                "The site may not support HTTPS, or the port may be unreachable. "
                f"Error: {cert_info.error}"
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Ensure the server is configured to accept TLS connections on port 443. "
                "Verify the host is reachable and the firewall permits port 443."
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
            title=f"TLS certificate expired for {cert_info.domain}",
            description=(
                f"The TLS certificate for '{cert_info.domain}' has expired{detail}. "
                "Browsers display a security warning and refuse the connection. "
                "The site is effectively unavailable over HTTPS."
            ),
            severity=Severity.CRITICAL,
            url=url,
            evidence=ev,
            remediation=(
                "Renew the TLS certificate immediately. "
                "Consider automated renewal via Let's Encrypt / ACME protocol."
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
            f" (valid from {cert_info.not_before.date()})"
            if cert_info.not_before
            else ""
        )
        ev = _cert_ev(cert_info, url, f"Certificate not yet valid{detail}")
        return [_finding(
            title=f"TLS certificate is not yet valid for {cert_info.domain}",
            description=(
                f"The TLS certificate for '{cert_info.domain}' has a notBefore date "
                f"in the future{detail}. Browsers will reject this certificate."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Verify the server clock is accurate (NTP sync). "
                "Reissue the certificate with a correct notBefore date."
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
            title=f"TLS certificate expiring soon: {label} remaining",
            description=(
                f"The TLS certificate for '{cert_info.domain}' expires in {label} "
                f"(on {expiry_str}). Failure to renew before expiry will cause browser "
                "security warnings and interrupt HTTPS connections."
            ),
            severity=sev,
            url=url,
            evidence=ev,
            remediation=(
                "Renew the certificate before it expires. "
                "Set up automated renewal (Let's Encrypt / ACME) to prevent recurrence."
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
            title=f"Self-signed TLS certificate for {cert_info.domain}",
            description=(
                f"The TLS certificate for '{cert_info.domain}' is self-signed and "
                "not issued by a trusted Certificate Authority. Browsers display a "
                "security warning and users cannot verify the server's identity."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Replace the self-signed certificate with one from a trusted CA. "
                "Free certificates are available via Let's Encrypt."
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
            title=f"TLS certificate hostname mismatch for {cert_info.domain}",
            description=(
                f"The TLS certificate does not cover the hostname '{cert_info.domain}'. "
                f"Certificate CN: '{cn_label}'. "
                "This prevents server identity verification and allows "
                "man-in-the-middle attacks."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Obtain a certificate that lists the correct domain in the Subject "
                "Alternative Names (SAN) field."
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
            title=f"Weak TLS protocol version: {cert_info.protocol_version}",
            description=(
                f"The connection negotiated {cert_info.protocol_version}, which is "
                "deprecated and has known cryptographic weaknesses (POODLE, BEAST, "
                "CRIME). TLS 1.2 is the minimum acceptable; TLS 1.3 is recommended."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Disable TLS 1.0 and 1.1 server-side. Configure the server to support "
                "only TLS 1.2 and TLS 1.3."
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
            title=f"HTTP does not redirect to HTTPS for {cert_info.domain}",
            description=(
                f"An HTTP request to '{first_url}' was not redirected to HTTPS. "
                "Users accessing the site over HTTP communicate without encryption. "
                "Combined with missing HSTS, this enables downgrade attacks."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                "Configure the server to issue a 301 redirect from all HTTP URLs to "
                "their HTTPS equivalent. Also add Strict-Transport-Security (HSTS)."
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
    """Parse a getpeercert() dict into TlsCertInfo."""
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

    now = datetime.now(timezone.utc)
    is_expired = not_after is not None and not_after < now
    is_not_yet_valid = not_before is not None and not_before > now
    is_self_signed = bool(
        subject_cn and issuer_cn and subject_cn == issuer_cn and not issuer_o
    )
    hostname_mismatch = not _hostname_matches(domain, subject_cn, sans)

    return TlsCertInfo(
        domain=domain,
        subject_cn=subject_cn,
        sans=sans,
        issuer_cn=issuer_cn,
        issuer_o=issuer_o,
        not_before=not_before,
        not_after=not_after,
        is_expired=is_expired,
        is_not_yet_valid=is_not_yet_valid,
        is_self_signed=is_self_signed,
        hostname_mismatch=hostname_mismatch,
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
