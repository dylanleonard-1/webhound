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
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "tls_checker"

_EXPIRY_CRITICAL_DAYS = 7
_EXPIRY_HIGH_DAYS = 14
_EXPIRY_MEDIUM_DAYS = 30

_WEAK_PROTOCOLS = frozenset({"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"})

# Enterprise metadata per finding kind. See engines/headers/security_headers.py
# for the calibration approach. TLS findings cluster around A02:2021
# (Cryptographic Failures) and map to PCI DSS 4.0 §4 (encryption in transit),
# ISO/IEC 27001:2022 A.8.24 (cryptography), and SOC 2 CC6.7 (encryption).
_FA: dict[str, FrameworkAlignment] = {
    "connection_failed": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", cvss_score=3.1,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.UNKNOWN,
    ),
    "cert_expired": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-298"], nist_controls=["SC-8", "SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", cvss_score=8.6,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"], hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "cert_not_yet_valid": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-298"], nist_controls=["SC-8", "SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "cert_expiring_soon": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-298"], nist_controls=["SC-8", "SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H", cvss_score=6.5,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "cert_self_signed": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-295"], nist_controls=["SC-8", "SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "cert_hostname_mismatch": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-297"], nist_controls=["SC-8", "SC-17"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "weak_protocol": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-326", "CWE-327"], nist_controls=["SC-8", "SC-13"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "legacy_protocol_supported": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-326", "CWE-327"], nist_controls=["SC-8", "SC-13"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "weak_key": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-326"], nist_controls=["SC-13"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", cvss_score=7.4,
        pci_dss=["4.2.1.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "weak_signature": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-327", "CWE-328"], nist_controls=["SC-13"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=7.1,
        pci_dss=["4.2.1.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "http_no_redirect": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=5.9,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
}


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
    cipher_suite: str | None = None      # negotiated cipher (e.g. "TLS_AES_256_GCM_SHA384")

    # Public key info
    key_type: str | None = None    # e.g. "rsa", "ec"
    key_bits: int | None = None    # e.g. 2048, 256

    # Signature algorithm on the leaf certificate
    signature_algorithm: str | None = None  # e.g. "sha256WithRSAEncryption"

    # Supported-protocol enumeration: which legacy versions does the server
    # *still accept*, separate from the one we negotiated?
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False

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

    Also probes whether the server still accepts TLS 1.0 / 1.1 — important
    even when the negotiated version is modern, because servers often retain
    backward-compatible legacy protocols that browsers and pen-test tools
    will silently downgrade to.
    """
    strict_ctx = ssl.create_default_context()
    ssl_error: str | None = None
    info: TlsCertInfo | None = None

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info = _parse_cert_dict(domain, cert, ssock.version())
                # Cipher: getcipher() returns (cipher_name, protocol, secret_bits)
                cipher = ssock.cipher()
                if cipher:
                    info.cipher_suite = cipher[0]
                # Public key + signature algorithm from the binary DER form.
                der = ssock.getpeercert(True)
                if der:
                    _fill_key_and_sig(info, der)
    except (ssl.SSLCertVerificationError, ssl.CertificateError) as exc:
        ssl_error = str(exc)
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as exc:
        return TlsCertInfo(domain=domain, error=str(exc), connection_failed=True)

    if info is None:
        # Strict context failed — parse what we can from the error string and
        # do a lenient handshake just to learn the protocol version.
        err_lower = (ssl_error or "").lower()
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
        info = TlsCertInfo(
            domain=domain,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            hostname_mismatch=hostname_mismatch,
            protocol_version=protocol_version,
            error=ssl_error,
        )

    # Legacy protocol enumeration — separate handshakes, short timeout each.
    # We only probe if the strict path got a usable handshake; otherwise the
    # earlier failure tells us more than the legacy probe would.
    if not info.connection_failed:
        info.supports_tls_1_0 = _probe_protocol_supported(domain, port, ssl.TLSVersion.TLSv1,   timeout=3.0)
        info.supports_tls_1_1 = _probe_protocol_supported(domain, port, ssl.TLSVersion.TLSv1_1, timeout=3.0)

    return info


def _probe_protocol_supported(
    domain: str, port: int, version: ssl.TLSVersion, *, timeout: float
) -> bool:
    """Returns True if the server completes a handshake with *exactly* version.

    Best-effort — older OpenSSL builds and Python interpreters compiled
    against post-3.0 OpenSSL will refuse to even initiate TLS 1.0 / 1.1
    handshakes on the client side, in which case we return False (we can't
    prove the server supports it, so we don't flag it).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def _fill_key_and_sig(info: "TlsCertInfo", der_bytes: bytes) -> None:
    """Populate key_type / key_bits / signature_algorithm from a DER cert.

    Uses `cryptography` if available; silently skips if it isn't.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        cert = x509.load_der_x509_certificate(der_bytes)
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            info.key_type = "rsa"
            info.key_bits = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            info.key_type = "ec"
            info.key_bits = pubkey.curve.key_size
        else:
            info.key_type = type(pubkey).__name__
            info.key_bits = getattr(pubkey, "key_size", None)
        # signature_algorithm_oid._name is the human-readable name on
        # modern cryptography releases.
        sig = cert.signature_algorithm_oid
        info.signature_algorithm = getattr(sig, "_name", None) or sig.dotted_string
    except Exception:
        # cryptography missing or DER unparseable — leave fields as None.
        pass


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
        findings.extend(self._check_legacy_protocol_supported(cert_info, url))
        findings.extend(self._check_weak_key(cert_info, url))
        findings.extend(self._check_weak_signature(cert_info, url))
        # OCSP stapling detection is gated until we can reliably detect it
        # from the handshake — see _check_ocsp_stapling for the limitation.
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
            framework=_FA["connection_failed"],
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
            framework=_FA["cert_expired"],
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
            framework=_FA["cert_not_yet_valid"],
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
            framework=_FA["cert_expiring_soon"],
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
            framework=_FA["cert_self_signed"],
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
            framework=_FA["cert_hostname_mismatch"],
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
            framework=_FA["weak_protocol"],
        )]

    # ------------------------------------------------------------------
    # Legacy protocol enumeration (server still ACCEPTS TLS 1.0 / 1.1)
    # ------------------------------------------------------------------

    def _check_legacy_protocol_supported(
        self, cert_info: TlsCertInfo, url: str
    ) -> list[Finding]:
        supported_legacy: list[str] = []
        if cert_info.supports_tls_1_0:
            supported_legacy.append("TLS 1.0")
        if cert_info.supports_tls_1_1:
            supported_legacy.append("TLS 1.1")
        if not supported_legacy:
            return []
        # Don't double-fire when the negotiated version is also legacy —
        # _check_weak_protocol already handled that.
        if cert_info.protocol_version and cert_info.protocol_version.upper() in _WEAK_PROTOCOLS:
            return []
        ev = _cert_ev(
            cert_info, url,
            f"Negotiated {cert_info.protocol_version} but server also accepts {', '.join(supported_legacy)}",
        )
        return [_finding(
            title=f"Server still accepts obsolete TLS versions ({', '.join(supported_legacy)})",
            description=(
                f"When we connected normally, your server picked a modern version "
                f"({cert_info.protocol_version}). But when we asked specifically for "
                f"{', '.join(supported_legacy)}, the server agreed. Attackers can force "
                "vulnerable clients to negotiate the weaker version, exposing them to "
                "known attacks (POODLE, BEAST). PCI DSS 4.0 requires TLS 1.2+."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Disable TLS 1.0 and TLS 1.1 on the server. Examples:\n"
                "  nginx:    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "  Apache:   SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                "  Cloudflare: Settings -> SSL/TLS -> Edge Certificates -> Minimum TLS Version = 1.2\n"
                "  AWS ALB: change the security policy to one that drops 1.0/1.1."
            ),
            framework=_FA["legacy_protocol_supported"],
        )]

    # ------------------------------------------------------------------
    # Weak public-key strength
    # ------------------------------------------------------------------

    def _check_weak_key(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        if not cert_info.key_type or not cert_info.key_bits:
            return []
        # NIST SP 800-57 / Mozilla guidance: RSA <2048 weak, EC <256 weak.
        weak = False
        if cert_info.key_type == "rsa" and cert_info.key_bits < 2048:
            weak = True
        elif cert_info.key_type == "ec" and cert_info.key_bits < 256:
            weak = True
        if not weak:
            return []
        ev = _cert_ev(
            cert_info, url,
            f"Public key: {cert_info.key_type.upper()} {cert_info.key_bits}-bit",
        )
        return [_finding(
            title=f"TLS certificate uses a weak {cert_info.key_type.upper()} key ({cert_info.key_bits}-bit)",
            description=(
                f"Your certificate's public key is {cert_info.key_bits}-bit "
                f"{cert_info.key_type.upper()}, below the modern minimum "
                f"({'2048 for RSA' if cert_info.key_type == 'rsa' else '256 for elliptic curves'}). "
                "Government and industry guidance (NIST SP 800-57, Mozilla, PCI DSS) "
                "consider keys this size weak against a well-resourced attacker."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Reissue the certificate with a stronger key. Recommended modern values:\n"
                "  - RSA: 2048-bit minimum, 3072-bit for new keys, 4096-bit for long-lived.\n"
                "  - EC:  P-256 (256-bit) or P-384 (384-bit).\n"
                "If you control the CSR, regenerate the private key with the new size and "
                "submit a new CSR to your CA."
            ),
            framework=_FA["weak_key"],
        )]

    # ------------------------------------------------------------------
    # Weak signature algorithm
    # ------------------------------------------------------------------

    def _check_weak_signature(self, cert_info: TlsCertInfo, url: str) -> list[Finding]:
        sig = (cert_info.signature_algorithm or "").lower()
        if not sig:
            return []
        # SHA-1 signed certs have been distrusted since 2017 but still appear
        # in internal / self-managed PKI.
        is_weak = ("sha1" in sig and "rsa" in sig) or sig.startswith("md5") or "md2" in sig
        if not is_weak:
            return []
        ev = _cert_ev(
            cert_info, url, f"Signature algorithm: {cert_info.signature_algorithm}"
        )
        return [_finding(
            title="TLS certificate uses a broken signature algorithm",
            description=(
                f"Your certificate was signed with `{cert_info.signature_algorithm}`. "
                "SHA-1 and MD5 are cryptographically broken — collisions can be generated, "
                "making it possible to forge a certificate that browsers would trust. "
                "Major browsers have distrusted SHA-1 certs since 2017 (and MD5 since "
                "2008), so users may already see warnings."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Reissue the certificate with SHA-256 (or stronger) signing. Modern "
                "CAs and ACME automation already use SHA-256 by default. If you run a "
                "private CA, update the CA configuration before reissuing leaf certs."
            ),
            framework=_FA["weak_signature"],
        )]

    # ------------------------------------------------------------------
    # OCSP stapling (disabled — see note)
    # ------------------------------------------------------------------
    # Python's stdlib `ssl` module doesn't expose whether the handshake
    # carried a stapled OCSP response. Until we add a reliable detection
    # path (cryptography.x509.ocsp parsing of the TLS CertificateStatus
    # extension, or an openssl s_client -status subprocess), we don't
    # fire — better to omit the check than to surface a false-positive on
    # every site. Method removed.

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
            framework=_FA["http_no_redirect"],
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
