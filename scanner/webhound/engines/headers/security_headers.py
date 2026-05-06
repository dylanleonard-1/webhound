# WebHound — scanner/webhound/engines/headers/security_headers.py
# Passive analysis of HTTP security response headers.
#
# Safe-mode: reads headers from HttpResponse only.
# No active probing, exploitation, or bypass attempts.

from __future__ import annotations

import re
from typing import NamedTuple

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "security_headers"

# HSTS max-age threshold for "too short" — 1 year in seconds.
_HSTS_MIN_MAX_AGE = 31_536_000

# CSP source patterns that eliminate meaningful protection.
_CSP_UNSAFE_INLINE = re.compile(r"'unsafe-inline'", re.I)
_CSP_UNSAFE_EVAL = re.compile(r"'unsafe-eval'", re.I)
# A bare wildcard (*) as a fetch directive value.
_CSP_WILDCARD_SRC = re.compile(r"(?:^|\s)\*(?:\s|;|$)")

# Referrer-Policy values that leak full URLs to third parties.
_UNSAFE_REFERRER = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


class SecurityHeadersEngine:
    """Checks HTTP response headers for missing or weak security directives.

    Passive, read-only analysis only.  Call ``analyze(response)`` to receive
    a list of :class:`~webhound.models.finding.Finding` objects.
    """

    NAME = _ENGINE

    def analyze(self, response: HttpResponse) -> list[Finding]:
        h = response.headers  # already lowercase keys
        url = response.url
        findings: list[Finding] = []

        findings.extend(self._check_csp(h, url))
        findings.extend(self._check_hsts(h, url, response))
        findings.extend(self._check_xfo(h, url))
        findings.extend(self._check_xcto(h, url))
        findings.extend(self._check_referrer(h, url))
        findings.extend(self._check_permissions(h, url))
        findings.extend(self._check_coop(h, url))
        findings.extend(self._check_coep(h, url))
        findings.extend(self._check_corp(h, url))

        return findings

    # ------------------------------------------------------------------
    # Content-Security-Policy
    # ------------------------------------------------------------------

    def _check_csp(self, h: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        csp = h.get("content-security-policy") or h.get("content-security-policy-report-only")

        if not csp:
            findings.append(_finding(
                title="Content-Security-Policy header missing",
                description=(
                    "No Content-Security-Policy (CSP) header was found. "
                    "CSP is a critical defence-in-depth mechanism that limits the impact "
                    "of cross-site scripting (XSS) and data injection attacks."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="Content-Security-Policy: <not present>",
                remediation=(
                    "Add a strict Content-Security-Policy header. "
                    "Start with: Content-Security-Policy: default-src 'self'"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-693"],
                    nist_controls=["SI-10"],
                ),
            ))
            return findings

        ev = Evidence.http_header("Content-Security-Policy", csp, url, _ENGINE)

        if _CSP_WILDCARD_SRC.search(csp):
            findings.append(_finding(
                title="CSP allows wildcard (*) source",
                description=(
                    f"The Content-Security-Policy contains a bare wildcard (*) source "
                    f"directive, which negates the policy's XSS protection entirely. "
                    f"Value: {csp!r}"
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation="Replace wildcard sources with explicit allowed origins.",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            ))

        if _CSP_UNSAFE_INLINE.search(csp):
            findings.append(_finding(
                title="CSP contains 'unsafe-inline'",
                description=(
                    "'unsafe-inline' in the Content-Security-Policy permits inline "
                    "scripts and styles, bypassing the XSS protection that CSP provides."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation=(
                    "Remove 'unsafe-inline'. Use nonces or hashes for legitimate "
                    "inline code: script-src 'nonce-{random}'"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            ))

        if _CSP_UNSAFE_EVAL.search(csp):
            findings.append(_finding(
                title="CSP contains 'unsafe-eval'",
                description=(
                    "'unsafe-eval' allows the use of eval() and related functions "
                    "which can execute attacker-controlled strings as code."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Remove 'unsafe-eval'. Refactor code to avoid eval().",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            ))

        if "default-src" not in csp.lower():
            findings.append(_finding(
                title="CSP missing default-src directive",
                description=(
                    "The Content-Security-Policy does not include a 'default-src' "
                    "fallback directive. Resources not covered by an explicit directive "
                    "will be allowed from any origin."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Add 'default-src' as a catch-all fallback, e.g. default-src 'self'.",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # Strict-Transport-Security
    # ------------------------------------------------------------------

    def _check_hsts(
        self, h: dict[str, str], url: str, response: HttpResponse
    ) -> list[Finding]:
        if not url.startswith("https://"):
            return []

        hsts = h.get("strict-transport-security")

        if not hsts:
            return [_finding(
                title="Strict-Transport-Security (HSTS) header missing",
                description=(
                    "The HTTPS response does not include a Strict-Transport-Security "
                    "header. Without HSTS, browsers may allow downgrade attacks that "
                    "redirect users to an unencrypted HTTP version of the site."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="Strict-Transport-Security: <not present>",
                remediation=(
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A02:2021"],
                    cwe_ids=["CWE-319"],
                    nist_controls=["SC-8"],
                ),
            )]

        ev = Evidence.http_header("Strict-Transport-Security", hsts, url, _ENGINE)
        findings: list[Finding] = []

        max_age = _parse_hsts_max_age(hsts)
        if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
            findings.append(_finding(
                title="HSTS max-age is below 1 year",
                description=(
                    f"The Strict-Transport-Security max-age is {max_age:,} seconds "
                    f"({max_age // 86400} days), which is below the recommended minimum "
                    f"of 1 year (31,536,000 seconds)."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation="Set max-age to at least 31536000 (1 year).",
                framework=FrameworkAlignment(
                    owasp_top10=["A02:2021"], cwe_ids=["CWE-319"]
                ),
            ))

        if "includesubdomains" not in hsts.lower():
            findings.append(_finding(
                title="HSTS does not include subdomains",
                description=(
                    "The Strict-Transport-Security header is missing "
                    "'includeSubDomains'. Subdomains remain vulnerable to downgrade "
                    "attacks even when the main domain is protected."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation="Add 'includeSubDomains' to the HSTS header.",
                framework=FrameworkAlignment(
                    owasp_top10=["A02:2021"], cwe_ids=["CWE-319"]
                ),
            ))

        return findings

    # ------------------------------------------------------------------
    # X-Frame-Options
    # ------------------------------------------------------------------

    def _check_xfo(self, h: dict[str, str], url: str) -> list[Finding]:
        xfo = h.get("x-frame-options")
        csp = h.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            return [_finding(
                title="X-Frame-Options header missing",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive was "
                    "found. The page may be embedded in an iframe on an attacker-"
                    "controlled site (clickjacking)."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="X-Frame-Options: <not present>",
                remediation=(
                    "Add: X-Frame-Options: DENY\n"
                    "Or use CSP: Content-Security-Policy: frame-ancestors 'none'"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-1021"],
                    nist_controls=["SI-10"],
                ),
            )]

        if xfo and xfo.strip().upper().startswith("ALLOW-FROM"):
            ev = Evidence.http_header("X-Frame-Options", xfo, url, _ENGINE)
            return [_finding(
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description=(
                    "X-Frame-Options: ALLOW-FROM is deprecated and not supported by "
                    "modern browsers. Use the CSP frame-ancestors directive instead."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation=(
                    "Replace with: Content-Security-Policy: "
                    "frame-ancestors 'self' https://trusted.example.com"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-1021"]
                ),
            )]

        return []

    # ------------------------------------------------------------------
    # X-Content-Type-Options
    # ------------------------------------------------------------------

    def _check_xcto(self, h: dict[str, str], url: str) -> list[Finding]:
        xcto = h.get("x-content-type-options")

        if not xcto:
            return [_finding(
                title="X-Content-Type-Options header missing",
                description=(
                    "The X-Content-Type-Options header is absent. Without 'nosniff', "
                    "browsers may interpret responses with incorrect MIME types, "
                    "enabling MIME-sniffing attacks."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="X-Content-Type-Options: <not present>",
                remediation="Add: X-Content-Type-Options: nosniff",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-430"],
                    nist_controls=["SI-10"],
                ),
            )]

        if xcto.strip().lower() != "nosniff":
            ev = Evidence.http_header("X-Content-Type-Options", xcto, url, _ENGINE)
            return [_finding(
                title="X-Content-Type-Options value is not 'nosniff'",
                description=(
                    f"X-Content-Type-Options is set to {xcto!r} rather than 'nosniff'. "
                    "Only the value 'nosniff' is recognized by browsers."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Set: X-Content-Type-Options: nosniff",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-430"]
                ),
            )]

        return []

    # ------------------------------------------------------------------
    # Referrer-Policy
    # ------------------------------------------------------------------

    def _check_referrer(self, h: dict[str, str], url: str) -> list[Finding]:
        rp = h.get("referrer-policy")

        if not rp:
            return [_finding(
                title="Referrer-Policy header missing",
                description=(
                    "No Referrer-Policy header was found. Browsers default to "
                    "'no-referrer-when-downgrade', potentially leaking full URL "
                    "paths to third-party sites via the Referer header."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Referrer-Policy: <not present>",
                remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-200"]
                ),
            )]

        if rp.strip().lower() in _UNSAFE_REFERRER:
            ev = Evidence.http_header("Referrer-Policy", rp, url, _ENGINE)
            return [_finding(
                title="Referrer-Policy is overly permissive",
                description=(
                    f"Referrer-Policy: {rp!r} sends the full URL (including path and "
                    "query parameters) as a Referer header to third-party sites. "
                    "This may leak sensitive URL parameters."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation="Use: Referrer-Policy: strict-origin-when-cross-origin",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-200"]
                ),
            )]

        return []

    # ------------------------------------------------------------------
    # Permissions-Policy
    # ------------------------------------------------------------------

    def _check_permissions(self, h: dict[str, str], url: str) -> list[Finding]:
        pp = h.get("permissions-policy")
        if not pp:
            return [_finding(
                title="Permissions-Policy header missing",
                description=(
                    "No Permissions-Policy header was found. Without it, all browser "
                    "features (camera, microphone, geolocation, etc.) default to their "
                    "browser-specified policy, which may be permissive."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Permissions-Policy: <not present>",
                remediation=(
                    "Add a Permissions-Policy header restricting unused features. "
                    "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            )]
        return []

    # ------------------------------------------------------------------
    # Cross-Origin-* headers (COOP, COEP, CORP)
    # ------------------------------------------------------------------

    def _check_coop(self, h: dict[str, str], url: str) -> list[Finding]:
        if not h.get("cross-origin-opener-policy"):
            return [_finding(
                title="Cross-Origin-Opener-Policy (COOP) header missing",
                description=(
                    "COOP prevents cross-origin windows from retaining a reference to "
                    "this page, protecting against cross-origin attacks such as "
                    "XS-Leaks."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Cross-Origin-Opener-Policy: <not present>",
                remediation="Add: Cross-Origin-Opener-Policy: same-origin",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            )]
        return []

    def _check_coep(self, h: dict[str, str], url: str) -> list[Finding]:
        if not h.get("cross-origin-embedder-policy"):
            return [_finding(
                title="Cross-Origin-Embedder-Policy (COEP) header missing",
                description=(
                    "COEP prevents a document from loading cross-origin resources "
                    "that don't explicitly grant permission. Required to enable "
                    "powerful features like SharedArrayBuffer."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Cross-Origin-Embedder-Policy: <not present>",
                remediation="Add: Cross-Origin-Embedder-Policy: require-corp",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            )]
        return []

    def _check_corp(self, h: dict[str, str], url: str) -> list[Finding]:
        if not h.get("cross-origin-resource-policy"):
            return [_finding(
                title="Cross-Origin-Resource-Policy (CORP) header missing",
                description=(
                    "CORP restricts which origins may embed this resource. Without it, "
                    "any site can embed this page's resources, enabling Spectre-style "
                    "side-channel reads."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Cross-Origin-Resource-Policy: <not present>",
                remediation="Add: Cross-Origin-Resource-Policy: same-origin",
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            )]
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_hsts_max_age(hsts_value: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.I)
    return int(m.group(1)) if m else None


def _finding(
    title: str,
    description: str,
    severity: Severity,
    url: str,
    remediation: str | None = None,
    framework: FrameworkAlignment | None = None,
    evidence: Evidence | None = None,
    evidence_content: str | None = None,
    confidence: float = 1.0,
) -> Finding:
    if evidence is None and evidence_content is not None:
        evidence = Evidence(
            evidence_type=EvidenceType.HEADER,
            content=evidence_content,
            location=url,
            source_engine=_ENGINE,
        )
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=FindingCategory.SECURITY_HEADER,
        evidence=[evidence] if evidence else [],
        confidence=confidence,
        remediation=remediation,
        framework=framework or FrameworkAlignment(),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
