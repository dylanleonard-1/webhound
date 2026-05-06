# WebHound — scanner/webhound/engines/headers/cors.py
# Passive analysis of CORS (Cross-Origin Resource Sharing) response headers.
#
# Safe-mode: reads headers from HttpResponse only.
# WebHound does not send an Origin header, so reflected-origin vulnerabilities
# are not directly observable here. This engine detects statically misconfigured
# ACAO values (wildcards, suspicious patterns) from the server's unconditional
# response.

from __future__ import annotations

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "cors"

# Methods that indicate an overly permissive CORS policy.
_SENSITIVE_METHODS = frozenset({"DELETE", "PUT", "PATCH"})


class CorsEngine:
    """Passive analysis of CORS response headers.

    Detects wildcard origins, dangerous credential combinations, and
    overly permissive method/header policies.

    Only analyzes headers present in the response.  Does not send Origin
    headers or modify any request.
    """

    NAME = _ENGINE

    def analyze(self, response: HttpResponse) -> list[Finding]:
        h = response.headers
        url = response.url

        # Only analyze responses that carry CORS headers.
        acao = h.get("access-control-allow-origin")
        if not acao:
            return []

        findings: list[Finding] = []
        acac = h.get("access-control-allow-credentials", "").strip().lower()
        acam = h.get("access-control-allow-methods", "")
        acah = h.get("access-control-allow-headers", "")

        findings.extend(self._check_wildcard_origin(acao, acac, url))
        findings.extend(self._check_permissive_methods(acao, acam, url))
        findings.extend(self._check_wildcard_headers(acao, acah, url))

        return findings

    # ------------------------------------------------------------------
    # Wildcard origin + credentials
    # ------------------------------------------------------------------

    def _check_wildcard_origin(
        self, acao: str, acac: str, url: str
    ) -> list[Finding]:
        acao_clean = acao.strip()

        if acao_clean == "*" and acac == "true":
            # Per RFC 6454 browsers should block this combination, but servers
            # that set it may be working around CORS via custom headers or
            # non-browser clients — still a significant misconfiguration.
            ev = _header_ev("Access-Control-Allow-Origin", acao_clean, url)
            return [_finding(
                title="CORS wildcard origin with credentials enabled",
                description=(
                    "Access-Control-Allow-Origin: * is combined with "
                    "Access-Control-Allow-Credentials: true. "
                    "This combination is rejected by browsers per spec, but "
                    "signals a serious CORS misconfiguration that may expose "
                    "authenticated resources to cross-origin attackers using "
                    "non-browser clients or future spec changes."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation=(
                    "Never combine ACAO: * with ACAC: true. "
                    "Maintain an explicit allowlist of trusted origins and "
                    "reflect only those origins dynamically."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A07:2021"],
                    cwe_ids=["CWE-942", "CWE-346"],
                    nist_controls=["AC-4"],
                ),
            )]

        if acao_clean == "*":
            ev = _header_ev("Access-Control-Allow-Origin", acao_clean, url)
            return [_finding(
                title="CORS policy allows any origin (wildcard)",
                description=(
                    "Access-Control-Allow-Origin: * permits any origin to make "
                    "cross-origin requests to this resource. If the resource "
                    "returns sensitive data, this may expose it to malicious sites."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    "Replace the wildcard with an explicit allowlist of trusted "
                    "origins. If the resource is truly public, document the intent."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-942"],
                    nist_controls=["AC-4"],
                ),
            )]

        # Non-wildcard origin present with credentials — normal but notable.
        if acac == "true":
            ev = _header_ev("Access-Control-Allow-Origin", acao_clean, url)
            return [_finding(
                title="CORS allows credentials for specific origin",
                description=(
                    f"Access-Control-Allow-Credentials: true is set for origin "
                    f"{acao_clean!r}. Credentials (cookies, auth headers) will be "
                    "sent in cross-origin requests from this origin. Verify the "
                    "origin is intentionally trusted."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation=(
                    "Ensure only intentionally trusted origins appear in "
                    "Access-Control-Allow-Origin when credentials are enabled. "
                    "Validate the Origin header server-side."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A07:2021"],
                    cwe_ids=["CWE-942"],
                    nist_controls=["AC-4"],
                ),
            )]

        return []

    # ------------------------------------------------------------------
    # Overly permissive methods
    # ------------------------------------------------------------------

    def _check_permissive_methods(
        self, acao: str, acam: str, url: str
    ) -> list[Finding]:
        if not acam:
            return []

        allowed = {m.strip().upper() for m in acam.split(",")}
        dangerous = allowed & _SENSITIVE_METHODS

        if dangerous:
            ev = _header_ev("Access-Control-Allow-Methods", acam, url)
            return [_finding(
                title="CORS policy permits sensitive HTTP methods",
                description=(
                    f"Access-Control-Allow-Methods includes "
                    f"{', '.join(sorted(dangerous))}, which allows cross-origin "
                    "callers to perform state-mutating operations. Combined with a "
                    "permissive origin policy this can enable cross-origin data "
                    "modification."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    "Restrict allowed methods to only those required. "
                    "Limit DELETE/PUT/PATCH to authenticated, narrowly scoped origins."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-942"],
                    nist_controls=["AC-4"],
                ),
            )]

        return []

    # ------------------------------------------------------------------
    # Wildcard in allowed headers
    # ------------------------------------------------------------------

    def _check_wildcard_headers(
        self, acao: str, acah: str, url: str
    ) -> list[Finding]:
        if acah.strip() == "*":
            ev = _header_ev("Access-Control-Allow-Headers", acah, url)
            return [_finding(
                title="CORS allows wildcard request headers",
                description=(
                    "Access-Control-Allow-Headers: * permits cross-origin requests "
                    "to include any request header. This may allow bypass of "
                    "server-side header validation checks."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation=(
                    "Enumerate explicitly allowed headers instead of using a wildcard."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"],
                    cwe_ids=["CWE-942"],
                    nist_controls=["AC-4"],
                ),
            )]
        return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _header_ev(name: str, value: str, url: str) -> Evidence:
    return Evidence.http_header(name, value, url, _ENGINE)


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
        category=FindingCategory.CORS,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=framework or FrameworkAlignment(),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
