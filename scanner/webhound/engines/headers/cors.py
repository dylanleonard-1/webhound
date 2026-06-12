# WebHound — scanner/webhound/engines/headers/cors.py
# Passive analysis of CORS (Cross-Origin Resource Sharing) response headers.
#
# Safe-mode: reads headers from HttpResponse only.
# WebHound does not send an Origin header, so reflected-origin vulnerabilities
# are not directly observable here. This engine detects statically misconfigured
# ACAO values (wildcards, suspicious patterns) from the server's unconditional
# response.

from __future__ import annotations

import re
from urllib.parse import urlparse

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "cors"

# Methods that indicate an overly permissive CORS policy.
_SENSITIVE_METHODS = frozenset({"DELETE", "PUT", "PATCH"})

# A path that plausibly returns PII / authenticated / API data — where ACAO:* actually
# matters. Public marketing/content pages (/, /about, …) do NOT match, so ACAO:* there is
# INFO, not MEDIUM. (audit #4: require credentials OR a sensitive resource to escalate.)
_SENSITIVE_PATH_RE = re.compile(
    r"(?:/api(?:/|$)|/graphql\b|/gql\b|/v\d+/|/rest/|/wp-json/|/account|/admin|/auth|"
    r"/oauth|/login|/logout|/users?\b|/me\b|/session|/token|/billing|/invoice|/order|"
    r"/cart|/checkout|/payment|/profile|/settings|/internal|/dashboard)",
    re.I,
)

# Enterprise metadata per CORS finding kind. See security_headers.py for the
# overall calibration approach.
_FA: dict[str, FrameworkAlignment] = {
    "cors_wildcard_with_creds": FrameworkAlignment(
        owasp_top10=["A07:2021"], cwe_ids=["CWE-942", "CWE-346"], nist_controls=["AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_score=7.5,
        pci_dss=["6.4.2"], iso_27001=["A.8.2", "A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "cors_wildcard": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-942"], nist_controls=["AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "cors_methods_permissive": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-942"], nist_controls=["AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "cors_wildcard_headers": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-942"], nist_controls=["AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
}


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

        sensitive = bool(_SENSITIVE_PATH_RE.search(urlparse(url).path or ""))
        findings.extend(self._check_wildcard_origin(acao, acac, url, sensitive=sensitive))
        findings.extend(self._check_permissive_methods(acao, acam, url))
        findings.extend(self._check_wildcard_headers(acao, acah, url))

        return findings

    # ------------------------------------------------------------------
    # Wildcard origin + credentials
    # ------------------------------------------------------------------

    def _check_wildcard_origin(
        self, acao: str, acac: str, url: str, *, sensitive: bool = False
    ) -> list[Finding]:
        acao_clean = acao.strip()

        if acao_clean == "*" and acac == "true":
            # Per the CORS spec, browsers reject ACAO=* with credentials. A server
            # that emits this combination is misconfigured; non-browser clients
            # may still honour it.
            ev = _header_ev("Access-Control-Allow-Origin", acao_clean, url)
            return [_finding(
                title="CORS is broken: wildcard origin + credentials",
                description=(
                    "Your server sends `Access-Control-Allow-Origin: *` together with "
                    "`Access-Control-Allow-Credentials: true`. Browsers reject this combination, "
                    "so credentialed cross-origin requests will fail silently — but the "
                    "configuration also signals a server that doesn't understand CORS, which "
                    "often hides bigger access-control bugs."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation=(
                    "Never set the wildcard origin with credentials. Maintain a server-side "
                    "allowlist of trusted origins and reflect the request `Origin` only when it's "
                    "on the allowlist."
                ),
                framework=_FA["cors_wildcard_with_creds"],
            )]

        if acao_clean == "*":
            ev = _header_ev("Access-Control-Allow-Origin", acao_clean, url)
            # ACAO:* WITHOUT credentials is only a real leak when the resource carries
            # sensitive/authenticated data. A browser won't even send credentials cross-
            # origin without ACAC:true, so on a public resource ACAO:* is informational.
            # Escalate to MEDIUM only when the path looks sensitive (API/account/auth/…).
            if sensitive:
                return [_finding(
                    title="CORS allows any website to read this resource",
                    description=(
                        "`Access-Control-Allow-Origin: *` lets any site on the internet read "
                        "responses from this endpoint via cross-origin requests, and its path looks "
                        "sensitive (API / account / auth). That's a leak for any PII, billing, or "
                        "authenticated content it returns."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "If this resource is intentionally public, no action needed — document it. "
                        "Otherwise replace `*` with an explicit allowlist of trusted origins."
                    ),
                    confidence=0.7,
                    framework=_FA["cors_wildcard"],
                )]
            return [_finding(
                title="CORS allows any website to read this resource (public)",
                description=(
                    "`Access-Control-Allow-Origin: *` lets any origin read this response. On a "
                    "public resource that's generally fine — and because `Access-Control-Allow-"
                    "Credentials` is not `true`, browsers won't send cookies/credentials cross-"
                    "origin, so no authenticated data is exposed this way. Review only if this "
                    "endpoint ever returns PII or authenticated content."
                ),
                severity=Severity.INFO,
                url=url,
                evidence=ev,
                remediation=(
                    "No action required for genuinely public data; document the intent. If the "
                    "endpoint may return PII/auth'd data, replace `*` with an origin allowlist."
                ),
                confidence=0.6,
                framework=_FA["cors_wildcard"],
            )]

        # Non-wildcard origin with credentials is the standard pattern for any
        # cookie-authenticated cross-origin API. It is not by itself a finding —
        # the noise this used to generate (one LOW per authenticated endpoint)
        # was the single biggest source of dashboard clutter from this engine.
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
                framework=_FA["cors_methods_permissive"],
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
                framework=_FA["cors_wildcard_headers"],
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
