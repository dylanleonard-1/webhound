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
                title="No Content-Security-Policy",
                description=(
                    "Your site doesn't tell browsers which scripts and styles are allowed to run. "
                    "Without this guardrail, a single injected script tag can run on every page."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="Content-Security-Policy: <not present>",
                remediation=(
                    "Add a Content-Security-Policy header — a defence-in-depth mechanism against XSS "
                    "(Cross-Site Scripting, CWE-79) and data-injection attacks. Start strict and loosen as needed:\n"
                    "  Content-Security-Policy: default-src 'self'"
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
                title="CSP allows any origin (wildcard)",
                description=(
                    "Your Content-Security-Policy contains a `*` directive, which lets browsers "
                    "load scripts and styles from anywhere. That removes most of the protection "
                    "the header was meant to provide."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation=(
                    "Replace the wildcard with explicit origins your site actually loads from.\n"
                    f"Observed policy: {csp[:200]!r}"
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            ))

        if _CSP_UNSAFE_INLINE.search(csp):
            findings.append(_finding(
                title="CSP allows inline scripts",
                description=(
                    "Your CSP permits inline `<script>` and `<style>` tags. An attacker who injects "
                    "even one tag can run code on your visitors' browsers."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation=(
                    "Remove `'unsafe-inline'`. For inline scripts you control, use a nonce or hash:\n"
                    "  script-src 'self' 'nonce-{random-per-response}'\n"
                    "Modern frameworks (Next.js, Rails, Django) generate nonces automatically."
                ),
                confidence=0.95,
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-79"]
                ),
            ))

        if _CSP_UNSAFE_EVAL.search(csp):
            findings.append(_finding(
                title="CSP allows eval()",
                description=(
                    "Your CSP allows JavaScript `eval()` and related functions. If any user-supplied "
                    "string reaches eval(), it runs as code."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    "Remove `'unsafe-eval'` from script-src. Most uses of eval() can be replaced "
                    "with JSON.parse() or a safer parser."
                ),
                confidence=0.9,
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-95"]
                ),
            ))

        if "default-src" not in csp.lower():
            findings.append(_finding(
                title="CSP is missing a default fallback",
                description=(
                    "Your CSP lists rules for specific resource types (scripts, images, etc.) but has "
                    "no `default-src`. Any resource type you forgot to mention is allowed from anywhere."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Add a catch-all fallback at the start of the policy: `default-src 'self';`",
                confidence=0.85,
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
                title="No HSTS — browsers can still talk to your site over plain HTTP",
                description=(
                    "Your site is on HTTPS but doesn't tell browsers to refuse the HTTP version. "
                    "On public WiFi, an attacker can intercept the first connection and downgrade "
                    "your visitors to an unencrypted version of your site."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="Strict-Transport-Security: <not present>",
                remediation=(
                    "Add to every HTTPS response:\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n\n"
                    "Once you're confident, you can also add `preload` and submit to "
                    "hstspreload.org — but preload is hard to reverse, so only do it when "
                    "every subdomain is HTTPS-ready."
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
                title="HSTS doesn't cover subdomains",
                description=(
                    "Your HSTS header protects the main domain but not subdomains. If you host "
                    "anything on a subdomain (mail, app, api), they remain vulnerable to downgrade "
                    "attacks. Skip this only if a subdomain genuinely needs to stay HTTP."
                ),
                severity=Severity.INFO,
                url=url,
                evidence=ev,
                remediation=(
                    "Add `includeSubDomains` to the HSTS header. Confirm first that every "
                    "subdomain you own can serve HTTPS — once set, browsers will refuse HTTP."
                ),
                confidence=0.7,
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
                title="Page can be embedded in any iframe (clickjacking risk)",
                description=(
                    "Your site doesn't tell browsers whether other sites are allowed to put it inside "
                    "an iframe. An attacker can embed your login or checkout page on their own domain "
                    "and trick visitors into clicking buttons they think are theirs (clickjacking)."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="X-Frame-Options: <not present>",
                remediation=(
                    "Pick one. Modern: add to your CSP:\n"
                    "  Content-Security-Policy: frame-ancestors 'none'\n"
                    "Legacy fallback for older browsers:\n"
                    "  X-Frame-Options: DENY"
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
                title="Browsers may misinterpret file types served by your site",
                description=(
                    "Without `X-Content-Type-Options: nosniff`, browsers guess the type of files "
                    "they receive. An attacker who can upload a file (an image, a PDF) can sometimes "
                    "trick the browser into running it as a script — that's called a MIME-sniffing attack."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence_content="X-Content-Type-Options: <not present>",
                remediation="Add to every response: `X-Content-Type-Options: nosniff`",
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
                title="No Referrer-Policy — full URLs may leak to third parties",
                description=(
                    "When a visitor clicks a link to another site (or your page loads a third-party "
                    "script), the browser sends the URL they came from. Without a Referrer-Policy, "
                    "URL paths and query strings — which often contain tokens, IDs, or session info — "
                    "can leak to advertisers, analytics, and other sites."
                ),
                severity=Severity.LOW,
                url=url,
                evidence_content="Referrer-Policy: <not present>",
                remediation="Add: `Referrer-Policy: strict-origin-when-cross-origin`",
                confidence=0.85,
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-200"]
                ),
            )]

        if rp.strip().lower() in _UNSAFE_REFERRER:
            ev = Evidence.http_header("Referrer-Policy", rp, url, _ENGINE)
            return [_finding(
                title="Referrer-Policy leaks full URLs to other sites",
                description=(
                    f"Your Referrer-Policy is set to {rp!r}, which sends the entire URL "
                    "(including the path and query string) to other sites your visitors click "
                    "through to. If URLs contain session tokens, password reset tokens, or "
                    "personal data, that's a leak."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation="Change to: `Referrer-Policy: strict-origin-when-cross-origin`",
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
                title="No Permissions-Policy — browser features are wide open",
                description=(
                    "Your site doesn't explicitly disable powerful browser features it doesn't use "
                    "(camera, microphone, geolocation, etc). Modern browsers default to safe behaviour, "
                    "so this is rarely exploited — but locking it down is best practice and required "
                    "for some compliance frameworks."
                ),
                severity=Severity.INFO,
                url=url,
                evidence_content="Permissions-Policy: <not present>",
                remediation=(
                    "List the features you don't use and disable them. Example for a typical "
                    "marketing site:\n"
                    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
                ),
                confidence=0.7,
                framework=FrameworkAlignment(
                    owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
                ),
            )]
        return []

    # ------------------------------------------------------------------
    # Cross-Origin-* headers (COOP, COEP, CORP)
    # ------------------------------------------------------------------
    # Combined into a single INFO finding. These are advanced cross-origin
    # isolation headers — most sites don't need them, and three separate LOW
    # findings on every page was producing dashboard noise. We only fire one
    # finding listing whichever are missing.

    def _check_coop(self, h: dict[str, str], url: str) -> list[Finding]:
        missing: list[str] = []
        if not h.get("cross-origin-opener-policy"):
            missing.append("Cross-Origin-Opener-Policy")
        if not h.get("cross-origin-embedder-policy"):
            missing.append("Cross-Origin-Embedder-Policy")
        if not h.get("cross-origin-resource-policy"):
            missing.append("Cross-Origin-Resource-Policy")

        if len(missing) == 0:
            return []

        return [_finding(
            title="Cross-origin isolation headers not set",
            description=(
                f"Your site doesn't set {len(missing)} of the 3 cross-origin isolation "
                "headers. These protect against advanced cross-origin attacks (XS-Leaks, "
                "Spectre-style side channels) and are required for some browser features "
                "like SharedArrayBuffer. Most sites that don't use those features can ignore "
                "this — set them only if you handle sensitive data or need full isolation."
            ),
            severity=Severity.INFO,
            url=url,
            evidence_content=", ".join(f"{name}: <not present>" for name in missing),
            remediation=(
                "If you want full cross-origin isolation, add:\n"
                "  Cross-Origin-Opener-Policy: same-origin\n"
                "  Cross-Origin-Embedder-Policy: require-corp\n"
                "  Cross-Origin-Resource-Policy: same-origin\n"
                "Test thoroughly — these can break embedded third-party content."
            ),
            confidence=0.6,
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]
            ),
        )]

    # Kept as placeholders so the analyze() pipeline doesn't change; the real
    # logic now lives in _check_coop above.
    def _check_coep(self, h: dict[str, str], url: str) -> list[Finding]:
        return []

    def _check_corp(self, h: dict[str, str], url: str) -> list[Finding]:
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
