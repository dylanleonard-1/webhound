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
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "security_headers"

# HSTS max-age threshold for "too short" — 1 year in seconds.
_HSTS_MIN_MAX_AGE = 31_536_000

# CSP source patterns that eliminate meaningful protection.
_CSP_UNSAFE_INLINE = re.compile(r"'unsafe-inline'", re.I)
_CSP_UNSAFE_EVAL = re.compile(r"'unsafe-eval'", re.I)
# A bare wildcard (*) as a fetch directive value.
_CSP_WILDCARD_SRC = re.compile(r"(?:^|\s)\*(?:\s|;|$)")
# strict-dynamic: when present, browsers IGNORE host-source allowlists,
# `*`, `'self'`, and `'unsafe-inline'` in script-src. The protection
# comes entirely from the nonce/hash chain instead. We use this to
# avoid flagging policies that are actually well-designed.
_CSP_STRICT_DYNAMIC = re.compile(r"'strict-dynamic'", re.I)

# Referrer-Policy values that leak full URLs to third parties.
_UNSAFE_REFERRER = frozenset({"unsafe-url", "no-referrer-when-downgrade"})

# ---------------------------------------------------------------------------
# Enterprise metadata per finding kind
# ---------------------------------------------------------------------------
# CVSS scores are calibrated against industry baselines for security-header
# weaknesses (defence-in-depth controls — usually MEDIUM-LOW base scores,
# higher when the control gap directly enables XSS or data theft).
#
# Compliance mappings target the most-cited public frameworks our buyers
# care about: PCI DSS 4.0, ISO/IEC 27001:2022, SOC 2 (Trust Services
# Criteria), and HIPAA Security Rule where applicable.
#
# Exploitability triages the finding: THEORETICAL (defence-in-depth gap),
# PRACTICAL (known attack path), KNOWN_EXPLOITED (active in the wild).

_FA: dict[str, FrameworkAlignment] = {
    # --- Content-Security-Policy --------------------------------------------
    "csp_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "csp_wildcard": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_score=7.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_unsafe_inline": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-79"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_score=6.1,
        pci_dss=["6.4.2", "6.2.4"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_unsafe_eval": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-95"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "csp_no_default_src": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=4.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- HSTS ---------------------------------------------------------------
    "hsts_missing": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8", "SC-23"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=5.9,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"], hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hsts_max_age_short": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.7,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "hsts_no_subdomains": FrameworkAlignment(
        owasp_top10=["A02:2021"], cwe_ids=["CWE-319"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        pci_dss=["4.2.1"], iso_27001=["A.8.24"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- X-Frame-Options / clickjacking -------------------------------------
    "xfo_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1021"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "xfo_allow_from": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1021"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=4.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- X-Content-Type-Options ---------------------------------------------
    "xcto_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-430"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "xcto_wrong_value": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-430"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- Referrer-Policy ----------------------------------------------------
    "referrer_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.7,
        pci_dss=["3.5.1"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "referrer_unsafe": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=4.3,
        pci_dss=["3.5.1"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    # --- Permissions-Policy -------------------------------------------------
    "permissions_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- Cross-Origin-* (COOP/COEP/CORP combined) ---------------------------
    "cross_origin_isolation_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=2.8,
        iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- X-XSS-Protection (legacy) ------------------------------------------
    "xss_protection_legacy": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1173"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.7,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.PRACTICAL,
    ),
    # --- Information disclosure ---------------------------------------------
    "server_version": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["SC-30"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.5.5"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "powered_by": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["SC-30"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.5.5"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "framework_fingerprint": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-200"], nist_controls=["SC-30"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", cvss_score=5.3,
        pci_dss=["6.5.5"], iso_27001=["A.5.34"], soc2=["CC6.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    # --- Cache-Control on auth ----------------------------------------------
    "cache_control_auth": FrameworkAlignment(
        owasp_top10=["A04:2021"], cwe_ids=["CWE-525", "CWE-200"], nist_controls=["SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", cvss_score=5.9,
        pci_dss=["6.5.6", "8.6.1"], iso_27001=["A.8.4", "A.5.34"], soc2=["CC6.1"], hipaa=["164.312(a)(2)(iii)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    # --- Legacy / deprecated -----------------------------------------------
    "hpkp_legacy": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1059"], nist_controls=["CM-2"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", cvss_score=4.0,
        iso_27001=["A.8.32"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "expect_ct_legacy": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1059"],
        iso_27001=["A.8.32"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "acma_excessive": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-942"], nist_controls=["AC-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.7,
        iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
}


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
        findings.extend(self._check_xss_protection(h, url))
        findings.extend(self._check_info_disclosure(h, url))
        findings.extend(self._check_cache_control_auth(h, url))
        findings.extend(self._check_legacy_headers(h, url))

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
                framework=_FA["csp_missing"],
            ))
            return findings

        ev = Evidence.http_header("Content-Security-Policy", csp, url, _ENGINE)
        # If strict-dynamic is in script-src, browsers that support it ignore
        # the host allowlist (including `*`) and 'unsafe-inline' for scripts.
        # Don't flag those when the policy is using the modern nonce/hash
        # pattern.
        has_strict_dynamic = bool(_CSP_STRICT_DYNAMIC.search(csp))

        if _CSP_WILDCARD_SRC.search(csp) and not has_strict_dynamic:
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
                framework=_FA["csp_wildcard"],
            ))

        if _CSP_UNSAFE_INLINE.search(csp) and not has_strict_dynamic:
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
                framework=_FA["csp_unsafe_inline"],
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
                framework=_FA["csp_unsafe_eval"],
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
                framework=_FA["csp_no_default_src"],
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
                framework=_FA["hsts_missing"],
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
                framework=_FA["hsts_max_age_short"],
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
                framework=_FA["hsts_no_subdomains"],
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
                framework=_FA["xfo_missing"],
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
                framework=_FA["xfo_allow_from"],
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
                framework=_FA["xcto_missing"],
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
                framework=_FA["xcto_wrong_value"],
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
                framework=_FA["referrer_missing"],
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
                framework=_FA["referrer_unsafe"],
            )]

        return []

    # ------------------------------------------------------------------
    # Permissions-Policy
    # ------------------------------------------------------------------

    def _check_permissions(self, h: dict[str, str], url: str) -> list[Finding]:
        pp = h.get("permissions-policy")
        # Treat absent OR empty value as the same thing — both mean "no policy".
        if not pp or not pp.strip():
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
                evidence_content=f"Permissions-Policy: {pp!r}" if pp is not None else "Permissions-Policy: <not present>",
                remediation=(
                    "List the features you don't use and disable them. Example for a typical "
                    "marketing site:\n"
                    "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
                ),
                confidence=0.7,
                framework=_FA["permissions_missing"],
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
        # Aggregate over the three cross-origin isolation headers. Validate the
        # value when present — `unsafe-none` is the lax default and is treated
        # the same as the header being absent.
        coop  = (h.get("cross-origin-opener-policy")    or "").strip().lower()
        coep  = (h.get("cross-origin-embedder-policy")  or "").strip().lower()
        corp  = (h.get("cross-origin-resource-policy")  or "").strip().lower()

        problems: list[str] = []
        # COOP safe: same-origin, same-origin-allow-popups, noopener-allow-popups.
        # COOP lax/no-op: unsafe-none, empty, absent.
        if coop in ("", "unsafe-none"):
            problems.append(f"Cross-Origin-Opener-Policy: {coop or '<not present>'}")
        # COEP safe: require-corp, credentialless. Lax: unsafe-none / empty.
        if coep in ("", "unsafe-none"):
            problems.append(f"Cross-Origin-Embedder-Policy: {coep or '<not present>'}")
        # CORP safe: same-origin, same-site. cross-origin is permissive but
        # explicitly required for genuinely public CDN-served assets — don't flag.
        if corp == "":
            problems.append(f"Cross-Origin-Resource-Policy: <not present>")

        if not problems:
            return []

        return [_finding(
            title="Cross-origin isolation headers not set",
            description=(
                f"Your site doesn't set {len(problems)} of the 3 cross-origin isolation "
                "headers (or they're set to the lax default). These protect against "
                "advanced cross-origin attacks (XS-Leaks, Spectre-style side channels) "
                "and are required for some browser features like SharedArrayBuffer. "
                "Most sites that don't use those features can ignore this — set them "
                "only if you handle sensitive data or need full isolation."
            ),
            severity=Severity.INFO,
            url=url,
            evidence_content="\n".join(problems),
            remediation=(
                "If you want full cross-origin isolation, add:\n"
                "  Cross-Origin-Opener-Policy: same-origin\n"
                "  Cross-Origin-Embedder-Policy: require-corp\n"
                "  Cross-Origin-Resource-Policy: same-origin\n"
                "Test thoroughly — these can break embedded third-party content."
            ),
            confidence=0.6,
            framework=_FA["cross_origin_isolation_missing"],
        )]

    # Kept as placeholders so the analyze() pipeline doesn't change; the real
    # logic now lives in _check_coop above.
    def _check_coep(self, h: dict[str, str], url: str) -> list[Finding]:
        return []

    def _check_corp(self, h: dict[str, str], url: str) -> list[Finding]:
        return []

    # ------------------------------------------------------------------
    # Information disclosure: Server / X-Powered-By
    # ------------------------------------------------------------------

    def _check_info_disclosure(self, h: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Server: only flag values that reveal version info. "nginx" alone is
        # fine; "nginx/1.18.0" leaks a CVE-checkable version. Same for Apache,
        # gunicorn, etc.
        server = (h.get("server") or "").strip()
        if server and any(c.isdigit() for c in server):
            ev = Evidence.http_header("Server", server, url, _ENGINE)
            findings.append(_finding(
                title="Server software version is publicly visible",
                description=(
                    f"Your server is advertising its software version: `{server}`. Attackers run "
                    "automated tools that match version strings against known vulnerabilities. "
                    "Even when you're patched, this gives them a free starting point."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation=(
                    "Strip the version from the Server header at your reverse proxy. Examples:\n"
                    "  nginx:   server_tokens off;\n"
                    "  Apache:  ServerTokens Prod\n"
                    "  IIS:     remove via URL Rewrite or `Remove-Item ...:::ServerHeader`\n"
                    "  Cloudflare: enabled by default — verify your origin isn't bypassing it."
                ),
                confidence=0.95,
                framework=_FA["server_version"],
            ))

        # X-Powered-By is *always* a disclosure header. The mere presence is
        # noteworthy because it's never required and is set by default by
        # several frameworks (Express, ASP.NET).
        xpb = (h.get("x-powered-by") or "").strip()
        if xpb:
            ev = Evidence.http_header("X-Powered-By", xpb, url, _ENGINE)
            findings.append(_finding(
                title="Framework / runtime is advertised in headers",
                description=(
                    f"Your site sends `X-Powered-By: {xpb}`. This header serves no functional "
                    "purpose and tells attackers exactly which framework / runtime to target. "
                    "Several frameworks (Express, ASP.NET) set it by default."
                ),
                severity=Severity.LOW,
                url=url,
                evidence=ev,
                remediation=(
                    "Disable the header in your framework:\n"
                    "  Express:  app.disable('x-powered-by')\n"
                    "  ASP.NET:  remove via Web.config or Startup.cs\n"
                    "  PHP:      expose_php = Off"
                ),
                confidence=0.95,
                framework=_FA["powered_by"],
            ))

        # Other framework-fingerprint headers seen in the wild.
        for fp_header in ("x-aspnet-version", "x-aspnetmvc-version", "x-drupal-cache", "x-generator", "x-pingback"):
            val = (h.get(fp_header) or "").strip()
            if val:
                ev = Evidence.http_header(fp_header.title(), val, url, _ENGINE)
                findings.append(_finding(
                    title=f"Framework fingerprint header `{fp_header}` exposed",
                    description=(
                        f"Your site sends `{fp_header}: {val}`. This header is set by specific "
                        "frameworks and helps attackers fingerprint your stack. It has no "
                        "functional value to clients."
                    ),
                    severity=Severity.LOW,
                    url=url,
                    evidence=ev,
                    remediation=f"Remove the `{fp_header}` header at your application or reverse proxy.",
                    confidence=0.9,
                    framework=_FA["framework_fingerprint"],
                ))

        return findings

    # ------------------------------------------------------------------
    # Cache-Control on sensitive endpoints
    # ------------------------------------------------------------------

    def _check_cache_control_auth(self, h: dict[str, str], url: str) -> list[Finding]:
        # Only flag if this URL looks like an auth / account / billing path AND
        # the Cache-Control header allows public/shared caching. We don't have
        # auth context here, so we use path heuristics.
        path_lc = url.lower()
        if not any(seg in path_lc for seg in (
            "/login", "/signin", "/sign-in", "/logout", "/signout",
            "/account", "/profile", "/settings", "/admin",
            "/billing", "/checkout", "/payment", "/orders",
            "/api/me", "/auth/", "/oauth/", "/sso/",
            "/dashboard",
        )):
            return []

        cc = (h.get("cache-control") or "").strip().lower()
        # Safe values include any of these directives.
        safe_tokens = ("no-store", "private", "max-age=0")
        if cc and any(tok in cc for tok in safe_tokens):
            return []
        # Explicitly public is bad on these paths.
        ev = Evidence.http_header("Cache-Control", cc or "<not present>", url, _ENGINE)
        return [_finding(
            title="Sensitive endpoint may be cached publicly",
            description=(
                "This URL looks like an authenticated endpoint (account, login, billing, etc.) "
                "but its `Cache-Control` header doesn't prevent caching. A shared cache (CDN, "
                "corporate proxy, browser back/forward cache) may store a response intended for "
                "one user and serve it to another."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation=(
                "Add to every response from authenticated endpoints:\n"
                "  Cache-Control: no-store\n"
                "If you genuinely want browser caching but no shared caching:\n"
                "  Cache-Control: private, no-cache"
            ),
            confidence=0.6,  # path heuristic — could be a marketing /login page
            framework=_FA["cache_control_auth"],
        )]

    # ------------------------------------------------------------------
    # Legacy / deprecated security headers still in use
    # ------------------------------------------------------------------

    def _check_legacy_headers(self, h: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []

        # HPKP: deprecated by Chrome (2018) and removed. If still present, it's
        # either dead config or — worse — actively risking a denial-of-service
        # bricking if a pinned key is lost.
        if h.get("public-key-pins") or h.get("public-key-pins-report-only"):
            val = h.get("public-key-pins") or h.get("public-key-pins-report-only", "")
            ev = Evidence.http_header("Public-Key-Pins", val[:200], url, _ENGINE)
            findings.append(_finding(
                title="HPKP header is deprecated and risky",
                description=(
                    "Your site sets a `Public-Key-Pins` header. HPKP was removed from Chrome in 2018 "
                    "and is no longer enforced by any major browser — but more importantly, if you "
                    "ever lose access to a pinned certificate key, the header can permanently lock "
                    "users out of your site (DoS). The risk now outweighs any benefit."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation=(
                    "Remove the `Public-Key-Pins` header. Use Certificate Transparency monitoring "
                    "(crt.sh, Cert Spotter) for the protection HPKP used to provide."
                ),
                confidence=0.98,
                framework=_FA["hpkp_legacy"],
            ))

        # Expect-CT is deprecated as of Chrome 107 (June 2023). Still works in
        # some browsers but no longer enforced anywhere by default.
        if h.get("expect-ct"):
            val = h.get("expect-ct", "")
            ev = Evidence.http_header("Expect-CT", val, url, _ENGINE)
            findings.append(_finding(
                title="Expect-CT header is deprecated",
                description=(
                    "Your site sets an `Expect-CT` header. Expect-CT was deprecated in 2023 because "
                    "Certificate Transparency is now enforced unconditionally by all major browsers. "
                    "The header no longer has any effect and just adds bytes to every response."
                ),
                severity=Severity.INFO,
                url=url,
                evidence=ev,
                remediation="Remove the `Expect-CT` header. Certificate Transparency is now enforced by default.",
                confidence=0.98,
                framework=_FA["expect_ct_legacy"],
            ))

        # Access-Control-Max-Age caps. Some servers set absurdly long values
        # (a year) to "improve performance", which means that if you fix a
        # misconfigured CORS policy later, clients will use the cached version
        # for up to the max-age. Chrome caps at 2h regardless, but Firefox /
        # Safari respect longer values.
        acma = h.get("access-control-max-age")
        if acma and acma.strip().isdigit():
            seconds = int(acma.strip())
            if seconds > 86400:  # > 24h
                ev = Evidence.http_header("Access-Control-Max-Age", acma, url, _ENGINE)
                findings.append(_finding(
                    title="CORS preflight cache lifetime is excessive",
                    description=(
                        f"Your server tells browsers to cache CORS preflight results for "
                        f"{seconds:,} seconds ({seconds // 86400} days). If you change a CORS "
                        "policy in the future, some browsers will keep using the old policy for "
                        "the entire cache lifetime — meaning a security fix won't take effect "
                        "until the cache expires."
                    ),
                    severity=Severity.LOW,
                    url=url,
                    evidence=ev,
                    remediation=(
                        "Cap the value at 24 hours or less:\n"
                        "  Access-Control-Max-Age: 86400\n"
                        "Chrome already caps at 2 hours; matching its limit is also reasonable."
                    ),
                    confidence=0.85,
                    framework=_FA["acma_excessive"],
                ))

        return findings

    # ------------------------------------------------------------------
    # X-XSS-Protection (legacy)
    # ------------------------------------------------------------------

    def _check_xss_protection(self, h: dict[str, str], url: str) -> list[Finding]:
        # Modern guidance (OWASP, Chrome, Firefox): set X-XSS-Protection to 0 or
        # don't set it at all. The legacy `1; mode=block` filter has known XSS
        # bugs of its own and was removed from Chrome 78 / Edge / Firefox.
        # We only flag if the site is actively re-enabling it.
        xss = (h.get("x-xss-protection") or "").strip().lower()
        if not xss:
            return []
        # Anything starting with "0" is fine.
        if xss.startswith("0"):
            return []
        ev = Evidence.http_header("X-XSS-Protection", xss, url, _ENGINE)
        return [_finding(
            title="X-XSS-Protection enables a deprecated, vulnerable filter",
            description=(
                "Your site sets `X-XSS-Protection: 1`, which turns on a legacy browser XSS "
                "filter that has been deprecated and removed from modern browsers. The filter "
                "itself had bugs that introduced new XSS vulnerabilities in the past. Old "
                "security guides still recommend this header — they're out of date."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Either drop the header entirely or explicitly disable the legacy filter:\n"
                "  X-XSS-Protection: 0\n"
                "Then rely on Content-Security-Policy for real XSS protection."
            ),
            confidence=0.95,
            framework=_FA["xss_protection_legacy"],
        )]


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
