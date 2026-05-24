# WebHound — scanner/webhound/engines/headers/csp_engine.py
# Deep structural analysis of Content-Security-Policy headers.
#
# Complements the basic CSP presence / unsafe-directive checks already
# performed by SecurityHeadersEngine.  This engine parses the full directive
# set and flags higher-order policy weaknesses:
#
#   • Missing object-src 'none'   — allows plugin/embed injection
#   • Missing or permissive base-uri — enables base-tag hijacking
#   • Missing form-action          — allows cross-origin form exfiltration
#   • data: / blob: in script-src  — permits JS execution via data URIs
#   • http: in script-src          — script loading over plaintext HTTP
#   • frame-ancestors not set      — incomplete clickjacking protection
#   • Enforce-only header absent (report-only mode only)
#
# Safe-mode: reads response headers only.  No requests are made.

from __future__ import annotations

import re
from typing import Any

from webhound.core.http_client import HttpResponse
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "csp_engine"

# Enterprise metadata per deep-CSP finding kind. Calibrated against the
# security_headers.py table.
_FA: dict[str, FrameworkAlignment] = {
    "csp_report_only": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "csp_no_object_src": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=4.3,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "csp_base_uri_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_base_uri_wildcard": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_form_action_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=4.7,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_form_action_wildcard": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=4.7,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_script_data": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-79"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_score=7.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_script_blob": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-79"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", cvss_score=7.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"], soc2=["CC6.6"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_script_http": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"], cwe_ids=["CWE-319", "CWE-693"], nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N", cvss_score=7.5,
        pci_dss=["4.2.1", "6.4.2"], iso_27001=["A.8.24"], soc2=["CC6.7"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_frame_ancestors_wildcard": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1021"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        pci_dss=["6.4.2"], iso_27001=["A.8.23"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "csp_frame_ancestors_missing": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-1021"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=3.1,
        iso_27001=["A.8.23"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "csp_no_reporting": FrameworkAlignment(
        owasp_top10=["A05:2021"], cwe_ids=["CWE-693", "CWE-778"], nist_controls=["AU-2", "SI-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", cvss_score=0.0,
        iso_27001=["A.8.15", "A.8.23"], soc2=["CC7.2"],
        exploitability=Exploitability.THEORETICAL,
    ),
}

# Source-list values that permit unsafe code execution paths.
_DATA_URI_RE = re.compile(r"\bdata:", re.I)
_BLOB_URI_RE = re.compile(r"\bblob:", re.I)
_HTTP_SRC_RE = re.compile(r"(?<![s])\bhttp:", re.I)  # 'http:' but not 'https:'


def _parse_csp(header: str) -> dict[str, list[str]]:
    """Parse a CSP header string into {directive_name: [source_values]}.

    Directive names are lower-cased; source values retain their original case.
    """
    directives: dict[str, list[str]] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


def _src_value_contains(sources: list[str], pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(s) for s in sources)


class CspEngine:
    """Deep structural analysis of Content-Security-Policy headers.

    Operates on the *enforcement* CSP only (``Content-Security-Policy``).
    If only a report-only policy is present it emits an informational finding.

    Usage::

        findings = CspEngine().analyze(response)
    """

    NAME = _ENGINE

    def analyze(self, response: HttpResponse) -> list[Finding]:
        h = response.headers
        url = response.url
        findings: list[Finding] = []

        csp_enforce = h.get("content-security-policy", "").strip()
        csp_report_only = h.get("content-security-policy-report-only", "").strip()

        # If there is no CSP at all the SecurityHeadersEngine already flags it.
        if not csp_enforce and not csp_report_only:
            return []

        # If only report-only is present, flag at INFO. Running report-only is the
        # standard CSP rollout pattern — deploy, watch reports, then enforce.
        # We surface it so the team knows enforcement is still pending; we do
        # not punish a healthy rollout with a MEDIUM.
        if not csp_enforce and csp_report_only:
            findings.append(_finding(
                title="CSP is in report-only mode (not blocking attacks yet)",
                description=(
                    "Your site has a Content-Security-Policy in report-only mode. That's the "
                    "right pattern when you're rolling CSP out — it collects violation reports "
                    "without breaking pages. But until you graduate to the enforcing header, "
                    "the policy doesn't actually block anything."
                ),
                severity=Severity.INFO,
                url=url,
                evidence_content=f"Content-Security-Policy-Report-Only: {csp_report_only[:200]}",
                remediation=(
                    "When the reports from your report-only deployment have stopped flagging "
                    "legitimate page behaviour, switch the header name from "
                    "`Content-Security-Policy-Report-Only` to `Content-Security-Policy`."
                ),
                confidence=0.9,
                framework=_FA["csp_report_only"],
            ))
            return findings

        # Work with the enforcement policy from here.
        csp = csp_enforce
        ev = Evidence(
            evidence_type=EvidenceType.HEADER,
            content=f"Content-Security-Policy: {csp[:300]}",
            location=url,
            source_engine=_ENGINE,
        )
        directives = _parse_csp(csp)

        findings.extend(self._check_object_src(directives, url, ev))
        findings.extend(self._check_base_uri(directives, url, ev))
        findings.extend(self._check_form_action(directives, url, ev))
        findings.extend(self._check_script_src_data(directives, url, ev))
        findings.extend(self._check_script_src_http(directives, url, ev))
        findings.extend(self._check_frame_ancestors(directives, url, ev))
        findings.extend(self._check_reporting(directives, url, ev))

        return findings

    # ------------------------------------------------------------------
    # Directive checks
    # ------------------------------------------------------------------

    def _check_object_src(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """object-src 'none' prevents plugin/embed/applet injection."""
        obj = d.get("object-src", d.get("default-src", []))
        if obj and "'none'" in [s.lower() for s in obj]:
            return []
        return [_finding(
            title="CSP doesn't block <object> and <embed> tags",
            description=(
                "Your CSP doesn't include `object-src 'none'`. If an attacker can inject an "
                "`<object>` or `<embed>` tag (via XSS or HTML injection), it can load legacy "
                "plugin content that bypasses CSP. Modern browsers no longer run Flash or Java "
                "plugins, so the practical risk is lower than it used to be — but locking this "
                "down costs nothing."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation="Add to your Content-Security-Policy: `object-src 'none';`",
            confidence=0.8,
            framework=_FA["csp_no_object_src"],
        )]

    def _check_base_uri(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """base-uri restricts the <base href> tag — prevents base-tag hijacking."""
        if "base-uri" in d:
            sources = [s.lower() for s in d["base-uri"]]
            if "*" not in sources:
                return []
            return [_finding(
                title="CSP base-uri allows wildcard",
                description=(
                    "The CSP base-uri directive permits all origins (*). "
                    "A <base href> tag can redirect all relative URLs to an "
                    "attacker-controlled origin."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Change base-uri to 'self' or 'none'.",
                framework=_FA["csp_base_uri_wildcard"],
            )]
        return [_finding(
            title="CSP missing base-uri directive",
            description=(
                "The Content-Security-Policy has no base-uri directive. "
                "Without it, an injected <base href='https://evil.example/'> tag "
                "can redirect all relative URLs to an attacker-controlled origin, "
                "enabling credential harvesting."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation="Add: base-uri 'self' to your Content-Security-Policy.",
            framework=_FA["csp_base_uri_missing"],
        )]

    def _check_form_action(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """form-action limits where forms may be submitted."""
        if "form-action" in d:
            sources = [s.lower() for s in d["form-action"]]
            if "*" not in sources:
                return []
            return [_finding(
                title="CSP form-action allows wildcard",
                description=(
                    "The CSP form-action directive allows submission to any origin (*). "
                    "An attacker with XSS or HTML injection can redirect form submissions "
                    "to an exfiltration endpoint."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence=ev,
                remediation="Change form-action to 'self' or an explicit allow-list.",
                framework=_FA["csp_form_action_wildcard"],
            )]
        return [_finding(
            title="CSP missing form-action directive",
            description=(
                "The Content-Security-Policy has no form-action directive. "
                "Without it, form submissions are not restricted by CSP, "
                "allowing injected forms to exfiltrate data to any origin."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            remediation="Add: form-action 'self' to your Content-Security-Policy.",
            framework=_FA["csp_form_action_missing"],
        )]

    def _check_script_src_data(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """data: / blob: in script-src permits JS execution via data URIs."""
        script_sources = d.get("script-src", d.get("default-src", []))
        findings: list[Finding] = []

        if _src_value_contains(script_sources, _DATA_URI_RE):
            findings.append(_finding(
                title="CSP script-src allows data: URIs",
                description=(
                    "The CSP script-src (or default-src) directive includes 'data:'. "
                    "This allows JavaScript to be executed via "
                    "<script src='data:text/javascript,...'>, completely bypassing "
                    "the intent of the CSP script restriction."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation="Remove 'data:' from script-src. Use nonces or hashes instead.",
                framework=_FA["csp_script_data"],
            ))

        if _src_value_contains(script_sources, _BLOB_URI_RE):
            findings.append(_finding(
                title="CSP script-src allows blob: URIs",
                description=(
                    "The CSP script-src directive includes 'blob:'. "
                    "Blob URLs can wrap arbitrary JavaScript, allowing script "
                    "execution that bypasses URL-based CSP checks."
                ),
                severity=Severity.HIGH,
                url=url,
                evidence=ev,
                remediation="Remove 'blob:' from script-src.",
                framework=_FA["csp_script_blob"],
            ))

        return findings

    def _check_script_src_http(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """Explicit http: source in script-src loads scripts over plaintext."""
        script_sources = d.get("script-src", d.get("default-src", []))
        if not _src_value_contains(script_sources, _HTTP_SRC_RE):
            return []
        return [_finding(
            title="CSP script-src includes http: scheme",
            description=(
                "The CSP script-src directive explicitly allows scripts loaded "
                "via unencrypted HTTP (http:). Scripts loaded over HTTP can be "
                "intercepted and modified by a network attacker."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            remediation=(
                "Remove 'http:' from script-src. Use 'https:' or explicit "
                "HTTPS origins only."
            ),
            framework=_FA["csp_script_http"],
        )]

    def _check_frame_ancestors(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        """frame-ancestors is the CSP replacement for X-Frame-Options."""
        if "frame-ancestors" in d:
            sources = [s.lower() for s in d["frame-ancestors"]]
            if "*" in sources:
                return [_finding(
                    title="CSP frame-ancestors allows any origin",
                    description=(
                        "The CSP frame-ancestors directive permits all origins (*) "
                        "to embed this page in a frame, making it vulnerable to "
                        "clickjacking attacks."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=ev,
                    remediation="Change frame-ancestors to 'self' or 'none'.",
                    framework=_FA["csp_frame_ancestors_wildcard"],
                )]
            return []
        return [_finding(
            title="CSP missing frame-ancestors directive",
            description=(
                "The Content-Security-Policy does not include a frame-ancestors "
                "directive. frame-ancestors is the modern replacement for "
                "X-Frame-Options and controls which origins may embed this page. "
                "Without it, clickjacking protection relies solely on the "
                "X-Frame-Options header."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Add: frame-ancestors 'self' (or 'none' if framing is not needed)."
            ),
            framework=_FA["csp_frame_ancestors_missing"],
        )]


    def _check_reporting(
        self, d: dict[str, list[str]], url: str, ev: Evidence
    ) -> list[Finding]:
        # A CSP without report-uri or report-to (and a matching Reporting-Endpoints
        # header) silently drops violation reports. The team will never know if
        # a real attacker triggers a block — or if a deploy is breaking the page
        # for visitors.
        has_report_uri = "report-uri" in d
        has_report_to  = "report-to"  in d
        if has_report_uri or has_report_to:
            return []
        return [_finding(
            title="CSP isn't reporting violations anywhere",
            description=(
                "Your CSP is in place but doesn't include `report-uri` or `report-to`. That means "
                "you never see when the policy blocks something — neither real attacks nor your "
                "own deployments that break the page. Without reports, tuning the policy is "
                "guesswork."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            remediation=(
                "Add a reporting endpoint:\n"
                "  Content-Security-Policy: default-src 'self'; report-uri /csp-violation;\n"
                "Or the modern equivalent, which requires a matching Reporting-Endpoints header:\n"
                "  Reporting-Endpoints: csp-endpoint=\"/csp-violation\"\n"
                "  Content-Security-Policy: default-src 'self'; report-to csp-endpoint;\n"
                "Services like Sentry, Datadog, and report-uri.com aggregate the reports for you."
            ),
            confidence=0.85,
            framework=_FA["csp_no_reporting"],
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
