# WebHound — scanner/webhound/engines/forms/form_risk.py
# Passive analysis of HTML forms for security misconfigurations.
#
# Safe-mode: reads pre-extracted PageArtifacts only. No form submission,
# no active probing, no exploitation, no credential testing.

from __future__ import annotations

import re
from urllib.parse import urlparse

from webhound.core.extractor import ExtractedForm, PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "form_risk"

# Input names that suggest a form carries credentials.
_CREDENTIAL_NAME_RE = re.compile(
    r"\b(?:password|passwd|pass(?:phrase)?|pwd|pin)\b",
    re.I,
)

# Input names that suggest a payment form.
_PAYMENT_NAME_RE = re.compile(
    r"\b(?:card(?:_?num(?:ber)?|_?no|holder)?|cc[-_]?num(?:ber)?|"
    r"credit[-_]?card|pan|cvv|cvc2?|expiry|exp[-_]?(?:month|year|date))\b",
    re.I,
)

# Hidden input names that carry sensitive values (exclude CSRF tokens).
_HIDDEN_SENSITIVE_NAME_RE = re.compile(
    r"\b(?:password|passwd|secret|api[-_]?key|"
    r"access[-_]?token|private[-_]?key|"
    r"session(?:_id)?|auth(?:_token)?|"
    r"ssn|credit[-_]?card|cvv|cvc)\b",
    re.I,
)

# Action URL patterns that suggest a non-production or risky endpoint.
_SUSPICIOUS_ACTION_RE = re.compile(
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|"
    r"/debug|/staging|/test(?:ing)?|/dev(?:elopment)?|/internal|"
    r"/api/admin|/admin/api)",
    re.I,
)

_HIDDEN_INPUTS_THRESHOLD = 7


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scheme(url: str) -> str:
    return urlparse(url).scheme.lower()


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _form_summary(form: ExtractedForm) -> str:
    action_str = form.action_url or form.action or "(none)"
    fields = ", ".join(
        f"{i.name}({i.input_type})"
        for i in form.inputs[:8]
        if i.name and i.input_type not in ("submit", "button", "image", "reset")
    )
    return f'action="{action_str}" method="{form.method}"\nFields: {fields or "(none)"}'


def _has_credential_input(form: ExtractedForm) -> bool:
    if form.has_password_field:
        return True
    return any(
        i.name and _CREDENTIAL_NAME_RE.search(i.name)
        for i in form.inputs
    )


def _has_payment_input(form: ExtractedForm) -> bool:
    return any(
        i.name and _PAYMENT_NAME_RE.search(i.name)
        for i in form.inputs
    )


def _hidden_inputs(form: ExtractedForm) -> list:
    return [i for i in form.inputs if i.input_type == "hidden"]


def _has_substantive_inputs(form: ExtractedForm) -> bool:
    """True when the form has at least one non-submit/button input."""
    return any(
        i.input_type not in ("submit", "button", "image", "reset", "hidden")
        for i in form.inputs
    )


# ---------------------------------------------------------------------------
# Per-form checks — each returns 0 or 1 Finding
# ---------------------------------------------------------------------------


def _check_password_over_http(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.has_password_field:
        return None
    if _scheme(page_url) != "http":
        return None
    return Finding(
        title="Password field on HTTP page",
        description=(
            "A form containing a password field is served over an unencrypted HTTP "
            "connection. Any credentials entered are transmitted in plaintext and are "
            "trivially interceptable by a network attacker. This applies regardless of "
            "whether the form's action URL uses HTTPS."
        ),
        severity=Severity.CRITICAL,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"method": form.method, "action": form.action_url},
        )],
        confidence=0.95,
        remediation=(
            "Enable HTTPS site-wide and redirect all HTTP traffic to HTTPS. "
            "Obtain a TLS certificate via Let's Encrypt or a commercial CA. "
            "Set HSTS to prevent future downgrade attacks."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A05:2021"],
            cwe_ids=["CWE-319", "CWE-523"],
            nist_controls=["SC-8", "SC-28"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_action": form.action_url},
    )


def _check_http_action_downgrade(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.action_url:
        return None
    if _scheme(page_url) != "https":
        return None
    if _scheme(form.action_url) != "http":
        return None
    if not form.has_password_field:
        return None
    return Finding(
        title="HTTPS page submits password form to HTTP endpoint",
        description=(
            f"The form action '{form.action_url}' uses HTTP, causing credentials "
            "submitted from this HTTPS page to be sent unencrypted. The secure page "
            "origin provides a false sense of security — the POST body is exposed in "
            "transit once the request leaves the browser."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"action_url": form.action_url, "page_scheme": "https"},
        )],
        confidence=0.95,
        remediation=(
            "Change the form action URL to use HTTPS. Ensure the receiving endpoint "
            "only accepts HTTPS connections and redirects or rejects HTTP submissions."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021"],
            cwe_ids=["CWE-319", "CWE-523"],
            nist_controls=["SC-8"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "action_url": form.action_url},
    )


def _check_external_action(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.action_url:
        return None
    action_host = _hostname(form.action_url)
    page_host = _hostname(page_url)
    if not action_host or action_host == page_host:
        return None

    is_credential = _has_credential_input(form)
    is_payment = _has_payment_input(form)

    if is_credential or is_payment:
        data_type = "credentials" if is_credential else "payment card data"
        return Finding(
            title=f"Login/payment form submits {data_type} to external domain",
            description=(
                f"The form posts {data_type} to '{form.action_url}', which is on a "
                f"different domain than the page ('{page_host}'). This is a strong "
                "indicator of a payment skimmer or credential-harvesting injection. "
                "Legitimate forms on this page should post to the same origin."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.FORM,
            evidence=[Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=_form_summary(form),
                location=page_url,
                source_engine=_ENGINE,
                extra={
                    "action_host": action_host,
                    "page_host": page_host,
                    "has_password": form.has_password_field,
                    "has_payment_fields": is_payment,
                },
            )],
            confidence=0.85,
            remediation=(
                "Verify this form action is intentional. If unexpected, investigate "
                "for JavaScript injection or a compromised template. Legitimate third-party "
                "payment processors (Stripe, PayPal) should use their own hosted forms, "
                "not forms that POST card data directly to their domain."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021", "A03:2021"],
                cwe_ids=["CWE-601", "CWE-200"],
                nist_controls=["SI-10", "SC-8"],
            ),
            scanner_engine=_ENGINE,
            metadata={"page_url": page_url, "action_url": form.action_url, "action_host": action_host},
        )

    return Finding(
        title="Form submits data to external domain",
        description=(
            f"The form posts to '{form.action_url}', a domain different from "
            f"the page origin ('{page_host}'). While cross-origin form actions are "
            "sometimes legitimate (third-party services), unrecognised external "
            "destinations may indicate injected data-harvesting forms."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"action_host": action_host, "page_host": page_host},
        )],
        confidence=0.7,
        remediation=(
            "Review whether this external form action is intentional. "
            "Audit your site for injected forms or compromised third-party scripts "
            "that may have introduced this element."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A08:2021"],
            cwe_ids=["CWE-601"],
            nist_controls=["SI-10"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "action_url": form.action_url, "action_host": action_host},
    )


def _check_missing_csrf(form: ExtractedForm, page_url: str) -> Finding | None:
    if form.method != "POST":
        return None
    if form.has_csrf_token:
        return None
    if not _has_substantive_inputs(form):
        return None
    return Finding(
        title="POST form lacks observable CSRF protection",
        description=(
            "No CSRF token field was detected in this POST form. Without a CSRF token, "
            "an attacker can craft a malicious page that silently submits this form on "
            "behalf of an authenticated user. Note: token-based protections delivered "
            "via cookies (SameSite=Strict/Lax) or custom headers may not be visible "
            "in static HTML analysis."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"method": form.method, "has_csrf_token": False},
        )],
        confidence=0.7,
        remediation=(
            "Implement CSRF protection using the Synchronizer Token Pattern: include a "
            "cryptographically random hidden field (e.g., '_csrf_token') unique per session. "
            "Alternatively, use SameSite=Strict or SameSite=Lax cookies combined with "
            "custom request headers."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A01:2021"],
            cwe_ids=["CWE-352"],
            nist_controls=["SI-10"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_action": form.action_url},
    )


def _check_get_credentials(form: ExtractedForm, page_url: str) -> Finding | None:
    if form.method != "GET":
        return None
    if not _has_credential_input(form):
        return None
    return Finding(
        title="Credential field submitted via GET method",
        description=(
            "A form with a password or credential-like field uses the GET method, "
            "causing the submitted value to appear in the URL query string. "
            "Passwords in URLs are logged by web servers, proxies, and browser history, "
            "and may be leaked in Referer headers to third parties."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"method": "GET", "has_password": form.has_password_field},
        )],
        confidence=0.9,
        remediation=(
            "Change the form method to POST. Credential and authentication forms "
            "must always use POST to prevent secrets from appearing in URLs, "
            "server logs, browser history, or Referer headers."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021"],
            cwe_ids=["CWE-598", "CWE-200"],
            nist_controls=["IA-5", "SC-8"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_method": "GET"},
    )


def _check_file_upload(form: ExtractedForm, page_url: str) -> Finding | None:
    upload_inputs = [i for i in form.inputs if i.input_type == "file"]
    if not upload_inputs:
        return None
    field_names = [i.name or "(unnamed)" for i in upload_inputs]
    return Finding(
        title="File upload form detected",
        description=(
            "The form includes a file upload input, allowing arbitrary files to be "
            "submitted to the server. Without strict server-side validation of file "
            "type, size, and content, upload forms are a common vector for malware "
            "upload, path traversal, and stored XSS."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"upload_fields": field_names},
        )],
        confidence=0.9,
        remediation=(
            "Validate uploaded files server-side: check MIME type (not just extension), "
            "enforce maximum file size, strip metadata, and store files outside the web "
            "root with randomized names. Do not trust client-supplied content-type headers."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A04:2021"],
            cwe_ids=["CWE-434"],
            nist_controls=["SI-3", "CM-7"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "upload_field_names": field_names},
    )


def _check_hidden_sensitive_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    sensitive = [
        i for i in _hidden_inputs(form)
        if i.name and _HIDDEN_SENSITIVE_NAME_RE.search(i.name)
    ]
    if not sensitive:
        return None
    names = [i.name for i in sensitive if i.name]
    return Finding(
        title="Sensitive data in hidden form field",
        description=(
            f"The form contains hidden input fields with names suggesting sensitive data: "
            f"{', '.join(repr(n) for n in names[:5])}. "
            "Hidden fields are visible in the page source and can be tampered with by "
            "the client. Sensitive values like tokens, keys, or credentials should not "
            "be placed in hidden form fields."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"sensitive_hidden_fields": names},
        )],
        confidence=0.75,
        remediation=(
            "Store sensitive state server-side (session) rather than in hidden HTML fields. "
            "Hidden fields are trivially read and modified by users and browser extensions. "
            "For CSRF tokens, this is acceptable only if the value is unpredictable and "
            "validated server-side."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A05:2021"],
            cwe_ids=["CWE-200", "CWE-472"],
            nist_controls=["SC-28"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "hidden_fields": names},
    )


def _check_excessive_hidden_inputs(form: ExtractedForm, page_url: str) -> Finding | None:
    hidden = _hidden_inputs(form)
    if len(hidden) <= _HIDDEN_INPUTS_THRESHOLD:
        return None
    names = [i.name for i in hidden if i.name]
    return Finding(
        title="Unusually high number of hidden form inputs",
        description=(
            f"The form contains {len(hidden)} hidden input fields. "
            "Legitimate forms rarely require this many hidden fields. "
            "Excessive hidden inputs may indicate injected tracking payloads, "
            "data-harvesting scripts, or poorly designed state management."
        ),
        severity=Severity.LOW,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"hidden_count": len(hidden), "hidden_names": names[:10]},
        )],
        confidence=0.65,
        remediation=(
            "Review whether all hidden fields are necessary. Replace client-side "
            "hidden state with server-side session storage where appropriate. "
            "Audit the page for injected scripts that may be appending hidden fields."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"],
            cwe_ids=["CWE-200"],
            nist_controls=["CM-7"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "hidden_count": len(hidden)},
    )


def _check_suspicious_action_url(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.action_url:
        return None
    if not _SUSPICIOUS_ACTION_RE.search(form.action_url):
        return None
    return Finding(
        title="Form action URL points to suspicious or non-production endpoint",
        description=(
            f"The form action '{form.action_url}' appears to target a non-production, "
            "debug, or internal endpoint. Forms in production deployments should not "
            "submit data to localhost, staging, or debug paths."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"action_url": form.action_url},
        )],
        confidence=0.8,
        remediation=(
            "Update the form action to point to the correct production endpoint. "
            "Ensure CI/CD pipelines replace environment-specific URLs at deploy time."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"],
            cwe_ids=["CWE-200", "CWE-16"],
            nist_controls=["CM-6"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "action_url": form.action_url},
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_FORM_CHECKS = [
    _check_password_over_http,
    _check_http_action_downgrade,
    _check_external_action,
    _check_missing_csrf,
    _check_get_credentials,
    _check_file_upload,
    _check_hidden_sensitive_fields,
    _check_excessive_hidden_inputs,
    _check_suspicious_action_url,
]


class FormRiskEngine:
    """Passive analysis of HTML forms for structural security risks.

    Operates on pre-extracted :class:`PageArtifacts` without making any
    network requests or submitting forms. Detects insecure transmission,
    cross-origin posting, missing CSRF protection, and dangerous configurations.

    Call ``analyze(artifacts)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not artifacts.forms:
            return []
        findings: list[Finding] = []
        for form in artifacts.forms:
            for check in _FORM_CHECKS:
                finding = check(form, artifacts.url)
                if finding is not None:
                    findings.append(finding)
        return findings
