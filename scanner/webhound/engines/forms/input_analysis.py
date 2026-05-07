# WebHound — scanner/webhound/engines/forms/input_analysis.py
# Passive analysis of HTML input fields for sensitive data exposure patterns.
#
# Safe-mode: reads pre-extracted PageArtifacts. No submission, no injection,
# no fuzzing, no active probing of any kind.

from __future__ import annotations

import re
from urllib.parse import urlparse

from webhound.core.extractor import ExtractedForm, FormInput, PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "input_analysis"

# ---------------------------------------------------------------------------
# Field name patterns
# ---------------------------------------------------------------------------

_PAYMENT_FIELD_RE = re.compile(
    r"\b(?:card(?:_?num(?:ber)?|_?no|holder|_?type)?|"
    r"cc[-_]?num(?:ber)?|credit[-_]?card|"
    r"pan\b|cvv\b|cvc2?\b|"
    r"expiry|exp[-_]?(?:month|year|date|mm|yy)|"
    r"billing[-_]?(?:name|address|zip)|"
    r"payment[-_]?method)\b",
    re.I,
)

_SSN_FIELD_RE = re.compile(
    r"\b(?:ssn\b|social[-_]?security(?:[-_]?num(?:ber)?)?|"
    r"tax[-_]?id\b|ein\b|itin\b|"
    r"national[-_]?id(?:[-_]?num(?:ber)?)?|"
    r"id[-_]?number|identity[-_]?num(?:ber)?)\b",
    re.I,
)

_ADMIN_DEBUG_FIELD_RE = re.compile(
    r"\b(?:debug(?:[-_]?mode)?|test[-_]?mode|"
    r"admin[-_]?(?:key|pass(?:word)?|token|override)|"
    r"bypass|superuser|sudo|"
    r"internal[-_]?(?:key|token|flag)|"
    r"backdoor|secret[-_]?key)\b",
    re.I,
)

_REDIRECT_PARAM_RE = re.compile(
    r"\b(?:redirect(?:[-_]?(?:url|uri|to))?|"
    r"next(?:[-_]?url)?|"
    r"goto\b|return(?:[-_]?(?:url|uri|to))?|"
    r"forward(?:[-_]?url)?|"
    r"continue(?:[-_]?url)?|"
    r"destination|target[-_]?url|"
    r"callback(?:[-_]?url)?)\b",
    re.I,
)

_TOKEN_SESSION_FIELD_RE = re.compile(
    r"\b(?:session(?:[-_]?(?:id|key|token))?|"
    r"auth(?:[-_]?token)?|"
    r"access[-_]?token|"
    r"refresh[-_]?token|"
    r"api[-_]?(?:key|token|secret)|"
    r"bearer[-_]?token|"
    r"jwt\b|id[-_]?token|"
    r"client[-_]?secret)\b",
    re.I,
)

# Hidden fields whose names suggest a secret value being passed through the form.
_UNSAFE_HIDDEN_NAME_RE = re.compile(
    r"\b(?:secret|private[-_]?key|api[-_]?(?:key|secret)|"
    r"access[-_]?token|auth(?:[-_]?token)?|"
    r"client[-_]?secret|signing[-_]?key)\b",
    re.I,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matching_inputs(form: ExtractedForm, pattern: re.Pattern[str]) -> list[FormInput]:
    return [i for i in form.inputs if i.name and pattern.search(i.name)]


def _input_list_summary(inputs: list[FormInput]) -> str:
    return ", ".join(
        f'<input type="{i.input_type}" name="{i.name}">'
        for i in inputs[:6]
        if i.name
    )


def _form_location(form: ExtractedForm, page_url: str) -> str:
    action_str = form.action_url or form.action or "(no action)"
    return f'{page_url} — form action="{action_str}"'


# ---------------------------------------------------------------------------
# Per-form checks — each returns 0 or 1 Finding
# ---------------------------------------------------------------------------


def _check_payment_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _PAYMENT_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Payment card fields detected in form",
        description=(
            f"The form contains input fields with names associated with payment card data: "
            f"{', '.join(repr(n) for n in names[:5])}. "
            "Forms that collect raw card data must comply with PCI-DSS. "
            "Consider using a tokenisation provider (Stripe Elements, Braintree, etc.) "
            "to avoid handling card data directly."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(matches),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"payment_fields": names},
        )],
        confidence=0.85,
        remediation=(
            "Replace direct card collection with a PCI-DSS compliant tokenisation "
            "solution. Card data should never be transmitted to or stored on your own "
            "servers unless you are PCI-DSS certified. Verify TLS is enforced on all "
            "pages that display these forms."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A05:2021"],
            cwe_ids=["CWE-312", "CWE-200"],
            nist_controls=["SC-28", "SC-8"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "payment_fields": names},
    )


def _check_ssn_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _SSN_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Government ID / SSN field detected in form",
        description=(
            f"The form collects fields whose names suggest government identification numbers "
            f"(SSN, tax ID, national ID): {', '.join(repr(n) for n in names[:5])}. "
            "Collection of national ID numbers is regulated in many jurisdictions "
            "(GDPR, CCPA, HIPAA). Transmission and storage must be appropriately protected."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(matches),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"id_fields": names},
        )],
        confidence=0.8,
        remediation=(
            "Ensure collection of government IDs is legally required and documented. "
            "Encrypt these fields in transit (TLS) and at rest. "
            "Apply the principle of data minimisation — collect only what is necessary "
            "and delete it when no longer required."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021"],
            cwe_ids=["CWE-312", "CWE-359"],
            nist_controls=["SC-28", "SC-8", "MP-6"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "id_fields": names},
    )


def _check_admin_debug_params(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _ADMIN_DEBUG_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Admin or debug parameters in form inputs",
        description=(
            f"The form contains input fields with names suggesting administrative or "
            f"debug functionality: {', '.join(repr(n) for n in names[:5])}. "
            "Exposing debug or admin parameters in public-facing HTML may allow "
            "an attacker to enable debug modes, bypass checks, or escalate privileges "
            "by manipulating these values."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(matches),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"admin_fields": names},
        )],
        confidence=0.75,
        remediation=(
            "Remove debug and admin parameters from public-facing HTML forms. "
            "Administrative functionality should be gated by server-side authentication, "
            "not controllable via client-supplied form fields."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A01:2021", "A05:2021"],
            cwe_ids=["CWE-284", "CWE-749"],
            nist_controls=["AC-3", "CM-7"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "admin_fields": names},
    )


def _check_redirect_params(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _REDIRECT_PARAM_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Open redirect parameter in form input",
        description=(
            f"The form contains input fields with names commonly used for redirect "
            f"parameters: {', '.join(repr(n) for n in names[:5])}. "
            "If submitted values are used to redirect users without strict validation, "
            "an attacker can redirect victims to phishing pages after login or other actions."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(matches),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"redirect_fields": names},
        )],
        confidence=0.7,
        remediation=(
            "Validate all redirect destinations server-side against an allowlist of "
            "trusted URLs or paths. Reject or ignore values pointing to external domains. "
            "Use relative paths for same-origin redirects wherever possible."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A01:2021"],
            cwe_ids=["CWE-601"],
            nist_controls=["SI-10"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "redirect_fields": names},
    )


def _check_token_session_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _TOKEN_SESSION_FIELD_RE)
    if not matches:
        return None
    # Exclude CSRF tokens — those are expected in forms
    non_csrf = [
        i for i in matches
        if i.name and not re.search(r"csrf", i.name, re.I)
    ]
    if not non_csrf:
        return None
    names = [i.name for i in non_csrf if i.name]
    return Finding(
        title="Session or authentication token exposed in form field",
        description=(
            f"The form includes fields with names suggesting session or authentication "
            f"tokens: {', '.join(repr(n) for n in names[:5])}. "
            "Exposing tokens in HTML form fields makes them readable to any JavaScript "
            "running on the page (XSS attacks), browser extensions, and page source viewers."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(non_csrf),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"token_fields": names},
        )],
        confidence=0.75,
        remediation=(
            "Do not embed session tokens or authentication credentials in HTML form fields. "
            "Use HttpOnly, Secure cookies for session management. "
            "If a token must be passed via form, scope it narrowly and rotate it after use."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A07:2021"],
            cwe_ids=["CWE-200", "CWE-522"],
            nist_controls=["IA-5", "SC-28"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "token_fields": names},
    )


def _check_unsafe_hidden_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = [
        i for i in form.inputs
        if i.input_type == "hidden"
        and i.name
        and _UNSAFE_HIDDEN_NAME_RE.search(i.name)
    ]
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Secret or key material in hidden form field",
        description=(
            f"Hidden form fields with names suggesting key or secret material were found: "
            f"{', '.join(repr(n) for n in names[:5])}. "
            "Hidden fields are visible to any user who views page source, and their "
            "values can be read or replaced by browser extensions and injected scripts."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(matches),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"unsafe_hidden_fields": names},
        )],
        confidence=0.8,
        remediation=(
            "Move secret or key material to server-side session storage. "
            "Hidden form fields are appropriate for non-sensitive state (form step, "
            "item IDs) but not for secrets that must remain confidential."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A05:2021"],
            cwe_ids=["CWE-200", "CWE-522", "CWE-312"],
            nist_controls=["SC-28"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "unsafe_hidden_fields": names},
    )


def _check_file_upload_inputs(form: ExtractedForm, page_url: str) -> Finding | None:
    upload_inputs = [i for i in form.inputs if i.input_type == "file"]
    if not upload_inputs:
        return None
    names = [i.name or "(unnamed)" for i in upload_inputs]
    return Finding(
        title="File upload input field present",
        description=(
            "A file upload input field was detected. File upload inputs require "
            "strict server-side validation to prevent malware upload, stored XSS "
            "via SVG/HTML files, and path traversal. "
            "This finding is informational — validate that server-side controls are in place."
        ),
        severity=Severity.LOW,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_input_list_summary(upload_inputs),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"upload_field_names": names},
        )],
        confidence=0.9,
        remediation=(
            "Validate file type by magic bytes (not just extension), enforce size limits, "
            "reject executable or script content types, and store uploaded files outside "
            "the web root. Use a virus scanner for user-supplied uploads."
        ),
        framework=FrameworkAlignment(
            owasp_top10=["A04:2021"],
            cwe_ids=["CWE-434"],
            nist_controls=["SI-3"],
        ),
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "upload_fields": names},
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_INPUT_CHECKS = [
    _check_payment_fields,
    _check_ssn_fields,
    _check_admin_debug_params,
    _check_redirect_params,
    _check_token_session_fields,
    _check_unsafe_hidden_fields,
    _check_file_upload_inputs,
]


class InputAnalysisEngine:
    """Passive analysis of HTML input fields for sensitive data exposure.

    Analyses field names in pre-extracted forms to identify patterns associated
    with payment card data, government IDs, authentication tokens, open redirects,
    and other high-risk input categories. No form submission or active probing.

    Call ``analyze(artifacts)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not artifacts.forms:
            return []
        findings: list[Finding] = []
        for form in artifacts.forms:
            for check in _INPUT_CHECKS:
                finding = check(form, artifacts.url)
                if finding is not None:
                    findings.append(finding)
        return findings
