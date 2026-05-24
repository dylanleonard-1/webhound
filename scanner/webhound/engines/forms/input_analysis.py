# WebHound — scanner/webhound/engines/forms/input_analysis.py
# Passive analysis of HTML input fields for sensitive data exposure patterns.
#
# Safe-mode: reads pre-extracted PageArtifacts. No submission, no injection,
# no fuzzing, no active probing of any kind.

from __future__ import annotations

import re

from webhound.core.extractor import ExtractedForm, FormInput, PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
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

# Hidden-field VALUE patterns (for content-based detection, not just name-based)
_VALUE_URL_RE = re.compile(r"^https?://[^\s]+$", re.I)
_VALUE_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$")
_VALUE_CC_RE = re.compile(r"^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$")
_VALUE_SSN_RE = re.compile(r"^\d{3}[- ]?\d{2}[- ]?\d{4}$")
# Generic "API key" — long base64-ish string with mixed case + digits
_VALUE_API_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{32,}$")


# ---------------------------------------------------------------------------
# Framework / CVSS / compliance preset table
# ---------------------------------------------------------------------------

_FA: dict[str, FrameworkAlignment] = {
    "payment_fields": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-312", "CWE-200"],
        nist_controls=["SC-28", "SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        pci_dss=["3.5.1", "3.7.4", "8.3.1"],
        iso_27001=["A.8.20", "A.8.24"],
        soc2=["CC6.1", "CC6.7"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "ssn_fields": FrameworkAlignment(
        owasp_top10=["A02:2021"],
        cwe_ids=["CWE-312", "CWE-359"],
        nist_controls=["SC-28", "SC-8", "MP-6"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        pci_dss=[],
        iso_27001=["A.8.10", "A.8.24"],
        soc2=["CC6.1", "CC6.7"],
        hipaa=["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "admin_debug": FrameworkAlignment(
        owasp_top10=["A01:2021", "A05:2021"],
        cwe_ids=["CWE-284", "CWE-749"],
        nist_controls=["AC-3", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.6,
        pci_dss=["6.2.4", "7.2.1"],
        iso_27001=["A.5.15", "A.8.9"],
        soc2=["CC6.1", "CC6.3"],
        hipaa=["164.312(a)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "redirect_params": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "token_session": FrameworkAlignment(
        owasp_top10=["A02:2021", "A07:2021"],
        cwe_ids=["CWE-200", "CWE-522"],
        nist_controls=["IA-5", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        pci_dss=["8.3.1"],
        iso_27001=["A.5.17", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=["164.312(d)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "unsafe_hidden": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-200", "CWE-522", "CWE-312"],
        nist_controls=["SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=7.5,
        pci_dss=["8.3.1"],
        iso_27001=["A.8.5", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=["164.312(a)(2)(i)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "file_upload_input": FrameworkAlignment(
        owasp_top10=["A04:2021"],
        cwe_ids=["CWE-434"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cvss_score=6.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC6.6"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hidden_url_value": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hidden_credential_value": FrameworkAlignment(
        owasp_top10=["A02:2021", "A07:2021"],
        cwe_ids=["CWE-200", "CWE-522", "CWE-798"],
        nist_controls=["IA-5", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        pci_dss=["3.5.1", "8.3.1"],
        iso_27001=["A.5.17", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=["164.312(a)(2)(i)", "164.312(d)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
}


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


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum — used to reduce CC false positives."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Per-form checks — each returns 0 or 1 Finding
# ---------------------------------------------------------------------------


def _check_payment_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _PAYMENT_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Form collects credit-card data directly",
        description=(
            f"The form has fields ({', '.join(repr(n) for n in names[:5])}) that "
            "collect raw payment-card details. Handling card data on your own "
            "infrastructure puts the site inside PCI DSS scope, with all the "
            "annual audit and quarterly scanning that comes with it. Most "
            "merchants offload this entirely to a payment processor — Stripe, "
            "Adyen, Braintree, etc — so card data never touches their servers."
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
            "Switch to a hosted-fields or iframe-based payment integration "
            "(Stripe Elements, Adyen Drop-in, Braintree Hosted Fields). These "
            "submit card data directly to the processor over a separate domain, "
            "dropping the site from PCI DSS SAQ A-EP / D scope down to SAQ A. "
            "If you must collect cards directly, make absolutely sure TLS is "
            "enforced on every page in the funnel, the card number is never "
            "logged, and the data is tokenised before it reaches storage."
        ),
        framework=_FA["payment_fields"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "payment_fields": names},
    )


def _check_ssn_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _SSN_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Form asks for a government ID (SSN, tax ID, national ID)",
        description=(
            f"Fields detected: {', '.join(repr(n) for n in names[:5])}. "
            "These map to highly regulated personal data — SSN, EIN, ITIN, "
            "national identity numbers. GDPR treats them as a special category "
            "in many member states, HIPAA classifies them as PHI when collected "
            "alongside health data, and state breach-notification laws (e.g. "
            "California SB-1386, NY SHIELD) trigger mandatory disclosure if "
            "they leak. The risk isn't that you collected them — it's whether "
            "the rest of the system is built to handle that responsibility."
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
            "Confirm that collecting these IDs is legally required (not just "
            "convenient) and that the privacy policy says so explicitly. Encrypt "
            "the field at rest using application-layer encryption — not just "
            "database transparent encryption — so a compromised DB read doesn't "
            "expose the cleartext. Mask the value in logs and admin UIs (e.g. "
            "show only the last four digits). Set a retention window and delete "
            "the value when the business reason for holding it expires."
        ),
        framework=_FA["ssn_fields"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "id_fields": names},
    )


def _check_admin_debug_params(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _ADMIN_DEBUG_FIELD_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Form exposes an admin or debug parameter",
        description=(
            f"Public HTML contains an input named {', '.join(repr(n) for n in names[:5])}. "
            "Field names like `admin_override`, `debug_mode`, `bypass`, and "
            "`sudo` suggest the server-side code may branch on a value the "
            "user can edit freely. If that branch grants extra access, switches "
            "off authentication, or enables verbose error output, an attacker "
            "only has to flip the value in browser dev tools to abuse it."
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
            "Remove the field from the public form entirely. Admin and debug "
            "features must be gated by server-side role checks, not by a value "
            "the client supplies. If the field is purely decorative (legacy "
            "template artifact), delete it — leaving it in invites both auditors "
            "and attackers to assume it does something."
        ),
        framework=_FA["admin_debug"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "admin_fields": names},
    )


def _check_redirect_params(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _REDIRECT_PARAM_RE)
    if not matches:
        return None
    names = [i.name for i in matches if i.name]
    return Finding(
        title="Form has a redirect / next-URL parameter",
        description=(
            f"Field(s) found: {', '.join(repr(n) for n in names[:5])}. "
            "Post-submit redirect parameters are convenient — they let the app "
            "send the user back where they came from — but they're a classic "
            "open-redirect sink. If the server does `redirect(request.form['next'])` "
            "without checking the destination, an attacker can craft a phishing "
            "link like `…/login?next=https://evil.example/fake-bank` so the "
            "victim lands on their fake page right after typing a real password."
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
            "Validate the destination server-side: accept only relative paths "
            "starting with `/`, or absolute URLs that match a strict allowlist "
            "of your own domains. Reject `//evil.example` (protocol-relative) "
            "and `javascript:` URLs explicitly. A useful pattern: hash-sign the "
            "next-URL when issuing it and verify the signature on the way back."
        ),
        framework=_FA["redirect_params"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "redirect_fields": names},
    )


def _check_token_session_fields(form: ExtractedForm, page_url: str) -> Finding | None:
    matches = _matching_inputs(form, _TOKEN_SESSION_FIELD_RE)
    if not matches:
        return None
    non_csrf = [
        i for i in matches
        if i.name and not re.search(r"csrf", i.name, re.I)
    ]
    if not non_csrf:
        return None
    names = [i.name for i in non_csrf if i.name]
    return Finding(
        title="Form exposes a session or auth token in plain HTML",
        description=(
            f"Fields look like session/auth tokens: {', '.join(repr(n) for n in names[:5])}. "
            "Tokens written into form fields are inside the DOM — any JavaScript "
            "on the page can read them, any browser extension can read them, "
            "and they show up in `view-source`. That defeats the main reason "
            "session cookies are marked HttpOnly: keeping them out of reach "
            "of JavaScript. Stored XSS on this page would mean immediate "
            "account takeover."
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
            "Move authentication state into `HttpOnly; Secure; SameSite=Lax` "
            "cookies. If a token genuinely has to travel through a form (for "
            "example a one-time email-confirmation link redirecting through "
            "a POST), scope it narrowly: single-use, short-lived, server-side "
            "revocation on consumption."
        ),
        framework=_FA["token_session"],
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
        title="Hidden field name suggests it carries a secret",
        description=(
            f"Hidden inputs with names that look like secret material: "
            f"{', '.join(repr(n) for n in names[:5])}. The word \"hidden\" in "
            "`<input type=\"hidden\">` is purely about the visual UI — the value "
            "is right there in the page source, readable by browser dev tools "
            "and any JavaScript on the page. A field named `signing_key` or "
            "`api_secret` rarely belongs in a form that loaded over the public "
            "internet."
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
            "Keep the secret server-side, in session state. If the user does "
            "need to round-trip something between requests, pass an opaque, "
            "unguessable session token and look the real value up server-side. "
            "Non-secret form state (a record ID, a step number) is fine in a "
            "hidden field — but only if the server treats it as untrusted input."
        ),
        framework=_FA["unsafe_hidden"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "unsafe_hidden_fields": names},
    )


def _check_file_upload_inputs(form: ExtractedForm, page_url: str) -> Finding | None:
    upload_inputs = [i for i in form.inputs if i.input_type == "file"]
    if not upload_inputs:
        return None
    names = [i.name or "(unnamed)" for i in upload_inputs]
    return Finding(
        title="File upload input is present",
        description=(
            "An `<input type=\"file\">` element accepts user-supplied files. "
            "By itself this is fine — the risk lives entirely in what the "
            "server does with the file. The most common failure modes are "
            "trusting the client-supplied Content-Type, allowing executable "
            "or scriptable file types (.html, .svg, .php), and storing the "
            "upload under the web root with a predictable name. This finding "
            "is informational; pair it with a manual review of the upload "
            "handler."
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
            "On the server side: detect the real file type by reading the "
            "first bytes (magic-number check), not by trusting the extension "
            "or the Content-Type header. Enforce a size limit. Store uploads "
            "outside the web root with a random filename. Serve them back "
            "with `Content-Disposition: attachment` and a safe Content-Type "
            "so the browser can't auto-execute them. For images, re-encode "
            "rather than storing the upload byte-for-byte."
        ),
        framework=_FA["file_upload_input"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "upload_fields": names},
    )


def _check_hidden_field_url_values(form: ExtractedForm, page_url: str) -> Finding | None:
    """A hidden field with a default value that's a full external URL."""
    url_hidden = [
        i for i in form.inputs
        if i.input_type == "hidden"
        and i.name
        and i.value
        and _VALUE_URL_RE.match(i.value.strip())
    ]
    if not url_hidden:
        return None
    items = [(i.name, i.value) for i in url_hidden if i.name and i.value]
    return Finding(
        title="Hidden field is pre-filled with an external URL",
        description=(
            f"A hidden form field carries a fully-qualified URL as its default "
            f"value (e.g. {items[0][0]}={items[0][1]!r}). If this value drives a "
            "post-submit redirect, an attacker who can influence the page (an "
            "injected ad, a stored XSS, a tampered CDN response) can swap it "
            "for an attacker-controlled URL and send users to a phishing page "
            "after they submit. Even without injection, the absolute URL in "
            "the form gives away routing/architecture information."
        ),
        severity=Severity.MEDIUM,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content="\n".join(f'name="{n}" value="{v[:120]}"' for n, v in items[:5]),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={"url_hidden_fields": [n for n, _ in items]},
        )],
        confidence=0.7,
        remediation=(
            "Don't write absolute URLs into hidden fields. If the form needs "
            "to remember a destination, use a relative path (`/account/profile`) "
            "or store a short opaque key server-side and look the destination "
            "up after submit. If absolute URLs are unavoidable, validate them "
            "against an allowlist before redirecting."
        ),
        framework=_FA["hidden_url_value"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "url_hidden_fields": [n for n, _ in items]},
    )


def _check_hidden_field_credential_values(form: ExtractedForm, page_url: str) -> Finding | None:
    """A hidden field whose VALUE looks like a credential or sensitive identifier."""
    hits: list[tuple[str, str, str]] = []  # (name, value, kind)
    for i in form.inputs:
        if i.input_type != "hidden" or not i.value:
            continue
        v = i.value.strip()
        if not v or len(v) < 8:
            continue
        if _VALUE_JWT_RE.match(v):
            hits.append((i.name or "(unnamed)", v, "JWT"))
            continue
        # CC: pattern match + Luhn to cut false positives on order IDs etc.
        if _VALUE_CC_RE.match(v) and _luhn_valid(v):
            hits.append((i.name or "(unnamed)", v, "credit_card"))
            continue
        if _VALUE_SSN_RE.match(v) and not v.startswith(("000", "666", "9")):
            hits.append((i.name or "(unnamed)", v, "ssn"))
            continue
        # Generic API key — require BOTH letters AND digits to skip pure hashes
        if (_VALUE_API_KEY_RE.match(v)
                and any(c.isalpha() for c in v)
                and any(c.isdigit() for c in v)
                and not _VALUE_URL_RE.match(v)):
            hits.append((i.name or "(unnamed)", v, "api_key_like"))
    if not hits:
        return None

    def _mask(v: str) -> str:
        if len(v) <= 8:
            return "*" * len(v)
        return v[:4] + "*" * (len(v) - 8) + v[-4:]

    kinds = sorted({k for _, _, k in hits})
    return Finding(
        title="Hidden field value looks like a credential or PII",
        description=(
            f"At least one hidden form field has a default value matching a "
            f"sensitive-data pattern ({', '.join(kinds)}). Values are returned "
            "verbatim in the page source — anyone viewing the page can read "
            "them, browser extensions and JavaScript can read them, and any "
            "request that includes the page URL as a referer can leak them. "
            "Hidden form fields aren't a confidentiality boundary."
        ),
        severity=Severity.HIGH,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content="\n".join(
                f'name="{n}" kind={k} value="{_mask(v)}"' for n, v, k in hits[:5]
            ),
            location=_form_location(form, page_url),
            source_engine=_ENGINE,
            extra={
                "credential_hidden_fields": [
                    {"name": n, "kind": k} for n, _, k in hits
                ],
            },
        )],
        confidence=0.85,
        remediation=(
            "Strip the value out of the HTML. Sensitive data (JWTs, API keys, "
            "card numbers, SSNs) belongs in server-side session storage; the "
            "client gets an opaque reference (a short, unguessable session "
            "key) and the server resolves it on submit. If a JWT really must "
            "be sent down to the client, use an `HttpOnly` cookie so JavaScript "
            "and the page source can't see it."
        ),
        framework=_FA["hidden_credential_value"],
        scanner_engine=_ENGINE,
        metadata={
            "page_url": page_url,
            "credential_hidden_fields": [
                {"name": n, "kind": k} for n, _, k in hits
            ],
        },
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
    _check_hidden_field_url_values,
    _check_hidden_field_credential_values,
]


class InputAnalysisEngine:
    """Passive analysis of HTML input fields for sensitive data exposure.

    Analyses field names AND default values in pre-extracted forms to identify
    patterns associated with payment card data, government IDs, authentication
    tokens, open redirects, and other high-risk input categories. No form
    submission or active probing.

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
