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
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "form_risk"

_CREDENTIAL_NAME_RE = re.compile(
    r"\b(?:password|passwd|pass(?:phrase)?|pwd|pin)\b",
    re.I,
)

_PAYMENT_NAME_RE = re.compile(
    r"\b(?:card(?:_?num(?:ber)?|_?no|holder)?|cc[-_]?num(?:ber)?|"
    r"credit[-_]?card|pan|cvv|cvc2?|expiry|exp[-_]?(?:month|year|date))\b",
    re.I,
)

_HIDDEN_SENSITIVE_NAME_RE = re.compile(
    r"\b(?:password|passwd|secret|api[-_]?key|"
    r"access[-_]?token|private[-_]?key|"
    r"session(?:_id)?|auth(?:_token)?|"
    r"ssn|credit[-_]?card|cvv|cvc)\b",
    re.I,
)

_SUSPICIOUS_ACTION_RE = re.compile(
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|"
    r"/debug|/staging|/test(?:ing)?|/dev(?:elopment)?|/internal|"
    r"/api/admin|/admin/api)",
    re.I,
)

_HIDDEN_INPUTS_THRESHOLD = 7


# ---------------------------------------------------------------------------
# Framework / CVSS / compliance preset table
# Single source of truth — every finding pulls its `framework=` from here.
# ---------------------------------------------------------------------------

_FA: dict[str, FrameworkAlignment] = {
    "password_over_http": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-319", "CWE-523"],
        nist_controls=["SC-8", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        pci_dss=["3.7.4", "4.2.1"],
        iso_27001=["A.8.20", "A.8.24"],
        soc2=["CC6.1", "CC6.7"],
        hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "payment_over_http": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-319", "CWE-312"],
        nist_controls=["SC-8", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        pci_dss=["3.5.1", "4.2.1"],
        iso_27001=["A.8.20", "A.8.24"],
        soc2=["CC6.1", "CC6.7"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "http_action_downgrade": FrameworkAlignment(
        owasp_top10=["A02:2021"],
        cwe_ids=["CWE-319", "CWE-523"],
        nist_controls=["SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.6,
        pci_dss=["4.2.1"],
        iso_27001=["A.8.20"],
        soc2=["CC6.1"],
        hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "external_credential_action": FrameworkAlignment(
        owasp_top10=["A08:2021", "A03:2021"],
        cwe_ids=["CWE-601", "CWE-200", "CWE-829"],
        nist_controls=["SI-10", "SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.0,
        pci_dss=["6.4.3", "11.6.1"],
        iso_27001=["A.8.25", "A.8.28"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.312(c)(1)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "external_action": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-601", "CWE-829"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "missing_csrf": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-352"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        cvss_score=6.5,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC6.1"],
        hipaa=["164.312(c)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "get_credentials": FrameworkAlignment(
        owasp_top10=["A02:2021"],
        cwe_ids=["CWE-598", "CWE-200"],
        nist_controls=["IA-5", "SC-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=6.5,
        pci_dss=["8.3.1"],
        iso_27001=["A.5.17", "A.8.20"],
        soc2=["CC6.1"],
        hipaa=["164.312(d)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "file_upload": FrameworkAlignment(
        owasp_top10=["A04:2021"],
        cwe_ids=["CWE-434"],
        nist_controls=["SI-3", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cvss_score=6.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC6.6"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hidden_sensitive_field": FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-200", "CWE-472"],
        nist_controls=["SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["8.3.1"],
        iso_27001=["A.8.5"],
        soc2=["CC6.1"],
        hipaa=["164.312(a)(2)(i)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "excessive_hidden": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-200"],
        nist_controls=["CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=[],
        iso_27001=["A.8.9"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "suspicious_action": FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-200", "CWE-16"],
        nist_controls=["CM-6"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.9", "A.8.31"],
        soc2=["CC8.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
}


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
        title="Login form is served over plain HTTP",
        description=(
            "This page collects a password but is served over http:// instead of "
            "https://. Anyone on the same network as the user — a coffee-shop Wi-Fi, "
            "a hotel, an ISP, a corporate proxy — can read the password as it's "
            "typed and submitted. The form's `action=` attribute doesn't change "
            "this: the page itself was loaded insecurely, so an attacker can also "
            "rewrite the form to point anywhere they want."
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
            "Serve the entire site over HTTPS and redirect every http:// request to "
            "https://. Free certificates are available through Let's Encrypt. After "
            "the redirect is in place, set the HSTS header "
            "(`Strict-Transport-Security: max-age=31536000; includeSubDomains`) so "
            "browsers refuse to load the site over plain HTTP again."
        ),
        framework=_FA["password_over_http"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_action": form.action_url},
    )


def _check_payment_over_http(form: ExtractedForm, page_url: str) -> Finding | None:
    """Catches payment-card forms on HTTP pages that don't have a password field."""
    if form.has_password_field:
        return None  # password check already fires
    if not _has_payment_input(form):
        return None
    if _scheme(page_url) != "http":
        return None
    payment_fields = [
        i.name for i in form.inputs
        if i.name and _PAYMENT_NAME_RE.search(i.name)
    ]
    return Finding(
        title="Payment form is served over plain HTTP",
        description=(
            f"This form collects credit-card data ({', '.join(repr(n) for n in payment_fields[:3])}) "
            "but the page is served over http:// rather than https://. Card numbers, "
            "expiry dates, and CVVs are sent in the clear, where anyone on the "
            "network can capture them. This is also a PCI DSS violation — the "
            "payment brands prohibit unencrypted transmission of cardholder data "
            "anywhere on the public internet."
        ),
        severity=Severity.CRITICAL,
        category=FindingCategory.FORM,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            content=_form_summary(form),
            location=page_url,
            source_engine=_ENGINE,
            extra={"payment_fields": payment_fields, "page_scheme": "http"},
        )],
        confidence=0.95,
        remediation=(
            "Move the entire payment flow onto HTTPS — and ideally don't collect "
            "raw card data at all. Use a tokenisation provider like Stripe Elements, "
            "Adyen Drop-in, or Braintree Hosted Fields so the card data goes directly "
            "from the user's browser to the processor, never touching your server. "
            "This drops the site from PCI DSS scope SAQ A-EP to SAQ A."
        ),
        framework=_FA["payment_over_http"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "payment_fields": payment_fields},
    )


def _check_http_action_downgrade(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.action_url:
        return None
    if _scheme(page_url) != "https":
        return None
    if _scheme(form.action_url) != "http":
        return None
    if not (form.has_password_field or _has_payment_input(form)):
        return None
    data_type = "password" if form.has_password_field else "card data"
    return Finding(
        title=f"Secure page submits {data_type} to an insecure HTTP URL",
        description=(
            f"The page itself loaded over HTTPS, but the form's action attribute "
            f"points to '{form.action_url}' — plain HTTP. The padlock in the "
            "browser is misleading: as soon as the user clicks submit, the form "
            "data leaves the encrypted page and travels in the clear. This is "
            "often a deployment mistake where one environment was upgraded to "
            "HTTPS but the endpoint URL wasn't updated."
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
            "Change the form's `action=` attribute to https://. Make sure the "
            "receiving endpoint only accepts HTTPS — otherwise an attacker can "
            "still force the downgrade. A common fix is using a protocol-relative "
            "or root-relative URL (e.g. `/login` instead of `http://example.com/login`)."
        ),
        framework=_FA["http_action_downgrade"],
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
        data_type = "credentials" if is_credential else "card data"
        return Finding(
            title=f"Form posts {data_type} to a different domain",
            description=(
                f"This form takes {data_type} but submits to '{form.action_url}' — "
                f"a different hostname than the page itself ('{page_host}'). That "
                "pattern is the textbook fingerprint of a card-skimmer or "
                "credential harvester. Legitimate payment processors like Stripe, "
                "Adyen, and Braintree use iframed forms on their own domain — they "
                "never accept a POST directly from a merchant page that contains "
                "raw card numbers."
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
                "Treat this as an incident until proven otherwise. Check the page "
                "template, recently merged CMS changes, and any third-party scripts "
                "that ran on this page. If the destination domain is unfamiliar, "
                "look it up — many skimmer domains are registered days before they "
                "appear. Compare the form's HTML against a known-good template."
            ),
            framework=_FA["external_credential_action"],
            scanner_engine=_ENGINE,
            metadata={"page_url": page_url, "action_url": form.action_url, "action_host": action_host},
        )

    return Finding(
        title="Form submits to a different domain",
        description=(
            f"The form posts to '{form.action_url}', which is a different host "
            f"than the page itself ('{page_host}'). Cross-origin form actions are "
            "sometimes legitimate — newsletter signups, search engines, embedded "
            "third-party tools — but unrecognised destinations are worth a manual "
            "review. Attackers often inject a hidden form pointing to an exfiltration "
            "endpoint, then trigger its submission from JavaScript on the page."
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
            "Confirm the destination domain is on your approved-vendor list. If "
            "you don't recognise it, audit the page source for injected `<form>` "
            "tags and check the change history for the template. Consider locking "
            "down `form-action` in your Content Security Policy."
        ),
        framework=_FA["external_action"],
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
        title="POST form has no visible CSRF token",
        description=(
            "This form submits via POST but doesn't include a hidden CSRF token "
            "field that we can see. Without one, an attacker can host a malicious "
            "page that auto-submits this form using the visitor's logged-in cookies — "
            "changing the victim's email, transferring funds, or anything else "
            "this form does. Note: if the app uses SameSite=Strict cookies or "
            "validates a custom request header, that protection is invisible to a "
            "static HTML scan and the finding may be a false positive."
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
            "Add a hidden input containing a per-session cryptographically-random "
            "token (commonly named `_csrf` or `authenticity_token`) and verify it "
            "server-side on every state-changing request. Most modern frameworks "
            "(Django, Rails, Laravel, ASP.NET) ship this protection built-in — "
            "make sure it's enabled rather than disabled per-route. Combine with "
            "`SameSite=Lax` or `Strict` cookies for defence in depth."
        ),
        framework=_FA["missing_csrf"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_action": form.action_url},
    )


def _check_get_credentials(form: ExtractedForm, page_url: str) -> Finding | None:
    if form.method != "GET":
        return None
    if not _has_credential_input(form):
        return None
    return Finding(
        title="Password is sent in the URL via GET",
        description=(
            "This login-style form uses GET, which means the submitted password "
            "ends up in the URL itself (e.g. `…/login?password=hunter2`). URLs "
            "are logged by web-server access logs, CDN logs, proxy servers, browser "
            "history, and bookmarks — and they're leaked to any external site the "
            "page links to via the Referer header. Treat any password that's ever "
            "been transmitted this way as compromised."
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
            "Change `method=\"GET\"` to `method=\"POST\"`. The server side must also "
            "reject password parameters arriving in the query string. After deploying "
            "the fix, rotate any passwords that may have been transmitted by GET in "
            "the past, and scrub the credential values from log retention systems."
        ),
        framework=_FA["get_credentials"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "form_method": "GET"},
    )


def _check_file_upload(form: ExtractedForm, page_url: str) -> Finding | None:
    upload_inputs = [i for i in form.inputs if i.input_type == "file"]
    if not upload_inputs:
        return None
    field_names = [i.name or "(unnamed)" for i in upload_inputs]
    return Finding(
        title="Form accepts file uploads",
        description=(
            "The page exposes a `<input type=\"file\">` field that lets visitors "
            "upload arbitrary files to the server. File uploads are one of the most "
            "exploited features on the web — without strict server-side checks, "
            "attackers use them to upload web shells, serve malware to other "
            "visitors, or store cross-site scripting payloads inside SVG/HTML files. "
            "This is informational: the actual risk depends on what the server does "
            "with the file after it lands."
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
            "Confirm the server side: (1) validates file content by magic bytes, "
            "not just by extension or the client-supplied Content-Type; (2) enforces "
            "a maximum file size; (3) stores uploads outside the web root with a "
            "random filename so they can't be requested directly; (4) sets "
            "`Content-Disposition: attachment` and a restrictive Content-Type "
            "header when serving them back; and (5) strips EXIF/metadata. For "
            "user avatars, re-encode the image rather than storing the upload "
            "byte-for-byte."
        ),
        framework=_FA["file_upload"],
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
        title="Hidden form fields contain names that look like secrets",
        description=(
            f"Hidden inputs with sensitive-sounding names were found in this form: "
            f"{', '.join(repr(n) for n in names[:5])}. Hidden doesn't mean private — "
            "any user can view the page source or open browser dev tools and read "
            "(or change) the value. If the server trusts that value when the form "
            "comes back, an attacker can tamper with it freely."
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
            "Keep the actual secret server-side, in the session. Pass an opaque "
            "session reference if you must round-trip something through the form. "
            "CSRF tokens are the one legitimate exception to the rule — they're "
            "supposed to be unpredictable and validated on submit, so seeing a "
            "field named `_csrf` or similar is fine."
        ),
        framework=_FA["hidden_sensitive_field"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "hidden_fields": names},
    )


def _check_excessive_hidden_inputs(form: ExtractedForm, page_url: str) -> Finding | None:
    hidden = _hidden_inputs(form)
    if len(hidden) <= _HIDDEN_INPUTS_THRESHOLD:
        return None
    names = [i.name for i in hidden if i.name]
    return Finding(
        title="Unusually many hidden form inputs",
        description=(
            f"This form has {len(hidden)} hidden inputs. Most forms only need a "
            "handful (CSRF token, a record ID or two). A long list of hidden "
            "fields can be a sign of an injected analytics or tracking payload "
            "that's harvesting data the user didn't intend to submit, or an "
            "over-broad framework defaulting to client-side state. Worth a quick "
            "look at what each one is for."
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
            "Audit each hidden field: confirm it's required, it's not echoing "
            "personal data, and the server validates rather than trusts it. Move "
            "client-side state into the session where you can. Check the page "
            "source for unexpected third-party scripts that may have inserted them."
        ),
        framework=_FA["excessive_hidden"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "hidden_count": len(hidden)},
    )


def _check_suspicious_action_url(form: ExtractedForm, page_url: str) -> Finding | None:
    if not form.action_url:
        return None
    if not _SUSPICIOUS_ACTION_RE.search(form.action_url):
        return None
    return Finding(
        title="Form points at a debug, staging, or internal URL",
        description=(
            f"The form's action is '{form.action_url}', which contains a "
            "non-production marker (localhost, /staging, /debug, /test, /internal, "
            "etc). In production this is almost always a configuration leak — "
            "either an environment variable wasn't substituted at build time, or "
            "a developer left a hard-coded URL in. Submissions may silently fail, "
            "land in the wrong environment, or expose an internal endpoint to the "
            "public."
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
            "Wire the form action through an environment-aware config rather than "
            "a hard-coded URL. Add a CI check that fails the build when "
            "non-production hostnames appear in production artifacts. Confirm "
            "the affected endpoint can't be reached from the internet at all."
        ),
        framework=_FA["suspicious_action"],
        scanner_engine=_ENGINE,
        metadata={"page_url": page_url, "action_url": form.action_url},
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_FORM_CHECKS = [
    _check_password_over_http,
    _check_payment_over_http,
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
