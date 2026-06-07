# WebHound — scanner/webhound/wade/classifier.py
# Converts scored anomalies into Finding objects with appropriate severity,
# category, confidence, framework alignment, and explainable evidence.

from __future__ import annotations

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity
from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassifier,
)
from webhound.wade.anomaly_scorer import ScoredAnomaly
from webhound.wade.change_classifier import ChangeClassifier
from webhound.wade.change_types import VENDOR_CHANGE_TYPES, ChangeBand, WadeChangeType
from webhound.wade.confidence import compute_confidence
from webhound.wade.diff_engine import DiffType
from webhound.wade.suppression import decide as suppression_decide
from webhound.wade.vendor_intel import VendorIntel

NAME = "wade"

# ChangeBand → scanner-wide Severity at Finding-build time.
_BAND_SEVERITY: dict[ChangeBand, Severity] = {
    ChangeBand.VERY_LOW: Severity.INFO,
    ChangeBand.LOW:      Severity.LOW,
    ChangeBand.MEDIUM:   Severity.MEDIUM,
    ChangeBand.HIGH:     Severity.HIGH,
    ChangeBand.CRITICAL: Severity.CRITICAL,
}

# WADE findings are behavioural signals (a diff against a baseline), not
# confirmed vulnerabilities. We cap severity at HIGH by default; only the
# integration with DomainClassifier can escalate a NEW_EXTERNAL_DOMAIN to
# CRITICAL when the new host classifies as MALICIOUS_INDICATOR.
_CRITICAL_THRESHOLD = 1.1
_DOWNGRADE_THRESHOLD = 0.40

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]

_TYPE_MAP: dict[DiffType, tuple[FindingCategory, Severity]] = {
    DiffType.NEW_SCRIPT_SOURCE:     (FindingCategory.JAVASCRIPT,     Severity.HIGH),
    DiffType.CHANGED_INLINE_SCRIPT: (FindingCategory.JAVASCRIPT,     Severity.HIGH),
    DiffType.NEW_EXTERNAL_DOMAIN:   (FindingCategory.JAVASCRIPT,     Severity.MEDIUM),
    DiffType.HEADER_REGRESSION:     (FindingCategory.SECURITY_HEADER, Severity.MEDIUM),
    DiffType.COOKIE_REGRESSION:     (FindingCategory.COOKIE,          Severity.MEDIUM),
    DiffType.NEW_FORM:              (FindingCategory.FORM,             Severity.MEDIUM),
    DiffType.FORM_FIELD_CHANGE:     (FindingCategory.FORM,             Severity.MEDIUM),
    DiffType.STATUS_CODE_CHANGE:    (FindingCategory.INFORMATIONAL,    Severity.INFO),
    # WADE 2.0 — severity for these comes from the change band; the entry
    # here only fixes the finding *category*.
    DiffType.REMOVED_SCRIPT_SOURCE:      (FindingCategory.JAVASCRIPT,      Severity.INFO),
    DiffType.REMOVED_EXTERNAL_DOMAIN:    (FindingCategory.JAVASCRIPT,      Severity.INFO),
    DiffType.NEW_THIRD_PARTY_DOMAIN:     (FindingCategory.JAVASCRIPT,      Severity.MEDIUM),
    DiffType.REMOVED_THIRD_PARTY_DOMAIN: (FindingCategory.JAVASCRIPT,      Severity.INFO),
    DiffType.NEW_API_ENDPOINT:           (FindingCategory.API,             Severity.LOW),
    DiffType.REMOVED_API_ENDPOINT:       (FindingCategory.API,             Severity.INFO),
    DiffType.HEADER_ADDED:               (FindingCategory.SECURITY_HEADER, Severity.INFO),
    DiffType.COOKIE_BEHAVIOR_CHANGE:     (FindingCategory.COOKIE,          Severity.LOW),
    DiffType.NEW_IFRAME:                 (FindingCategory.JAVASCRIPT,      Severity.HIGH),
    DiffType.REDIRECT_CHANGE:            (FindingCategory.INFORMATIONAL,   Severity.MEDIUM),
    DiffType.TECHNOLOGY_CHANGE:          (FindingCategory.TECHNOLOGY,      Severity.INFO),
    DiffType.DOM_STRUCTURE_CHANGE:       (FindingCategory.INFORMATIONAL,   Severity.INFO),
}

# WADE 2.0 diff types whose severity comes from the change-intelligence band.
# The original eight keep their calibrated v1 path (preserving v1 behaviour).
_V2_DIFF_TYPES: frozenset[DiffType] = frozenset({
    DiffType.REMOVED_SCRIPT_SOURCE, DiffType.REMOVED_EXTERNAL_DOMAIN,
    DiffType.NEW_THIRD_PARTY_DOMAIN, DiffType.REMOVED_THIRD_PARTY_DOMAIN,
    DiffType.NEW_API_ENDPOINT, DiffType.REMOVED_API_ENDPOINT,
    DiffType.HEADER_ADDED, DiffType.COOKIE_BEHAVIOR_CHANGE,
    DiffType.NEW_IFRAME, DiffType.REDIRECT_CHANGE,
    DiffType.TECHNOLOGY_CHANGE, DiffType.DOM_STRUCTURE_CHANGE,
})

_TITLES: dict[DiffType, str] = {
    DiffType.NEW_SCRIPT_SOURCE:     "New external script appeared since last scan",
    DiffType.CHANGED_INLINE_SCRIPT: "Inline script content changed since last scan",
    DiffType.NEW_EXTERNAL_DOMAIN:   "Page contacts a new external domain",
    DiffType.HEADER_REGRESSION:     "Security header dropped since last scan",
    DiffType.COOKIE_REGRESSION:     "Cookie lost a security flag since last scan",
    DiffType.NEW_FORM:              "New form appeared since last scan",
    DiffType.FORM_FIELD_CHANGE:     "Form fields changed since last scan",
    DiffType.STATUS_CODE_CHANGE:    "Page status code changed since last scan",
    DiffType.REMOVED_SCRIPT_SOURCE:      "External script removed since last scan",
    DiffType.REMOVED_EXTERNAL_DOMAIN:    "External domain no longer referenced",
    DiffType.NEW_THIRD_PARTY_DOMAIN:     "Page loads from a new third-party host",
    DiffType.REMOVED_THIRD_PARTY_DOMAIN: "Third-party resource host removed",
    DiffType.NEW_API_ENDPOINT:           "New API endpoint surfaced since last scan",
    DiffType.REMOVED_API_ENDPOINT:       "API endpoint no longer referenced",
    DiffType.HEADER_ADDED:               "Security header added since last scan",
    DiffType.COOKIE_BEHAVIOR_CHANGE:     "New cookie set since last scan",
    DiffType.NEW_IFRAME:                 "New iframe embedded since last scan",
    DiffType.REDIRECT_CHANGE:            "Redirect behaviour changed since last scan",
    DiffType.TECHNOLOGY_CHANGE:          "Detected technology stack changed",
    DiffType.DOM_STRUCTURE_CHANGE:       "Page structure changed since last scan",
}

_DESCRIPTIONS: dict[DiffType, str] = {
    DiffType.NEW_SCRIPT_SOURCE: (
        "Compared with the previous baseline, this page now loads a "
        "JavaScript file that wasn't there last time. A net-new script on "
        "an established page is one of the strongest signals of either an "
        "intentional deploy or an attacker injection — and from a passive "
        "scan you can't tell the two apart. Confirm against your "
        "deployment record. Magecart-style skimmers typically arrive this "
        "way through a compromised plugin, CDN, or admin credential."
    ),
    DiffType.CHANGED_INLINE_SCRIPT: (
        "An inline `<script>` block on this page has different content "
        "than the previous baseline. The hash of the script body changed, "
        "which means either: (1) you re-deployed and the build emitted "
        "different output, or (2) someone modified the page after deploy. "
        "If your build is deterministic, option 2 is the alarm bell."
    ),
    DiffType.NEW_EXTERNAL_DOMAIN: (
        "The page is now loading or linking to a domain it didn't touch "
        "in the previous baseline. Every external domain is a "
        "supply-chain trust decision; a brand-new one on an established "
        "page warrants a vendor review. The integration with the local "
        "DomainClassifier escalates this finding's severity when the new "
        "host scores RISKY or MALICIOUS_INDICATOR."
    ),
    DiffType.HEADER_REGRESSION: (
        "A security header that was present in the previous baseline is "
        "now missing. Header regressions usually come from CDN config "
        "drift, a framework upgrade that swapped middleware defaults, or "
        "a deliberate change someone forgot to coordinate. Either way, "
        "the protections that header provided are gone for the moment."
    ),
    DiffType.COOKIE_REGRESSION: (
        "A cookie that previously carried Secure / HttpOnly attributes is "
        "now being set without them. Cookie-attribute regressions almost "
        "always trace to a framework upgrade or a backend config change "
        "— the protection silently disappears and most teams don't notice "
        "until an external scanner flags it."
    ),
    DiffType.NEW_FORM: (
        "A form that wasn't on this page in the previous baseline now is. "
        "On low-trust pages (CMS-driven content), this can be benign — "
        "editors add contact forms. On sensitive pages (login, checkout, "
        "account settings), a new form is one of the textbook formjacking "
        "signatures: the attacker overlays a fake form to harvest "
        "credentials or card data."
    ),
    DiffType.FORM_FIELD_CHANGE: (
        "An existing form has different fields than in the previous "
        "baseline — same action URL, different input set. The most common "
        "innocent cause is a feature change (added a phone field); the "
        "most common malicious cause is a skimmer adding hidden inputs to "
        "exfiltrate captured data inside the legitimate POST."
    ),
    DiffType.STATUS_CODE_CHANGE: (
        "The page returned a different HTTP status code than in the "
        "previous baseline. Status changes are usually deploys (404 → "
        "200 after publishing) or maintenance (200 → 503), but a "
        "previously-200 page returning 302 to an unfamiliar domain is a "
        "redirect-hijack signature."
    ),
}


_FA: dict[DiffType, FrameworkAlignment] = {
    DiffType.NEW_SCRIPT_SOURCE: FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829", "CWE-494", "CWE-1395"],
        nist_controls=["SI-7", "CM-3", "CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=8.5,
        pci_dss=["6.4.3", "11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.8.25", "A.8.32"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(1)(ii)(D)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.CHANGED_INLINE_SCRIPT: FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-494", "CWE-506"],
        nist_controls=["SI-7", "CM-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3", "11.6.1"],
        iso_27001=["A.8.25", "A.8.32"],
        soc2=["CC7.1"],
        hipaa=["164.308(a)(1)(ii)(D)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.NEW_EXTERNAL_DOMAIN: FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829"],
        nist_controls=["CM-8", "SR-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.4.3", "12.8.5"],
        iso_27001=["A.5.19", "A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.HEADER_REGRESSION: FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-693", "CWE-16"],
        nist_controls=["CM-6", "CM-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["2.2.1", "6.4.3"],
        iso_27001=["A.8.9", "A.8.32"],
        soc2=["CC6.1", "CC8.1"],
        hipaa=["164.312(e)(1)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.COOKIE_REGRESSION: FrameworkAlignment(
        owasp_top10=["A02:2021", "A05:2021"],
        cwe_ids=["CWE-614", "CWE-1004", "CWE-16"],
        nist_controls=["AC-12", "SC-23", "CM-6"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cvss_score=6.5,
        pci_dss=["2.2.1", "8.3.1", "8.6.1"],
        iso_27001=["A.5.17", "A.8.5", "A.8.32"],
        soc2=["CC6.1", "CC6.7"],
        hipaa=["164.312(a)(2)(i)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.NEW_FORM: FrameworkAlignment(
        owasp_top10=["A08:2021", "A03:2021"],
        cwe_ids=["CWE-352", "CWE-79", "CWE-506"],
        nist_controls=["SI-10", "SI-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        cvss_score=7.1,
        pci_dss=["6.4.3", "11.6.1"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.FORM_FIELD_CHANGE: FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-10", "SI-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    DiffType.STATUS_CODE_CHANGE: FrameworkAlignment(
        owasp_top10=["A05:2021"],
        cwe_ids=["CWE-754"],
        nist_controls=["CM-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=[],
        iso_27001=["A.8.32"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
}


class Classifier:
    """Convert scored anomalies into Findings with framework alignment.

    Integrates with the local DomainClassifier so a NEW_EXTERNAL_DOMAIN
    finding can be auto-escalated from MEDIUM to HIGH (if the domain is
    RISKY) or CRITICAL (if it's MALICIOUS_INDICATOR) based on local
    classification signals — no network calls.
    """

    def __init__(self, domain_classifier: DomainClassifier | None = None) -> None:
        self._domain_clf = domain_classifier or DomainClassifier()
        self._change_clf = ChangeClassifier(VendorIntel(self._domain_clf))

    def classify(self, anomalies: list[ScoredAnomaly]) -> list[Finding]:
        return [self._to_finding(a) for a in anomalies]

    def _to_finding(self, a: ScoredAnomaly) -> Finding:
        item = a.diff_item
        category, base_sev = _TYPE_MAP.get(
            item.diff_type, (FindingCategory.UNKNOWN, Severity.INFO)
        )
        confidence = compute_confidence(a)

        # NEW_EXTERNAL_DOMAIN: ask the DomainClassifier whether the host
        # itself looks malicious. Escalate severity accordingly. Same idea
        # for NEW_SCRIPT_SOURCE: extract the host from the script URL.
        threat_intel_extra: dict[str, object] = {}
        escalated_sev: Severity | None = None
        if item.diff_type == DiffType.NEW_EXTERNAL_DOMAIN and item.current_value:
            cls = self._domain_clf.classify(item.current_value.strip())
            threat_intel_extra = {
                "domain_classification": cls.classification.value,
                "domain_score": cls.score,
                "domain_signals": cls.signals,
            }
            if cls.classification == DomainClass.MALICIOUS_INDICATOR:
                escalated_sev = Severity.CRITICAL
            elif cls.classification == DomainClass.RISKY:
                escalated_sev = Severity.HIGH
        elif item.diff_type == DiffType.NEW_SCRIPT_SOURCE and item.current_value:
            host = _hostname_of(item.current_value)
            if host:
                cls = self._domain_clf.classify(host)
                threat_intel_extra = {
                    "script_host_classification": cls.classification.value,
                    "script_host_score": cls.score,
                    "script_host_signals": cls.signals,
                }
                if cls.classification == DomainClass.MALICIOUS_INDICATOR:
                    escalated_sev = Severity.CRITICAL

        if escalated_sev is not None:
            severity = escalated_sev
        else:
            severity = _adjust_severity(base_sev, a.anomaly_score, confidence,
                                         item.diff_type)

        # WADE 2.0 intelligence: classify the change and reconcile severity.
        # The original eight diff types keep their calibrated path above; the
        # band overrides only for new v2 types, confirmed-malicious escalation,
        # and to *calm* a known-benign vendor addition.
        assess = self._change_clf.assess(a)
        if item.diff_type in _V2_DIFF_TYPES:
            severity = _BAND_SEVERITY[assess.band]
        elif assess.change_type == WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR:
            severity = Severity.CRITICAL
        elif assess.change_type in VENDOR_CHANGE_TYPES:
            severity = _BAND_SEVERITY[assess.band]   # known vendor → calm it down

        sup = suppression_decide(assess, item.diff_type)

        description = _description(item, a, escalated_sev is not None)
        framework = _FA.get(item.diff_type, FrameworkAlignment())

        evidence = Evidence(
            evidence_type=EvidenceType.PATTERN_MATCH,
            content=item.detail,
            location=item.url,
            confidence=confidence,
            source_engine=NAME,
            extra={
                "diff_type":       item.diff_type.value,
                "baseline_value":  item.baseline_value,
                "current_value":   item.current_value,
                "context_type":    a.context_type,
                "context_weight":  a.context_weight,
                "raw_score":       a.raw_score,
                # WADE 2.0 intelligence
                "wade_change_type":       assess.change_type.value,
                "wade_change_band":       assess.band.value,
                "wade_confidence_level":  assess.confidence.value,
                "wade_vendor_category":   assess.vendor_category,
                "wade_threat_intel_hit":  assess.threat_intel_hit,
                "wade_rationale":         assess.rationale,
                "wade_suppressed":        sup.suppressed,
                "wade_suppression_reason": sup.reason,
                **threat_intel_extra,
            },
        )
        tags = ["wade", "anomaly", item.diff_type.value, a.context_type,
                assess.change_type.value, f"confidence:{assess.confidence.value}"]
        if assess.threat_intel_hit:
            tags.append("threat_intel")
        if sup.suppressed:
            tags.append("wade_suppressed")
        return Finding(
            title=_TITLES.get(item.diff_type, "Anomaly detected"),
            description=description,
            severity=severity,
            category=category,
            scanner_engine=NAME,
            evidence=[evidence],
            confidence=confidence,
            anomaly_score=a.anomaly_score,
            framework=framework,
            tags=tags,
            remediation=_remediation(item.diff_type),
            metadata={
                "wade_change_type": assess.change_type.value,
                "wade_change_band": assess.band.value,
                "wade_confidence_level": assess.confidence.value,
                "wade_suppressed": sup.suppressed,
            },
        )


def _hostname_of(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _adjust_severity(
    base: Severity,
    anomaly_score: float,
    confidence: float,
    diff_type: DiffType,
) -> Severity:
    if (
        anomaly_score >= _CRITICAL_THRESHOLD
        and diff_type in (DiffType.NEW_SCRIPT_SOURCE, DiffType.CHANGED_INLINE_SCRIPT)
    ):
        return Severity.CRITICAL
    if confidence < _DOWNGRADE_THRESHOLD and base != Severity.INFO:
        idx = _SEVERITY_ORDER.index(base)
        return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]
    return base


def _description(item, a: ScoredAnomaly, threat_intel_boosted: bool) -> str:
    base = _DESCRIPTIONS.get(item.diff_type, item.detail)
    ctx_note = (
        f" Context: {a.context_type} page (weight ×{a.context_weight:.1f})."
        if a.context_type != "default" else ""
    )
    ti_note = (
        " The destination host scores as risky or malicious by local "
        "threat-intelligence signals, so the severity here has been "
        "escalated above the default WADE baseline."
        if threat_intel_boosted else ""
    )
    return (
        f"{base}{ctx_note}{ti_note} Anomaly score: {a.anomaly_score:.2f}. "
        f"Baseline value: {item.baseline_value!r}. "
        f"Current value: {item.current_value!r}."
    )


def _remediation(diff_type: DiffType) -> str:
    base = {
        DiffType.NEW_SCRIPT_SOURCE: (
            "Confirm against the deployment record whether this script "
            "was added intentionally. If yes, document the source and "
            "add it to your CSP `script-src` allowlist. If you cannot "
            "account for it, treat the page as potentially compromised: "
            "snapshot the HTML, audit CMS / template / CDN changes from "
            "the last baseline, rotate admin credentials."
        ),
        DiffType.CHANGED_INLINE_SCRIPT: (
            "Re-deploys cause this in deterministic builds — match the "
            "change to a recent release. If the build is "
            "reproducible and you cannot match the change to a deploy, "
            "treat as a compromise event."
        ),
        DiffType.NEW_EXTERNAL_DOMAIN: (
            "Verify the new host is on your approved-vendor list. If "
            "not, add it (with purpose and security posture) or remove "
            "the reference. Update your CSP `connect-src` / `script-src` "
            "/ `img-src` to lock the policy down once the inventory is "
            "stable."
        ),
        DiffType.HEADER_REGRESSION: (
            "Compare your reverse-proxy / CDN / framework config against "
            "the previous baseline. The most common cause is a config "
            "merge that overwrote a security middleware default. Re-add "
            "the header and add a CI test that fails the build if it "
            "drops out again."
        ),
        DiffType.COOKIE_REGRESSION: (
            "Find where the cookie is set (framework default vs explicit "
            "Set-Cookie call) and re-add the missing attribute. "
            "Application frameworks often have a single config flag to "
            "force Secure + HttpOnly globally — turn it on rather than "
            "tracking each cookie."
        ),
        DiffType.NEW_FORM: (
            "Confirm the new form is intentional. If you don't recognise "
            "it, treat as formjacking and snapshot the HTML before "
            "removing it — the forensic record helps determine the "
            "injection vector. Audit CMS user activity since the last "
            "baseline."
        ),
        DiffType.FORM_FIELD_CHANGE: (
            "Match the new fields against the most recent feature change. "
            "Pay special attention to added hidden fields — those are "
            "the standard skimmer technique for exfiltrating captured "
            "data through the original POST."
        ),
        DiffType.STATUS_CODE_CHANGE: (
            "Identify whether the change is a deploy (acceptable), "
            "a maintenance window (acceptable), or a redirect chain to "
            "an unfamiliar domain (compromise). Re-run the scan after "
            "addressing the cause."
        ),
    }
    return base.get(diff_type, "Investigate the change against your "
                                "deployment record and CMS audit log.")
