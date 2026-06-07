# WebHound — scanner/webhound/wade/change_classifier.py
# WADE 2.0 change classification + scoring (Tasks 3, 5, 6).
#
# Turns a scored diff into an *understood* change: what kind of change it is
# (WadeChangeType), how confident WADE is (WadeConfidence), and the
# customer-facing 'should I care?' band (ChangeBand). The reasoning blends:
#
#   * the raw diff type            (what mechanically changed)
#   * vendor reputation            (vendor_intel → DomainClassifier)
#   * page sensitivity / context   (ContextEngine output, already on the anomaly)
#   * threat-intel signals         (malicious / risky host)
#
# No network calls — everything is local.

from __future__ import annotations

import re
from dataclasses import dataclass, field

from webhound.wade.anomaly_scorer import ScoredAnomaly
from webhound.wade.change_types import (
    SECURITY_RELEVANT_CHANGE_TYPES,
    VENDOR_CHANGE_TYPES,
    ChangeBand,
    WadeChangeType,
    WadeConfidence,
)
from webhound.wade.confidence import confidence_level
from webhound.wade.diff_engine import DiffType
from webhound.wade.vendor_intel import VendorIntel, VendorVerdict

# Page contexts where an unexpected change carries materially higher risk.
SENSITIVE_CONTEXTS: frozenset[str] = frozenset({
    "admin", "checkout", "login", "account", "cart",
})
# Page contexts where the same change reads calmer.
CALM_CONTEXTS: frozenset[str] = frozenset({"homepage", "contact"})

# Base 'should I care?' band per change type, before context adjustment.
_BASE_BAND: dict[WadeChangeType, ChangeBand] = {
    WadeChangeType.EXPECTED_DEPLOYMENT:           ChangeBand.VERY_LOW,
    WadeChangeType.NORMAL_CONTENT_UPDATE:         ChangeBand.VERY_LOW,
    WadeChangeType.NEW_ANALYTICS_TOOL:            ChangeBand.VERY_LOW,
    WadeChangeType.NEW_MARKETING_TOOL:            ChangeBand.VERY_LOW,
    WadeChangeType.NEW_THIRD_PARTY_SERVICE:       ChangeBand.LOW,
    WadeChangeType.NEW_PAYMENT_PROVIDER:          ChangeBand.LOW,
    WadeChangeType.NEW_AUTH_PROVIDER:             ChangeBand.LOW,
    WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE:      ChangeBand.MEDIUM,
    WadeChangeType.SUSPICIOUS_IFRAME:             ChangeBand.HIGH,
    WadeChangeType.SUSPICIOUS_REDIRECT:           ChangeBand.HIGH,
    WadeChangeType.POSSIBLE_COMPROMISE:           ChangeBand.HIGH,
    WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR: ChangeBand.CRITICAL,
}

_BANDS: list[ChangeBand] = [
    ChangeBand.VERY_LOW, ChangeBand.LOW, ChangeBand.MEDIUM,
    ChangeBand.HIGH, ChangeBand.CRITICAL,
]

# A form is sensitive — and therefore worth alerting on wherever it appears —
# when its signature names credential/payment fields or a login/checkout
# action. A new contact/newsletter form is benign content; a new password or
# card form is the classic formjacking signature.
_SENSITIVE_FORM_RE: re.Pattern[str] = re.compile(
    r"password|passwd|\bpwd\b|cvv|cvc|cardnumber|card[_-]?number|creditcard|"
    r"ccnum|account[_-]?number|routing|ssn|/login|/signin|/sign-in|/checkout|"
    r"/payment|/pay\b|/account|/auth",
    re.IGNORECASE,
)

# Diff types where the changed value names a host we can reputation-check.
_HOST_BEARING: frozenset[DiffType] = frozenset({
    DiffType.NEW_SCRIPT_SOURCE, DiffType.REMOVED_SCRIPT_SOURCE,
    DiffType.NEW_EXTERNAL_DOMAIN, DiffType.REMOVED_EXTERNAL_DOMAIN,
    DiffType.NEW_THIRD_PARTY_DOMAIN, DiffType.REMOVED_THIRD_PARTY_DOMAIN,
    DiffType.NEW_IFRAME, DiffType.REDIRECT_CHANGE, DiffType.NEW_API_ENDPOINT,
})


@dataclass
class ChangeAssessment:
    """WADE's full intelligence read on a single scored change."""

    change_type: WadeChangeType
    band: ChangeBand
    confidence: WadeConfidence
    threat_intel_hit: bool
    vendor_category: str
    rationale: str
    vendor: VendorVerdict | None = None
    signals: list[str] = field(default_factory=list)


class ChangeClassifier:
    """Assess scored anomalies into :class:`ChangeAssessment` objects."""

    def __init__(self, vendor_intel: VendorIntel | None = None) -> None:
        self._vendor = vendor_intel or VendorIntel()

    def assess(self, anomaly: ScoredAnomaly) -> ChangeAssessment:
        item = anomaly.diff_item
        dt = item.diff_type
        ctx = anomaly.context_type

        verdict = self._verdict_for(item)
        threat_hit = bool(verdict and (verdict.is_malicious or verdict.is_risky))

        change_type = self._change_type(item, ctx, verdict)
        band = self._band(change_type, ctx)
        conf = confidence_level(
            anomaly,
            threat_intel_hit=bool(verdict and verdict.is_malicious),
        )
        return ChangeAssessment(
            change_type=change_type,
            band=band,
            confidence=conf,
            threat_intel_hit=threat_hit,
            vendor_category=verdict.vendor_category if verdict else "unknown",
            rationale=self._rationale(dt, ctx, verdict, change_type),
            vendor=verdict,
            signals=list(verdict.signals) if verdict else [],
        )

    def assess_all(self, anomalies: list[ScoredAnomaly]) -> list[ChangeAssessment]:
        return [self.assess(a) for a in anomalies]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _verdict_for(self, item) -> VendorVerdict | None:
        if item.diff_type not in _HOST_BEARING or not item.current_value:
            return None
        # Redirect current_value is "host → host"; take the final hop.
        value = item.current_value
        if item.diff_type == DiffType.REDIRECT_CHANGE and "→" in value:
            value = value.split("→")[-1].strip()
        if item.diff_type == DiffType.NEW_IFRAME and "|" in value:
            value = value.split("|", 1)[0].strip()
        return self._vendor.assess(value)

    def _change_type(
        self, item, ctx: str, verdict: VendorVerdict | None
    ) -> WadeChangeType:
        dt = item.diff_type
        # Threat-intel always wins.
        if verdict and verdict.is_malicious:
            return WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR

        sensitive = ctx in SENSITIVE_CONTEXTS

        # --- iframes ----------------------------------------------------
        if dt == DiffType.NEW_IFRAME:
            if verdict and verdict.is_known_vendor:
                return WadeChangeType.NEW_THIRD_PARTY_SERVICE
            return WadeChangeType.SUSPICIOUS_IFRAME

        # --- redirects --------------------------------------------------
        if dt == DiffType.REDIRECT_CHANGE:
            if verdict and verdict.is_trusted:
                return WadeChangeType.NORMAL_CONTENT_UPDATE
            return WadeChangeType.SUSPICIOUS_REDIRECT

        # --- new scripts / domains / third parties ----------------------
        if dt in (DiffType.NEW_SCRIPT_SOURCE, DiffType.NEW_EXTERNAL_DOMAIN,
                  DiffType.NEW_THIRD_PARTY_DOMAIN):
            if verdict and verdict.change_type is not None:
                return verdict.change_type            # known vendor by category
            if verdict and verdict.is_risky:
                return WadeChangeType.POSSIBLE_COMPROMISE
            if dt == DiffType.NEW_SCRIPT_SOURCE:
                return WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE
            # Unknown new non-script third party — concerning on sensitive
            # pages, otherwise a (still-noted) new service.
            return (WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE if sensitive
                    else WadeChangeType.NEW_THIRD_PARTY_SERVICE)

        # --- inline script body changed ---------------------------------
        if dt == DiffType.CHANGED_INLINE_SCRIPT:
            return WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE

        # --- forms ------------------------------------------------------
        # A credential/payment form is sensitive *wherever* it appears; a
        # plain contact/newsletter form on a non-sensitive page is content.
        if dt in (DiffType.NEW_FORM, DiffType.FORM_FIELD_CHANGE):
            if sensitive or _SENSITIVE_FORM_RE.search(item.current_value or ""):
                return WadeChangeType.POSSIBLE_COMPROMISE
            return WadeChangeType.NORMAL_CONTENT_UPDATE

        # --- API endpoints ----------------------------------------------
        if dt == DiffType.NEW_API_ENDPOINT:
            if verdict and verdict.is_known_vendor:
                return WadeChangeType.NEW_THIRD_PARTY_SERVICE
            return WadeChangeType.NORMAL_CONTENT_UPDATE

        # --- everything else: removals, headers, cookies, status, dom,
        #     technology — non-additive churn, treated as expected/normal.
        if dt in (DiffType.STATUS_CODE_CHANGE, DiffType.DOM_STRUCTURE_CHANGE,
                  DiffType.TECHNOLOGY_CHANGE):
            return WadeChangeType.EXPECTED_DEPLOYMENT
        return WadeChangeType.NORMAL_CONTENT_UPDATE

    def _band(self, change_type: WadeChangeType, ctx: str) -> ChangeBand:
        if change_type == WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR:
            return ChangeBand.CRITICAL
        band = _BASE_BAND.get(change_type, ChangeBand.LOW)
        if change_type in SECURITY_RELEVANT_CHANGE_TYPES:
            if ctx in SENSITIVE_CONTEXTS:
                band = _shift(band, +1)
            elif ctx in CALM_CONTEXTS:
                band = _shift(band, -1)
        return band

    def _rationale(
        self, dt: DiffType, ctx: str,
        verdict: VendorVerdict | None, change_type: WadeChangeType,
    ) -> str:
        bits: list[str] = [f"{dt.value} on a '{ctx}' page"]
        if verdict and verdict.is_known_vendor:
            bits.append(
                f"host '{verdict.host}' is a known {verdict.vendor_category} "
                f"vendor ({verdict.classification.value})"
            )
        elif verdict and verdict.is_malicious:
            bits.append(f"host '{verdict.host}' flagged as malicious indicator")
        elif verdict and verdict.is_risky:
            bits.append(f"host '{verdict.host}' classified risky")
        elif verdict:
            bits.append(f"host '{verdict.host}' is unrecognised")
        bits.append(f"→ {change_type.value}")
        return "; ".join(bits)


def _shift(band: ChangeBand, delta: int) -> ChangeBand:
    idx = _BANDS.index(band)
    return _BANDS[max(0, min(len(_BANDS) - 1, idx + delta))]
