# WebHound — scanner/webhound/wade/change_types.py
# WADE 2.0 intelligence vocabulary: the change taxonomy, confidence levels,
# and severity bands that turn a raw diff into an *understood* change.
#
# These enums are the shared language between the change classifier
# (change_classifier.py), the scorer, the suppression layer, and the
# Finding-building classifier.  No network calls; pure data + ordering.

from __future__ import annotations

from enum import Enum


class WadeChangeType(str, Enum):
    """What a detected change *means*, not merely what changed.

    Ordered loosely from benign → malicious. The classifier maps a
    (DiffItem + domain reputation + page context) tuple onto exactly one
    of these so downstream layers can reason about intent rather than
    raw mechanics.
    """

    # --- Benign / expected -------------------------------------------------
    EXPECTED_DEPLOYMENT       = "expected_deployment"
    NORMAL_CONTENT_UPDATE     = "normal_content_update"

    # --- Known third-party additions (low concern, classified for clarity) -
    NEW_MARKETING_TOOL        = "new_marketing_tool"
    NEW_ANALYTICS_TOOL        = "new_analytics_tool"
    NEW_THIRD_PARTY_SERVICE   = "new_third_party_service"
    NEW_PAYMENT_PROVIDER      = "new_payment_provider"
    NEW_AUTH_PROVIDER         = "new_auth_provider"

    # --- Security-relevant / suspicious ------------------------------------
    SUSPICIOUS_SCRIPT_CHANGE  = "suspicious_script_change"
    SUSPICIOUS_IFRAME         = "suspicious_iframe"
    SUSPICIOUS_REDIRECT       = "suspicious_redirect"

    # --- Compromise indicators ---------------------------------------------
    POSSIBLE_COMPROMISE       = "possible_compromise"
    CONFIRMED_MALICIOUS_INDICATOR = "confirmed_malicious_indicator"


# Change types that represent a known, named third-party vendor being added.
# Reporting presents these as inventory rather than threats.
VENDOR_CHANGE_TYPES: frozenset[WadeChangeType] = frozenset({
    WadeChangeType.NEW_MARKETING_TOOL,
    WadeChangeType.NEW_ANALYTICS_TOOL,
    WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    WadeChangeType.NEW_PAYMENT_PROVIDER,
    WadeChangeType.NEW_AUTH_PROVIDER,
})

# Change types that describe an actively concerning event.
SECURITY_RELEVANT_CHANGE_TYPES: frozenset[WadeChangeType] = frozenset({
    WadeChangeType.SUSPICIOUS_SCRIPT_CHANGE,
    WadeChangeType.SUSPICIOUS_IFRAME,
    WadeChangeType.SUSPICIOUS_REDIRECT,
    WadeChangeType.POSSIBLE_COMPROMISE,
    WadeChangeType.CONFIRMED_MALICIOUS_INDICATOR,
})


class WadeConfidence(str, Enum):
    """How sure WADE is that a reported change is real and correctly
    characterised — orthogonal to how *dangerous* it is.

    CONFIRMED   — physically observed in the markup / headers / redirect.
    HIGH        — strong corroboration (e.g. threat-intel hit on a host).
    MEDIUM      — reliable extraction, mild interpretation.
    LOW         — inferred from a softer signal (route guessed from JS).
    HEURISTIC   — pattern-based guess (technology fingerprint).
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HEURISTIC = "heuristic"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self.value]

    @property
    def as_float(self) -> float:
        """A representative numeric confidence for the level."""
        return _CONFIDENCE_FLOAT[self.value]


_CONFIDENCE_RANK: dict[str, int] = {
    "confirmed": 5, "high": 4, "medium": 3, "low": 2, "heuristic": 1,
}
_CONFIDENCE_FLOAT: dict[str, float] = {
    "confirmed": 0.95, "high": 0.85, "medium": 0.70, "low": 0.50,
    "heuristic": 0.40,
}


class ChangeBand(str, Enum):
    """The customer-facing 'should I care?' band for a change.

    Distinct from :class:`~webhound.models.severity.Severity` so the WADE
    intelligence layer can reason in its own vocabulary before mapping onto
    the scanner-wide severity scale at Finding-build time.
    """

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _BAND_RANK[self.value]


_BAND_RANK: dict[str, int] = {
    "very_low": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
