# WebHound — scanner/webhound/wade/vendor_intel.py
# WADE 2.0 known-vendor awareness.
#
# This is a thin reasoning layer over the existing local DomainClassifier
# (threat_intel/domain_classifier.py) — it adds NO new domain lists. It
# answers the WADE-specific questions:
#
#     Is this host a known, trusted vendor?
#     What does that vendor do (analytics / payment / auth / …)?
#     Which WADE change type should a *new* appearance of it map to?
#
# Keeping the lists in one place (DomainClassifier) means a vendor added
# there is automatically understood here too.

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from webhound.threat_intel.domain_classifier import (
    DomainClass,
    DomainClassification,
    DomainClassifier,
)
from webhound.wade.change_types import WadeChangeType

# Functional vendor category → the WADE change type a *new* appearance maps to.
_CATEGORY_TO_CHANGE: dict[str, WadeChangeType] = {
    "analytics": WadeChangeType.NEW_ANALYTICS_TOOL,
    "ads":       WadeChangeType.NEW_MARKETING_TOOL,
    "marketing": WadeChangeType.NEW_MARKETING_TOOL,
    "payment":   WadeChangeType.NEW_PAYMENT_PROVIDER,
    "identity":  WadeChangeType.NEW_AUTH_PROVIDER,
    "chat":      WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    "cdn":       WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    "hosting":   WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    "commerce":  WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    "social":    WadeChangeType.NEW_THIRD_PARTY_SERVICE,
    "media":     WadeChangeType.NEW_THIRD_PARTY_SERVICE,
}


@dataclass(frozen=True)
class VendorVerdict:
    """WADE's read on a single host."""

    host: str
    classification: DomainClass
    vendor_category: str
    score: float
    signals: list[str]
    is_known_vendor: bool          # trusted or common-benign
    is_malicious: bool             # MALICIOUS_INDICATOR
    is_risky: bool                 # RISKY
    change_type: WadeChangeType | None  # mapped vendor change type, if known

    @property
    def is_trusted(self) -> bool:
        return self.classification in (
            DomainClass.TRUSTED, DomainClass.COMMON_BENIGN
        )


class VendorIntel:
    """Vendor awareness for WADE, backed by the shared DomainClassifier."""

    def __init__(self, domain_classifier: DomainClassifier | None = None) -> None:
        self._clf = domain_classifier or DomainClassifier()

    def assess(self, host_or_url: str) -> VendorVerdict:
        """Return a :class:`VendorVerdict` for a hostname or full URL."""
        host = _to_host(host_or_url)
        cls: DomainClassification = self._clf.classify(host)
        is_known = cls.classification in (
            DomainClass.TRUSTED, DomainClass.COMMON_BENIGN
        )
        change_type = (
            _CATEGORY_TO_CHANGE.get(cls.vendor_category) if is_known else None
        )
        return VendorVerdict(
            host=host,
            classification=cls.classification,
            vendor_category=cls.vendor_category,
            score=cls.score,
            signals=list(cls.signals),
            is_known_vendor=is_known,
            is_malicious=(cls.classification == DomainClass.MALICIOUS_INDICATOR),
            is_risky=(cls.classification == DomainClass.RISKY),
            change_type=change_type,
        )


def _to_host(host_or_url: str) -> str:
    """Extract a bare hostname from either a hostname or a full URL."""
    s = (host_or_url or "").strip()
    if not s:
        return ""
    if "://" in s or s.startswith("//"):
        parsed = urlparse(s if "://" in s else f"http:{s}")
        return (parsed.hostname or "").lower()
    # Looks like a bare host already (possibly with a path) — strip any path.
    return s.split("/", 1)[0].lower()
