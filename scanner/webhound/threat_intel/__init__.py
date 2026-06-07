# WebHound — scanner/webhound/threat_intel/__init__.py

from .domain_classifier import DomainClass, DomainClassification, DomainClassifier
from .enrichment_service import (
    BaseProvider,
    EnrichmentResult,
    EnrichmentService,
    ProviderResult,
)
from .urlhaus_client import UrlhausClient
from .virustotal_client import VirusTotalClient
# Phase-13 advanced threat intelligence + supply chain.
from .brand_impersonation import (
    ImpersonationVerdict,
    assess_domain,
)
from .domain_reputation import (
    DomainReputation,
    DomainReputationEngine,
    ReputationClass,
)
from .feed_manager import FeedManager, FeedMatch
from .feed_normalizer import (
    IndicatorKind,
    ThreatCategory,
    ThreatIndicator,
)
from .reputation_cache import ReputationCache
from .script_reputation import (
    ScriptReputation,
    ScriptReputationEngine,
    ScriptVerdict,
)
from .supply_chain import (
    SupplyChainChange,
    SupplyChainChangeType,
    SupplyChainEngine,
)
from .threat_correlation import (
    ThreatCorrelation,
    ThreatCorrelationType,
    ThreatSignals,
    WadeVendorEvent,
    classify_wade_vendor_event,
    correlate_threats,
)

__all__ = [
    "DomainClass",
    "DomainClassification",
    "DomainClassifier",
    "BaseProvider",
    "EnrichmentResult",
    "EnrichmentService",
    "ProviderResult",
    "UrlhausClient",
    "VirusTotalClient",
    "ImpersonationVerdict", "assess_domain",
    "DomainReputation", "DomainReputationEngine", "ReputationClass",
    "FeedManager", "FeedMatch", "IndicatorKind", "ThreatCategory",
    "ThreatIndicator", "ReputationCache", "ScriptReputation",
    "ScriptReputationEngine", "ScriptVerdict", "SupplyChainChange",
    "SupplyChainChangeType", "SupplyChainEngine", "ThreatCorrelation",
    "ThreatCorrelationType", "ThreatSignals", "WadeVendorEvent",
    "classify_wade_vendor_event", "correlate_threats",
]
