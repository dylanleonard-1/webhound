# WebHound — scanner/webhound/frameworks/__init__.py
# Phase-9 framework-aware discovery.

from webhound.frameworks.base import (
    DetectionContext,
    FrameworkDetection,
    FrameworkProfile,
    KnownSurface,
)
from webhound.frameworks.profiles import ALL_PROFILES
from webhound.frameworks.registry import (
    ScanFrameworkResult,
    build_coverage,
    context_from_artifacts,
    detect_from_context,
    detect_scan,
    is_normal_framework_change,
    normal_change_matchers,
)

__all__ = [
    "DetectionContext", "FrameworkDetection", "FrameworkProfile",
    "KnownSurface", "ALL_PROFILES", "ScanFrameworkResult",
    "build_coverage", "context_from_artifacts", "detect_from_context",
    "detect_scan", "is_normal_framework_change", "normal_change_matchers",
]
