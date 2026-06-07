# WebHound — scanner/webhound/graph/relationship_extractor.py
# Phase-20: pure helpers the graph builder uses to normalize values and
# resolve which graph node a finding / WADE change / threat indicator
# affects. Kept separate so the resolution logic is unit-testable
# without building a whole graph.

from __future__ import annotations

from urllib.parse import urlparse


def hostname(url: str) -> str:
    if not url:
        return ""
    try:
        h = urlparse(url).hostname
        if h:
            return h.lower()
    except Exception:  # noqa: BLE001
        pass
    # Bare host (maybe with a path).
    return (url or "").split("/", 1)[0].lower()


def registrable(host: str) -> str:
    try:
        from webhound.browser.network_capture import _registrable as _r
        return _r(host)
    except Exception:  # noqa: BLE001
        return host


def normalize_url(url: str) -> str:
    """Drop fragments + trailing slashes so the same page normalizes to
    one node (deterministic ids)."""
    if not url:
        return ""
    u = url.split("#", 1)[0]
    if len(u) > 1 and u.endswith("/"):
        u = u[:-1]
    return u


def vendor_for_host(host: str) -> tuple[str | None, str, bool]:
    """(vendor_registrable_domain, vendor_category, is_trusted) for a
    host, via the local DomainClassifier. Unknown hosts return
    (None, 'unknown', False) — never auto-escalated (Task 4/8)."""
    if not host:
        return None, "unknown", False
    try:
        from webhound.threat_intel.domain_classifier import (
            DomainClass, DomainClassifier, vendor_category,
        )
        cls = DomainClassifier().classify(host)
        trusted = cls.classification in (DomainClass.TRUSTED,
                                         DomainClass.COMMON_BENIGN)
        cat = vendor_category(host)
        if trusted or cat != "unknown":
            return cls.registerable_domain or registrable(host), cat, trusted
    except Exception:  # noqa: BLE001
        pass
    return None, "unknown", False


# Diff-type → the node type a WADE change affects (Task 7).
WADE_TARGET_TYPE = {
    "new_script_source": "script",
    "removed_script_source": "script",
    "changed_inline_script": "inline_script",
    "new_external_domain": "third_party_domain",
    "removed_external_domain": "third_party_domain",
    "new_third_party_domain": "third_party_domain",
    "removed_third_party_domain": "third_party_domain",
    "new_api_endpoint": "api_endpoint",
    "removed_api_endpoint": "api_endpoint",
    "new_form": "form",
    "form_field_change": "form",
    "header_added": "header",
    "header_regression": "header",
    "new_iframe": "iframe",
    "redirect_change": "redirect",
    "technology_change": "technology",
}


# Engine → the kind of node a finding is primarily ABOUT, so a finding
# links to the right asset (Task 6).
FINDING_TARGET_HINT = {
    "cookie_scanner": "cookie",
    "security_headers": "header",
    "csp_engine": "header",
    "cors": "header",
    "third_party_domains": "third_party_domain",
    "threat_intel": "third_party_domain",
    "form_risk": "form",
    "input_analysis": "form",
    "endpoint_discovery": "api_endpoint",
    "hidden_iframes": "iframe",
    "injected_js": "script",
    "obfuscation_detector": "script",
    "js_analyzer": "script",
    "sensitive_paths": "page",
    "suspicious_redirects": "redirect",
}
