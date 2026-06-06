# WebHound — tests/test_observed_api_inventory.py
# Phase-6C Task 5: browser-observed API traffic becomes inventory
# findings (INFO), with at most a LOW advisory for admin-style
# endpoints. Never higher — observed != exploitable.

from __future__ import annotations

from webhound.browser.models import NetworkArtifact
from webhound.engines.api_discovery.endpoint_discovery import (
    EndpointDiscoveryEngine,
)
from webhound.models.severity import Severity


def _art(url, kind="fetch", content_type=None) -> NetworkArtifact:
    return NetworkArtifact(
        url=url, method="GET", initiator_kind=kind,
        page_url="https://target.test/", content_type=content_type,
    )


def test_observed_api_traffic_is_info_inventory() -> None:
    engine = EndpointDiscoveryEngine()
    findings = engine.analyze_observed_requests([
        _art("https://target.test/api/v1/products?page=1"),
        _art("https://target.test/api/v1/products?page=2"),   # dedupes
        _art("https://api.vendor.com/v2/collect", kind="xhr"),
        _art("https://target.test/assets/logo.png", kind="image"),  # not API
    ], primary_host="target.test")

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.INFO
    assert "inventory" in f.tags
    assert "browser_network" in f.tags
    assert f.metadata["evidence_source"] == "browser_network"
    # Query-string variants dedupe to one path-level endpoint.
    eps = f.metadata["observed_endpoints"]
    assert "https://target.test/api/v1/products" in eps
    assert len([e for e in eps if "products" in e]) == 1
    assert f.evidence[0].extra["same_origin_count"] == 1
    assert f.evidence[0].extra["cross_origin_count"] == 1


def test_admin_style_endpoint_caps_at_low() -> None:
    engine = EndpointDiscoveryEngine()
    findings = engine.analyze_observed_requests([
        _art("https://target.test/wp-admin/admin-ajax.php", kind="xhr"),
        _art("https://target.test/api/v1/items"),
    ], primary_host="target.test")

    severities = {f.severity for f in findings}
    assert Severity.HIGH not in severities
    assert Severity.CRITICAL not in severities
    admin = [f for f in findings if "Admin-style" in f.title]
    assert len(admin) == 1
    assert admin[0].severity == Severity.LOW
    assert "advisory" in admin[0].tags


def test_no_api_traffic_no_findings() -> None:
    engine = EndpointDiscoveryEngine()
    assert engine.analyze_observed_requests([
        _art("https://target.test/style.css", kind="stylesheet"),
    ], primary_host="target.test") == []
    assert engine.analyze_observed_requests([], primary_host="t") == []
