# WebHound — scanner/tests/test_threat_intel_coverage.py
# Phase-5C threat-intel coverage validation tests.

from __future__ import annotations

import pytest

from webhound.core.url_discovery import HostInventoryEntry
from webhound.threat_intel.coverage import (
    ThreatIntelCoverageReport,
    audit_threat_intel_coverage,
)


def _make_entry(host: str, **kw) -> HostInventoryEntry:
    e = HostInventoryEntry(hostname=host)
    e.add(kind=kw.get("kind", "script"),
          url=f"https://{host}/", page_url="https://target.test/")
    return e


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------


def test_empty_inventory_reports_full_coverage() -> None:
    r = audit_threat_intel_coverage({})
    assert r.total_hosts == 0
    assert r.classified_hosts == 0
    assert r.coverage_ratio == 1.0
    assert r.has_coverage_gap is False


def test_audit_populates_vendor_classification_on_entry() -> None:
    inv = {
        "fonts.googleapis.com": _make_entry("fonts.googleapis.com"),
        "evil.tk":               _make_entry("evil.tk"),
    }
    audit_threat_intel_coverage(inv)
    assert inv["fonts.googleapis.com"].vendor_classification is not None
    assert inv["fonts.googleapis.com"].threat_intel_state == "checked"
    assert inv["evil.tk"].vendor_classification is not None
    assert inv["evil.tk"].threat_intel_state == "checked"


def test_audit_records_per_tier_histogram() -> None:
    inv = {
        # Trusted (in TRUSTED_DOMAINS list).
        "fonts.googleapis.com": _make_entry("fonts.googleapis.com"),
        # Risky-TLD heuristic.
        "g7vk3-tracking-cdn.tk": _make_entry("g7vk3-tracking-cdn.tk"),
    }
    r = audit_threat_intel_coverage(inv)
    assert r.total_hosts == 2
    assert r.classified_hosts == 2
    # Both went through the classifier, both ended in some tier.
    assert sum(r.per_tier_count.values()) == 2


def test_audit_records_per_source_histogram() -> None:
    e1 = HostInventoryEntry(hostname="cdn.example.com")
    e1.add(kind="script", url="https://cdn.example.com/",
           page_url="https://target.test/")
    e2 = HostInventoryEntry(hostname="api.example.com")
    e2.add(kind="fetch", url="https://api.example.com/",
           page_url="https://target.test/")
    e2.add(kind="csp", url="https://api.example.com/",
           page_url="https://target.test/")
    inv = {"cdn.example.com": e1, "api.example.com": e2}
    r = audit_threat_intel_coverage(inv)
    # cdn.example.com → static_html
    # api.example.com → browser + csp
    assert r.per_source_count.get("static_html", 0) >= 1
    assert r.per_source_count.get("browser", 0) >= 1
    assert r.per_source_count.get("csp", 0) >= 1


def test_audit_flags_externally_enriched_hosts() -> None:
    inv = {"cdn.example.com": _make_entry("cdn.example.com")}
    r = audit_threat_intel_coverage(
        inv, already_enriched={"cdn.example.com"},
    )
    assert r.enriched_via_external_provider == 1
    assert inv["cdn.example.com"].vt_status == "checked"


def test_audit_no_bypass_invariant() -> None:
    """Every host in the inventory must end up classified. Coverage
    ratio = 1.0; unclassified list empty. This is the central
    invariant Phase-5C exists to enforce."""
    inv = {
        f"host-{i}.example.com": _make_entry(f"host-{i}.example.com")
        for i in range(20)
    }
    r = audit_threat_intel_coverage(inv)
    assert r.coverage_ratio == 1.0
    assert r.unclassified_hosts == []
    assert r.has_coverage_gap is False


def test_audit_records_classifier_exception_as_gap() -> None:
    """If the classifier raises for a host, the audit must record the
    gap rather than letting the host silently skip threat-intel."""

    class _BrokenClassifier:
        def classify(self, host: str):
            raise RuntimeError("simulated classifier failure")

    inv = {"weird.example.com": _make_entry("weird.example.com")}
    r = audit_threat_intel_coverage(inv, classifier=_BrokenClassifier())
    assert r.unclassified_hosts == ["weird.example.com"]
    assert r.has_coverage_gap is True
    assert inv["weird.example.com"].threat_intel_state == "unavailable"


def test_audit_to_dict_keys_pinned() -> None:
    r = ThreatIntelCoverageReport(total_hosts=1, classified_hosts=1)
    d = r.to_dict()
    for key in ("total_hosts", "classified_hosts", "unclassified_hosts",
                "per_tier_count", "per_source_count",
                "enriched_via_external_provider", "coverage_ratio",
                "has_coverage_gap"):
        assert key in d
