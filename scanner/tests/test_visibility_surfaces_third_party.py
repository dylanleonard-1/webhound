# WebHound — scanner/tests/test_visibility_surfaces_third_party.py
# Phase 8 tests: third-party mapping section. Reuses the real
# graph.relationship_extractor.vendor_for_host classifier. No network.

from __future__ import annotations

from webhound.core.visibility.surfaces import build_third_party_section


def test_classifies_and_counts_hosts():
    hosts = [
        "www.google-analytics.com",
        "fonts.googleapis.com",
        "totally-unknown-vendor-xyz.example",
    ]
    section = build_third_party_section(hosts, primary_host="example.com")
    assert section["count"] == 3
    # Every host gets a category bucket.
    assert sum(section["by_category"].values()) == 3
    # The made-up host is unknown.
    assert section["unknown"] >= 1


def test_excludes_primary_and_dedupes():
    hosts = ["example.com", "cdn.vendor.com", "cdn.vendor.com"]
    section = build_third_party_section(hosts, primary_host="example.com")
    # primary excluded, duplicate collapsed → 1 unique host.
    assert section["count"] == 1
    assert section["hosts"][0]["host"] == "cdn.vendor.com"


def test_empty_host_list():
    section = build_third_party_section([], primary_host="example.com")
    assert section["count"] == 0
    assert section["by_category"] == {}


def test_none_host_list():
    section = build_third_party_section(None, primary_host="example.com")
    assert section["count"] == 0
