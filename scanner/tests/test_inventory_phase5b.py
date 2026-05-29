# WebHound — scanner/tests/test_inventory_phase5b.py
# Phase-5B canonical inventory tests.
#
# Validates that HostInventoryEntry tracks discovery_sources +
# last_seen_page in addition to first_seen_page, that downstream
# enrichment fields (vendor_classification, threat_intel_state,
# vt_status, baseline_status) round-trip cleanly, and that the new
# CSP + redirect inventory contribution picks up hosts that no
# rendered element references.

from __future__ import annotations

import pytest

from webhound.core.url_discovery import (
    HostInventoryEntry,
    PageHostContribution,
    _csp_source_hosts,
    aggregate_host_inventory,
    build_response_inventory_contribution,
)


# ---------------------------------------------------------------------------
# HostInventoryEntry: new fields
# ---------------------------------------------------------------------------


def test_inventory_entry_default_state_clean() -> None:
    e = HostInventoryEntry(hostname="cdn.example.com")
    assert e.discovery_sources == set()
    assert e.last_seen_page is None
    assert e.vendor_classification is None
    assert e.threat_intel_state is None
    assert e.vt_status is None
    assert e.baseline_status is None


def test_inventory_entry_add_records_discovery_source() -> None:
    e = HostInventoryEntry(hostname="cdn.example.com")
    e.add(kind="script", url="https://cdn.example.com/lib.js",
          page_url="https://target.test/a")
    e.add(kind="fetch", url="https://cdn.example.com/api",
          page_url="https://target.test/b")
    e.add(kind="csp", url="https://cdn.example.com/",
          page_url="https://target.test/a")
    e.add(kind="redirect", url="https://cdn.example.com/r",
          page_url="https://target.test/a")
    e.add(kind="iframe", url="https://cdn.example.com/x",
          page_url="https://target.test/a")
    # 5 distinct discovery_sources from the kinds added.
    assert e.discovery_sources == {
        "static_html", "browser", "csp", "redirect", "iframe",
    }


def test_inventory_entry_last_seen_page_tracks_latest() -> None:
    e = HostInventoryEntry(hostname="cdn.example.com")
    e.add(kind="script", url="https://cdn.example.com/a.js",
          page_url="https://target.test/a")
    e.add(kind="script", url="https://cdn.example.com/b.js",
          page_url="https://target.test/b")
    assert e.first_seen_page == "https://target.test/a"
    assert e.last_seen_page == "https://target.test/b"


def test_inventory_entry_unknown_kind_falls_back_to_static() -> None:
    e = HostInventoryEntry(hostname="cdn.example.com")
    e.add(kind="some_new_engine_kind", url="https://cdn.example.com/",
          page_url="https://target.test/")
    # Unknown kinds bucket to 'static' to stay backwards-compatible
    # with engines that pre-date the Phase-5 source bucketing.
    assert e.discovery_sources == {"static"}


# ---------------------------------------------------------------------------
# CSP parser
# ---------------------------------------------------------------------------


def test_csp_source_hosts_extracts_basic() -> None:
    csp = "default-src 'self'; script-src 'self' https://cdn.example.com"
    hosts = _csp_source_hosts(csp)
    assert "cdn.example.com" in hosts


def test_csp_source_hosts_skips_keywords_and_nonces() -> None:
    csp = (
        "script-src 'self' 'nonce-abc' 'unsafe-inline' "
        "'sha256-xyz' data: blob: * "
        "https://api.example.com"
    )
    hosts = _csp_source_hosts(csp)
    assert hosts == ["api.example.com"]


def test_csp_source_hosts_strips_wildcards_and_schemes() -> None:
    csp = "img-src *.cdn.example.com https://images.example.com"
    hosts = _csp_source_hosts(csp)
    assert "cdn.example.com" in hosts
    assert "images.example.com" in hosts


def test_csp_source_hosts_only_keeps_known_directives() -> None:
    csp = "report-uri https://reports.example.com/csp; report-to default"
    # report-uri isn't in _CSP_DIRECTIVES_WITH_HOSTS, so reports.example.com
    # is dropped.
    assert _csp_source_hosts(csp) == []


# ---------------------------------------------------------------------------
# build_response_inventory_contribution
# ---------------------------------------------------------------------------


def test_response_inventory_csp_hosts_added() -> None:
    pc = build_response_inventory_contribution(
        "https://target.test/",
        headers={"content-security-policy":
                  "script-src https://cdn.example.com"},
    )
    urls = [u for u, _ in pc.urls]
    assert any("cdn.example.com" in u for u in urls)


def test_response_inventory_redirect_chain_added() -> None:
    pc = build_response_inventory_contribution(
        "https://target.test/",
        redirect_chain=[
            "https://shortener.test/abc",
            "https://target.test/welcome",
        ],
    )
    kinds = [k for _, k in pc.urls]
    assert kinds == ["redirect", "redirect"]


def test_response_inventory_empty_inputs_clean_passthrough() -> None:
    pc = build_response_inventory_contribution(
        "https://target.test/",
    )
    assert pc.urls == []


# ---------------------------------------------------------------------------
# Aggregator picks up the new contributions
# ---------------------------------------------------------------------------


def test_aggregator_folds_csp_hosts_into_inventory() -> None:
    """A CSP-only host (no element references it) should still appear
    in the aggregate inventory tagged with discovery_source='csp'."""
    page = PageHostContribution(
        page_url="https://target.test/",
        page_host="target.test",
        urls=[("https://known.example.com/x.js", "script")],
    )
    csp_contrib = build_response_inventory_contribution(
        "https://target.test/",
        headers={"content-security-policy":
                  "script-src https://csp-only.example.com"},
    )
    inv = aggregate_host_inventory([page, csp_contrib])
    assert "csp-only.example.com" in inv
    assert "csp" in inv["csp-only.example.com"].discovery_sources


def test_aggregator_folds_redirect_chain_into_inventory() -> None:
    page = PageHostContribution(
        page_url="https://target.test/",
        page_host="target.test", urls=[],
    )
    redirect_contrib = build_response_inventory_contribution(
        "https://target.test/",
        redirect_chain=["https://hop.example.com/r"],
    )
    inv = aggregate_host_inventory([page, redirect_contrib])
    assert "hop.example.com" in inv
    assert "redirect" in inv["hop.example.com"].discovery_sources
