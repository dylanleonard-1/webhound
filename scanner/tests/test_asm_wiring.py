# WebHound — scanner/tests/test_asm_wiring.py
# Phase-4 slice C: ASM enabled in the ENTERPRISE profile, optional
# everywhere else. The orchestrator integration test lives elsewhere;
# these tests pin the *configuration* contract end-to-end.

from __future__ import annotations

import pytest

from webhound.core.scan_profiles import (
    DEEP,
    ENTERPRISE,
    PROFILES,
    QUICK,
    STANDARD,
    MONITOR,
    get_profile,
)


# ---------------------------------------------------------------------------
# Profile registry
# ---------------------------------------------------------------------------


def test_enterprise_profile_registered() -> None:
    assert "enterprise" in PROFILES
    assert get_profile("enterprise") is ENTERPRISE


def test_enterprise_is_only_profile_with_asm_enabled() -> None:
    assert ENTERPRISE.asm_enabled is True
    for p in (QUICK, STANDARD, DEEP, MONITOR):
        assert p.asm_enabled is False, (
            f"profile {p.name} unexpectedly has asm_enabled=True"
        )


def test_enterprise_profile_to_scan_options_propagates_flag() -> None:
    opts = ENTERPRISE.to_scan_options()
    assert opts.asm_enabled is True


def test_non_enterprise_to_scan_options_keeps_flag_false() -> None:
    for p in (QUICK, STANDARD, DEEP, MONITOR):
        opts = p.to_scan_options()
        assert opts.asm_enabled is False


def test_enterprise_summary_includes_asm_flag() -> None:
    summary = ENTERPRISE.summary()
    assert summary["asm_enabled"] is True
    assert summary["name"] == "enterprise"


def test_enterprise_pages_and_depth_are_deep_or_more() -> None:
    """ENTERPRISE must crawl at least as much as DEEP — it's the
    'attack-surface review' tier."""
    assert ENTERPRISE.max_pages >= DEEP.max_pages
    assert ENTERPRISE.max_depth >= DEEP.max_depth


# ---------------------------------------------------------------------------
# ScanOptions default — confirm flag is opt-in
# ---------------------------------------------------------------------------


def test_scan_options_default_asm_enabled_false() -> None:
    from webhound.models.target import ScanOptions
    assert ScanOptions().asm_enabled is False
