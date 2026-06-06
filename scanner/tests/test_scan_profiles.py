# WebHound — scanner/tests/test_scan_profiles.py
# Tests for Phase 15: scan configuration profiles and baseline-aware runner.
#
# Covers: each profile's field values, get_profile validation, to_scan_options
# mapping, profile registry completeness, run_scan argument parsing helpers,
# and report filename generation.

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from webhound.core.scan_profiles import (
    DEEP,
    MONITOR,
    PROFILE_NAMES,
    PROFILES,
    QUICK,
    STANDARD,
    ScanProfile,
    get_profile,
)
from webhound.models.target import ScanOptions


# ---------------------------------------------------------------------------
# Profile registry
# ---------------------------------------------------------------------------


class TestProfileRegistry:
    def test_five_profiles_registered(self) -> None:
        assert len(PROFILES) == 5

    def test_expected_names_present(self) -> None:
        assert set(PROFILES) == {
            "quick", "standard", "deep", "monitor", "enterprise",
        }

    def test_profile_names_tuple_sorted(self) -> None:
        assert PROFILE_NAMES == tuple(sorted(PROFILES))

    def test_all_profiles_are_scan_profile_instances(self) -> None:
        for p in PROFILES.values():
            assert isinstance(p, ScanProfile)

    def test_profiles_are_frozen(self) -> None:
        with pytest.raises((AttributeError, TypeError)):
            QUICK.max_pages = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# get_profile
# ---------------------------------------------------------------------------


class TestGetProfile:
    def test_returns_quick(self) -> None:
        assert get_profile("quick") is QUICK

    def test_returns_standard(self) -> None:
        assert get_profile("standard") is STANDARD

    def test_returns_deep(self) -> None:
        assert get_profile("deep") is DEEP

    def test_returns_monitor(self) -> None:
        assert get_profile("monitor") is MONITOR

    def test_unknown_profile_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown scan profile"):
            get_profile("turbo")

    def test_error_message_lists_valid_names(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            get_profile("ghost")
        msg = str(exc_info.value)
        for name in ("quick", "standard", "deep", "monitor"):
            assert name in msg

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            get_profile("")

    def test_case_sensitive(self) -> None:
        with pytest.raises(ValueError):
            get_profile("Quick")

    def test_whitespace_raises(self) -> None:
        with pytest.raises(ValueError):
            get_profile("quick ")


# ---------------------------------------------------------------------------
# QUICK profile
# ---------------------------------------------------------------------------


class TestQuickProfile:
    def test_name(self) -> None:
        assert QUICK.name == "quick"

    def test_max_pages(self) -> None:
        assert QUICK.max_pages == 5

    def test_max_depth(self) -> None:
        assert QUICK.max_depth == 1

    def test_rate_limit_rps(self) -> None:
        assert QUICK.rate_limit_rps == 1.0

    def test_request_timeout(self) -> None:
        assert QUICK.request_timeout_seconds == 15

    def test_include_subdomains_false(self) -> None:
        assert QUICK.include_subdomains is False

    def test_respect_robots_true(self) -> None:
        assert QUICK.respect_robots_txt is True

    def test_verify_tls_true(self) -> None:
        assert QUICK.verify_tls is True

    def test_has_description(self) -> None:
        assert QUICK.description


# ---------------------------------------------------------------------------
# STANDARD profile
# ---------------------------------------------------------------------------


class TestStandardProfile:
    def test_name(self) -> None:
        assert STANDARD.name == "standard"

    def test_max_pages(self) -> None:
        assert STANDARD.max_pages == 25

    def test_max_depth(self) -> None:
        assert STANDARD.max_depth == 2

    def test_rate_limit_rps(self) -> None:
        assert STANDARD.rate_limit_rps == 1.0

    def test_verify_tls(self) -> None:
        assert STANDARD.verify_tls is True

    def test_respect_robots(self) -> None:
        assert STANDARD.respect_robots_txt is True


# ---------------------------------------------------------------------------
# DEEP profile
# ---------------------------------------------------------------------------


class TestDeepProfile:
    def test_name(self) -> None:
        assert DEEP.name == "deep"

    def test_max_pages_at_least_100(self) -> None:
        assert DEEP.max_pages >= 100

    def test_max_depth_at_least_3(self) -> None:
        assert DEEP.max_depth >= 3

    def test_rate_limit_polite(self) -> None:
        # Deep should be slower to avoid hammering the server
        assert DEEP.rate_limit_rps <= 1.0

    def test_verify_tls(self) -> None:
        assert DEEP.verify_tls is True

    def test_respect_robots(self) -> None:
        assert DEEP.respect_robots_txt is True

    def test_include_subdomains_false(self) -> None:
        assert DEEP.include_subdomains is False


# ---------------------------------------------------------------------------
# MONITOR profile
# ---------------------------------------------------------------------------


class TestMonitorProfile:
    def test_name(self) -> None:
        assert MONITOR.name == "monitor"

    def test_max_pages(self) -> None:
        assert MONITOR.max_pages == 10

    def test_max_depth(self) -> None:
        assert MONITOR.max_depth == 1

    def test_rate_limit_polite(self) -> None:
        assert MONITOR.rate_limit_rps <= 1.0

    def test_verify_tls(self) -> None:
        assert MONITOR.verify_tls is True

    def test_respect_robots(self) -> None:
        assert MONITOR.respect_robots_txt is True


# ---------------------------------------------------------------------------
# Safety invariants — no profile may enable unsafe behaviour
# ---------------------------------------------------------------------------


class TestProfileSafetyInvariants:
    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_verify_tls_always_true(self, profile: ScanProfile) -> None:
        assert profile.verify_tls is True

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_respect_robots_always_true(self, profile: ScanProfile) -> None:
        assert profile.respect_robots_txt is True

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_include_subdomains_always_false(self, profile: ScanProfile) -> None:
        assert profile.include_subdomains is False

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_rate_limit_rps_never_exceeds_2(self, profile: ScanProfile) -> None:
        assert profile.rate_limit_rps <= 2.0

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_rate_limit_rps_positive(self, profile: ScanProfile) -> None:
        assert profile.rate_limit_rps > 0

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_max_pages_at_least_1(self, profile: ScanProfile) -> None:
        assert profile.max_pages >= 1

    @pytest.mark.parametrize("profile", list(PROFILES.values()))
    def test_max_depth_at_least_1(self, profile: ScanProfile) -> None:
        assert profile.max_depth >= 1


# ---------------------------------------------------------------------------
# to_scan_options mapping
# ---------------------------------------------------------------------------


class TestToScanOptions:
    def _check_mapping(self, profile: ScanProfile) -> ScanOptions:
        opts = profile.to_scan_options()
        assert isinstance(opts, ScanOptions)
        assert opts.max_pages == profile.max_pages
        assert opts.max_depth == profile.max_depth
        assert opts.rate_limit_rps == profile.rate_limit_rps
        assert opts.request_timeout_seconds == profile.request_timeout_seconds
        assert opts.include_subdomains == profile.include_subdomains
        assert opts.respect_robots_txt == profile.respect_robots_txt
        assert opts.verify_tls == profile.verify_tls
        return opts

    def test_quick_maps_correctly(self) -> None:
        self._check_mapping(QUICK)

    def test_standard_maps_correctly(self) -> None:
        self._check_mapping(STANDARD)

    def test_deep_maps_correctly(self) -> None:
        self._check_mapping(DEEP)

    def test_monitor_maps_correctly(self) -> None:
        self._check_mapping(MONITOR)

    def test_returns_scan_options_instance(self) -> None:
        assert isinstance(QUICK.to_scan_options(), ScanOptions)

    def test_each_call_returns_new_instance(self) -> None:
        a = STANDARD.to_scan_options()
        b = STANDARD.to_scan_options()
        assert a is not b


# ---------------------------------------------------------------------------
# ScanProfile.summary()
# ---------------------------------------------------------------------------


class TestScanProfileSummary:
    def test_summary_is_dict(self) -> None:
        assert isinstance(QUICK.summary(), dict)

    def test_summary_contains_required_keys(self) -> None:
        d = STANDARD.summary()
        for key in (
            "name", "description", "max_pages", "max_depth",
            "rate_limit_rps", "request_timeout_seconds",
            "include_subdomains", "respect_robots_txt", "verify_tls",
        ):
            assert key in d

    def test_summary_values_match_profile(self) -> None:
        d = DEEP.summary()
        assert d["name"] == "deep"
        assert d["max_pages"] == DEEP.max_pages
        assert d["rate_limit_rps"] == DEEP.rate_limit_rps


# ---------------------------------------------------------------------------
# run_scan argument parser
# ---------------------------------------------------------------------------


class TestRunScanArgParser:
    """Import and exercise the argument parser from run_scan without running a scan."""

    def _parser(self) -> argparse.ArgumentParser:
        import importlib.util, sys
        from pathlib import Path

        # Import run_scan without executing main()
        spec = importlib.util.spec_from_file_location(
            "run_scan",
            Path(__file__).parent.parent / "run_scan.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod._build_arg_parser()  # type: ignore[attr-defined]

    def test_default_profile_is_standard(self) -> None:
        args = self._parser().parse_args(["https://example.com"])
        assert args.profile == "standard"

    def test_profile_flag_accepted(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--profile", "quick"])
        assert args.profile == "quick"

    def test_save_baseline_flag(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--save-baseline"])
        assert args.save_baseline is True

    def test_use_latest_baseline_flag(self) -> None:
        args = self._parser().parse_args(
            ["https://example.com", "--use-latest-baseline"]
        )
        assert args.use_latest_baseline is True

    def test_baseline_store_path(self, tmp_path: Path) -> None:
        args = self._parser().parse_args(
            ["https://example.com", "--baseline-store", str(tmp_path)]
        )
        assert args.baseline_store == str(tmp_path)

    def test_output_dir_flag(self, tmp_path: Path) -> None:
        args = self._parser().parse_args(
            ["https://example.com", "--output-dir", str(tmp_path)]
        )
        assert args.output_dir == str(tmp_path)

    def test_invalid_profile_raises(self) -> None:
        with pytest.raises(SystemExit):
            self._parser().parse_args(["https://example.com", "--profile", "turbo"])

    def test_all_profiles_accepted(self) -> None:
        parser = self._parser()
        for name in PROFILE_NAMES:
            args = parser.parse_args(["https://example.com", "--profile", name])
            assert args.profile == name


# ---------------------------------------------------------------------------
# Report filename helper
# ---------------------------------------------------------------------------


class TestReportFilename:
    def _fn(self, url: str, profile: str) -> str:
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "run_scan",
            Path(__file__).parent.parent / "run_scan.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod._report_filename(url, profile)  # type: ignore[attr-defined]

    def test_filename_contains_hostname(self) -> None:
        name = self._fn("https://example.com", "quick")
        assert "example" in name

    def test_filename_contains_profile(self) -> None:
        name = self._fn("https://example.com", "quick")
        assert "quick" in name

    def test_filename_ends_with_json(self) -> None:
        name = self._fn("https://example.com", "standard")
        assert name.endswith(".json")

    def test_filename_has_no_path_separators(self) -> None:
        name = self._fn("https://sub.example.com", "deep")
        assert "/" not in name
        assert "\\" not in name
