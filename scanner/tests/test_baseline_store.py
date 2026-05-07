# WebHound — scanner/tests/test_baseline_store.py
# Tests for Phase 14: WADE baseline filesystem persistence.
#
# Covers: save/load round-trip, list, get_latest, delete, target isolation,
# path-traversal protection, invalid JSON handling, missing file handling,
# UUID lookup, and BaselineMetadata contents.

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from webhound.wade.baseline_builder import BaselineBuilder, PageSnapshot, SiteBaseline
from webhound.wade.baseline_store import (
    BaselineMetadata,
    BaselineStore,
    _hostname_from_url,
    _sanitize_hostname,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_baseline(
    target_url: str = "https://example.com",
    scan_id: str | None = None,
    created_at: str | None = None,
    page_count: int = 2,
) -> SiteBaseline:
    sid = scan_id or str(uuid4())
    ts = created_at or datetime.now(timezone.utc).isoformat()
    pages = {
        f"{target_url}/": PageSnapshot(
            url=f"{target_url}/",
            status_code=200,
            content_hash="abc123",
            headers={"content-type": "text/html"},
            script_sources=["https://cdn.example.com/app.js"],
            inline_hashes=["deadbeef"],
            external_domains=["cdn.example.com"],
            form_signatures=["GET||email"],
            cookie_signatures={"session": "HttpOnly;Secure"},
        ),
        f"{target_url}/about": PageSnapshot(
            url=f"{target_url}/about",
            status_code=200,
            content_hash="def456",
            headers={"content-type": "text/html"},
            script_sources=[],
            inline_hashes=[],
            external_domains=[],
            form_signatures=[],
            cookie_signatures={},
        ),
    }
    return SiteBaseline(
        target_url=target_url,
        scan_id=sid,
        created_at=ts,
        pages=pages,
        all_script_sources=["https://cdn.example.com/app.js"],
        all_external_domains=["cdn.example.com"],
        page_count=page_count,
    )


def _store(tmp_path: Path) -> BaselineStore:
    return BaselineStore(tmp_path)


# ---------------------------------------------------------------------------
# BaselineStore — initialisation
# ---------------------------------------------------------------------------


class TestBaselineStoreInit:
    def test_custom_store_dir(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        assert store.store_dir == tmp_path

    def test_store_dir_as_string(self, tmp_path: Path) -> None:
        store = BaselineStore(str(tmp_path))
        assert store.store_dir == tmp_path

    def test_default_store_dir_is_path(self) -> None:
        store = BaselineStore()
        assert isinstance(store.store_dir, Path)


# ---------------------------------------------------------------------------
# save_baseline
# ---------------------------------------------------------------------------


class TestSaveBaseline:
    def test_returns_path(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        path = _store(tmp_path).save_baseline(bl)
        assert isinstance(path, Path)
        assert path.exists()

    def test_file_is_json(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        path = _store(tmp_path).save_baseline(bl)
        payload = json.loads(path.read_text())
        assert isinstance(payload, dict)

    def test_envelope_keys(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        path = _store(tmp_path).save_baseline(bl)
        envelope = json.loads(path.read_text())
        for key in ("webhound_baseline_version", "scan_id", "target_url",
                    "created_at", "page_count", "baseline"):
            assert key in envelope

    def test_filename_is_scan_id(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        path = _store(tmp_path).save_baseline(bl)
        assert path.stem == bl.scan_id

    def test_file_in_hostname_subdir(self, tmp_path: Path) -> None:
        bl = _make_baseline(target_url="https://example.com")
        path = _store(tmp_path).save_baseline(bl)
        assert path.parent.name == "example.com"

    def test_creates_subdir_on_first_save(self, tmp_path: Path) -> None:
        bl = _make_baseline(target_url="https://newhost.example.org")
        _store(tmp_path).save_baseline(bl)
        assert (tmp_path / "newhost.example.org").is_dir()

    def test_overwrite_same_scan_id(self, tmp_path: Path) -> None:
        sid = str(uuid4())
        bl1 = _make_baseline(scan_id=sid, page_count=1)
        bl2 = _make_baseline(scan_id=sid, page_count=5)
        store = _store(tmp_path)
        store.save_baseline(bl1)
        store.save_baseline(bl2)
        envelope = json.loads(
            (tmp_path / "example.com" / f"{sid}.json").read_text()
        )
        assert envelope["page_count"] == 5


# ---------------------------------------------------------------------------
# load_baseline — round-trip
# ---------------------------------------------------------------------------


class TestLoadBaseline:
    def test_round_trip_by_path(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(path)
        assert loaded.scan_id == bl.scan_id
        assert loaded.target_url == bl.target_url
        assert loaded.page_count == bl.page_count

    def test_round_trip_pages(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(path)
        assert set(loaded.pages.keys()) == set(bl.pages.keys())

    def test_page_snapshot_fields(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(path)
        snap = loaded.pages["https://example.com/"]
        assert snap.content_hash == "abc123"
        assert snap.script_sources == ["https://cdn.example.com/app.js"]
        assert snap.cookie_signatures == {"session": "HttpOnly;Secure"}

    def test_load_by_scan_id_string(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        store.save_baseline(bl)
        loaded = store.load_baseline(bl.scan_id)
        assert loaded.scan_id == bl.scan_id

    def test_load_by_absolute_path_string(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(str(path))
        assert loaded.scan_id == bl.scan_id

    def test_load_preserves_all_script_sources(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(path)
        assert loaded.all_script_sources == bl.all_script_sources

    def test_load_preserves_all_external_domains(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        loaded = store.load_baseline(path)
        assert loaded.all_external_domains == bl.all_external_domains

    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        missing = tmp_path / "example.com" / "nope.json"
        with pytest.raises(FileNotFoundError):
            store.load_baseline(missing)

    def test_missing_uuid_raises_file_not_found(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(FileNotFoundError):
            store.load_baseline(str(uuid4()))

    def test_invalid_json_raises_value_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "example.com" / "broken.json"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_text("not valid json {{{{", encoding="utf-8")
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="Invalid JSON"):
            store.load_baseline(bad_file)

    def test_missing_baseline_key_raises_value_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "example.com" / "nok.json"
        bad_file.parent.mkdir(parents=True, exist_ok=True)
        bad_file.write_text(json.dumps({"scan_id": "x", "no_baseline": True}), encoding="utf-8")
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="Missing 'baseline'"):
            store.load_baseline(bad_file)


# ---------------------------------------------------------------------------
# list_baselines
# ---------------------------------------------------------------------------


class TestListBaselines:
    def test_empty_when_no_baselines(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        assert store.list_baselines("https://example.com") == []

    def test_returns_one_entry(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        store.save_baseline(bl)
        metas = store.list_baselines("https://example.com")
        assert len(metas) == 1

    def test_returns_multiple_entries(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        for _ in range(3):
            store.save_baseline(_make_baseline())
        metas = store.list_baselines("https://example.com")
        assert len(metas) == 3

    def test_metadata_fields(self, tmp_path: Path) -> None:
        bl = _make_baseline(page_count=4)
        store = _store(tmp_path)
        store.save_baseline(bl)
        meta = store.list_baselines("https://example.com")[0]
        assert meta.scan_id == bl.scan_id
        assert meta.target_url == bl.target_url
        assert meta.page_count == 4
        assert isinstance(meta.file_path, Path)

    def test_corrupt_file_skipped_in_listing(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save_baseline(_make_baseline())
        # Plant a corrupt file
        bad = tmp_path / "example.com" / "corrupt.json"
        bad.write_text("{{ bad", encoding="utf-8")
        metas = store.list_baselines("https://example.com")
        assert len(metas) == 1  # only the valid one

    def test_metadata_to_dict(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        store.save_baseline(bl)
        meta = store.list_baselines("https://example.com")[0]
        d = meta.to_dict()
        assert d["scan_id"] == bl.scan_id
        assert "file_path" in d


# ---------------------------------------------------------------------------
# get_latest_baseline
# ---------------------------------------------------------------------------


class TestGetLatestBaseline:
    def test_returns_none_when_empty(self, tmp_path: Path) -> None:
        assert _store(tmp_path).get_latest_baseline("https://example.com") is None

    def test_returns_only_baseline_when_one(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        store.save_baseline(bl)
        latest = store.get_latest_baseline("https://example.com")
        assert latest is not None
        assert latest.scan_id == bl.scan_id

    def test_returns_most_recent_by_created_at(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        bl_old = _make_baseline(created_at="2025-01-01T00:00:00+00:00")
        bl_new = _make_baseline(created_at="2025-06-01T00:00:00+00:00")
        bl_mid = _make_baseline(created_at="2025-03-01T00:00:00+00:00")
        for bl in (bl_old, bl_new, bl_mid):
            store.save_baseline(bl)
        latest = store.get_latest_baseline("https://example.com")
        assert latest is not None
        assert latest.scan_id == bl_new.scan_id

    def test_latest_has_correct_pages(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save_baseline(_make_baseline(created_at="2025-01-01T00:00:00+00:00"))
        bl_new = _make_baseline(created_at="2025-12-01T00:00:00+00:00")
        store.save_baseline(bl_new)
        latest = store.get_latest_baseline("https://example.com")
        assert latest is not None
        assert set(latest.pages.keys()) == set(bl_new.pages.keys())


# ---------------------------------------------------------------------------
# delete_baseline
# ---------------------------------------------------------------------------


class TestDeleteBaseline:
    def test_delete_by_scan_id(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        store.save_baseline(bl)
        store.delete_baseline(bl.scan_id)
        assert store.list_baselines("https://example.com") == []

    def test_delete_by_path(self, tmp_path: Path) -> None:
        bl = _make_baseline()
        store = _store(tmp_path)
        path = store.save_baseline(bl)
        store.delete_baseline(path)
        assert not path.exists()

    def test_delete_raises_for_missing_file(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(FileNotFoundError):
            store.delete_baseline(str(uuid4()))

    def test_delete_removes_only_target_file(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        bl1 = _make_baseline()
        bl2 = _make_baseline()
        store.save_baseline(bl1)
        store.save_baseline(bl2)
        store.delete_baseline(bl1.scan_id)
        remaining = store.list_baselines("https://example.com")
        assert len(remaining) == 1
        assert remaining[0].scan_id == bl2.scan_id


# ---------------------------------------------------------------------------
# Target isolation
# ---------------------------------------------------------------------------


class TestTargetIsolation:
    def test_separate_targets_separate_directories(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        bl_a = _make_baseline(target_url="https://alpha.com")
        bl_b = _make_baseline(target_url="https://beta.com")
        store.save_baseline(bl_a)
        store.save_baseline(bl_b)
        assert (tmp_path / "alpha.com").is_dir()
        assert (tmp_path / "beta.com").is_dir()

    def test_list_returns_only_target_baselines(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save_baseline(_make_baseline(target_url="https://alpha.com"))
        store.save_baseline(_make_baseline(target_url="https://beta.com"))
        alpha_metas = store.list_baselines("https://alpha.com")
        beta_metas = store.list_baselines("https://beta.com")
        assert len(alpha_metas) == 1
        assert len(beta_metas) == 1
        assert alpha_metas[0].target_url == "https://alpha.com"
        assert beta_metas[0].target_url == "https://beta.com"

    def test_get_latest_scoped_to_target(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        bl_a = _make_baseline(target_url="https://alpha.com",
                               created_at="2025-12-01T00:00:00+00:00")
        bl_b = _make_baseline(target_url="https://beta.com",
                               created_at="2025-06-01T00:00:00+00:00")
        store.save_baseline(bl_a)
        store.save_baseline(bl_b)
        latest_a = store.get_latest_baseline("https://alpha.com")
        assert latest_a is not None
        assert latest_a.scan_id == bl_a.scan_id

    def test_unknown_target_returns_empty_list(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save_baseline(_make_baseline(target_url="https://example.com"))
        assert store.list_baselines("https://other.com") == []


# ---------------------------------------------------------------------------
# Path traversal and filename sanitization
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_hostname_sanitized_for_directory(self, tmp_path: Path) -> None:
        # Hostname with path separator characters must not escape store_dir
        bl = _make_baseline(target_url="https://normal.example.com")
        path = _store(tmp_path).save_baseline(bl)
        assert str(tmp_path) in str(path)
        assert ".." not in str(path)

    def test_sanitize_hostname_replaces_slashes(self) -> None:
        result = _sanitize_hostname("../../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_sanitize_hostname_allows_dots_hyphens(self) -> None:
        result = _sanitize_hostname("sub.example-site.com")
        assert result == "sub.example-site.com"

    def test_sanitize_hostname_truncated_at_128_chars(self) -> None:
        long_host = "a" * 200
        assert len(_sanitize_hostname(long_host)) == 128

    def test_sanitize_empty_hostname_returns_unknown(self) -> None:
        assert _sanitize_hostname("") == "unknown"

    def test_load_traversal_path_raises(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="Path traversal"):
            store.load_baseline("../../../etc/passwd")

    def test_load_traversal_dotdot_raises(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="Path traversal"):
            store.load_baseline("../../secret.json")

    def test_delete_traversal_path_raises(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(ValueError, match="Path traversal"):
            store.delete_baseline("../../some_file.json")

    def test_invalid_scan_id_not_treated_as_uuid(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        # A string with a slash should not match UUID pattern and go to path branch
        with pytest.raises(ValueError, match="Path traversal"):
            store.load_baseline("../evil.json")


# ---------------------------------------------------------------------------
# hostname_from_url helper
# ---------------------------------------------------------------------------


class TestHostnameFromUrl:
    def test_https_url(self) -> None:
        assert _hostname_from_url("https://example.com/path") == "example.com"

    def test_http_url(self) -> None:
        assert _hostname_from_url("http://sub.example.com") == "sub.example.com"

    def test_url_with_port(self) -> None:
        assert _hostname_from_url("https://example.com:8443/") == "example.com"

    def test_empty_string_returns_unknown(self) -> None:
        assert _hostname_from_url("") == "unknown"
