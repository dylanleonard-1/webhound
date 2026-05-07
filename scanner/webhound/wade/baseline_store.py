# WebHound — scanner/webhound/wade/baseline_store.py
# Local filesystem persistence for WADE SiteBaseline objects.
#
# Baselines are stored as JSON files under a configurable store directory,
# one subdirectory per hostname, one file per scan:
#
#     store_dir/
#       example.com/
#         <scan-uuid>.json
#       sub.example.com/
#         <scan-uuid>.json
#
# Cookie values are never stored — PageSnapshot only captures security flags
# (Secure, HttpOnly, SameSite=…), so no credentials reach the file system.

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .baseline_builder import BaselineBuilder, SiteBaseline

# Default location; callers may always supply a different ``store_dir``.
_DEFAULT_STORE_DIR: Path = Path.home() / ".webhound" / "baselines"

# Only these characters are allowed in the hostname directory component.
_SAFE_CHAR_RE: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9._-]")

# Scan IDs are UUID v4 strings: 8-4-4-4-12 hex digits and hyphens.
_SCAN_ID_RE: re.Pattern[str] = re.compile(
    r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"
)

_MAX_HOSTNAME_LEN: int = 128


class BaselineMetadata:
    """Lightweight envelope summary for one saved baseline (no page data)."""

    __slots__ = ("scan_id", "target_url", "created_at", "page_count", "file_path")

    def __init__(
        self,
        scan_id: str,
        target_url: str,
        created_at: str,
        page_count: int,
        file_path: Path,
    ) -> None:
        self.scan_id = scan_id
        self.target_url = target_url
        self.created_at = created_at
        self.page_count = page_count
        self.file_path = file_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "created_at": self.created_at,
            "page_count": self.page_count,
            "file_path": str(self.file_path),
        }


class BaselineStore:
    """Save and load WADE :class:`SiteBaseline` objects on the local filesystem.

    Usage::

        store = BaselineStore()                          # default ~/.webhound/baselines
        store = BaselineStore("/tmp/webhound-test")      # custom directory

        path = store.save_baseline(baseline)
        bl   = store.load_baseline(path)                 # by path
        bl   = store.load_baseline(baseline.scan_id)     # by UUID

        latest = store.get_latest_baseline("https://example.com")
        metas  = store.list_baselines("https://example.com")
        store.delete_baseline(baseline.scan_id)
    """

    def __init__(self, store_dir: Path | str | None = None) -> None:
        self._store_dir = (
            Path(store_dir) if store_dir is not None else _DEFAULT_STORE_DIR
        )

    @property
    def store_dir(self) -> Path:
        """Root directory where baselines are persisted."""
        return self._store_dir

    # ------------------------------------------------------------------
    # Core I/O
    # ------------------------------------------------------------------

    def save_baseline(self, baseline: SiteBaseline) -> Path:
        """Serialise ``baseline`` to JSON and return its file path.

        The file is placed at ``store_dir/<hostname>/<scan_id>.json``.
        The hostname directory is created if it does not already exist.
        """
        hostname = _hostname_from_url(baseline.target_url)
        target_dir = self._store_dir / _sanitize_hostname(hostname)
        target_dir.mkdir(parents=True, exist_ok=True)

        file_path = target_dir / f"{baseline.scan_id}.json"
        envelope: dict[str, Any] = {
            "webhound_baseline_version": 1,
            "scan_id": baseline.scan_id,
            "target_url": baseline.target_url,
            "created_at": baseline.created_at,
            "page_count": baseline.page_count,
            "baseline": BaselineBuilder().to_dict(baseline),
        }
        file_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        return file_path

    def load_baseline(self, path_or_id: Path | str) -> SiteBaseline:
        """Return the :class:`SiteBaseline` stored at ``path_or_id``.

        ``path_or_id`` may be:

        - An absolute :class:`Path` or path string ending in ``.json``.
        - A relative path resolved within ``store_dir`` (path traversal is
          rejected).
        - A UUID scan-id string; the store directory tree is searched.

        Raises :exc:`FileNotFoundError` if no matching file exists.
        Raises :exc:`ValueError` for invalid JSON or a malformed file.
        """
        file_path = self._resolve_path(path_or_id)
        if not file_path.exists():
            raise FileNotFoundError(f"Baseline file not found: {file_path}")

        raw = file_path.read_text(encoding="utf-8")
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in baseline file {file_path}: {exc}"
            ) from exc

        if "baseline" not in envelope:
            raise ValueError(f"Missing 'baseline' key in {file_path}")

        return BaselineBuilder().from_dict(envelope["baseline"])

    def get_latest_baseline(self, target_url: str) -> SiteBaseline | None:
        """Return the baseline with the most recent ``created_at`` for *target_url*.

        Returns ``None`` when no baselines exist for the given target.
        """
        metas = self.list_baselines(target_url)
        if not metas:
            return None
        latest = max(metas, key=lambda m: m.created_at)
        return self.load_baseline(latest.file_path)

    def list_baselines(self, target_url: str) -> list[BaselineMetadata]:
        """Return :class:`BaselineMetadata` for every saved baseline for *target_url*.

        Files that cannot be parsed (corrupt, missing envelope keys) are
        silently skipped so one bad file never breaks the full listing.
        Returns an empty list when no baselines exist.
        """
        hostname = _hostname_from_url(target_url)
        target_dir = self._store_dir / _sanitize_hostname(hostname)
        if not target_dir.is_dir():
            return []

        metas: list[BaselineMetadata] = []
        for json_file in sorted(target_dir.glob("*.json")):
            meta = _read_metadata(json_file)
            if meta is not None:
                metas.append(meta)
        return metas

    def delete_baseline(self, path_or_id: Path | str) -> None:
        """Remove a baseline file from disk.

        Raises :exc:`FileNotFoundError` when the file does not exist.
        """
        file_path = self._resolve_path(path_or_id)
        if not file_path.exists():
            raise FileNotFoundError(f"Baseline file not found: {file_path}")
        file_path.unlink()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, path_or_id: Path | str) -> Path:
        """Resolve *path_or_id* to an absolute :class:`Path`.

        Lookup order:
        1. UUID string → search subdirectories under ``store_dir``.
        2. Absolute path → used directly.
        3. Relative path → anchored to ``store_dir``; traversal raises ValueError.
        """
        path_str = str(path_or_id)

        # UUID lookup — must match strict pattern to prevent traversal.
        if _SCAN_ID_RE.match(path_str):
            return self._find_by_scan_id(path_str)

        p = Path(path_or_id)
        if p.is_absolute():
            return p.resolve()

        # Relative path: resolve inside store_dir and enforce containment.
        resolved = (self._store_dir / p).resolve()
        store_resolved = self._store_dir.resolve()
        try:
            resolved.relative_to(store_resolved)
        except ValueError:
            raise ValueError(f"Path traversal detected: {path_or_id!r}")
        return resolved

    def _find_by_scan_id(self, scan_id: str) -> Path:
        """Search all hostname subdirectories for ``<scan_id>.json``."""
        if self._store_dir.is_dir():
            for subdir in self._store_dir.iterdir():
                if subdir.is_dir():
                    candidate = subdir / f"{scan_id}.json"
                    if candidate.exists():
                        return candidate
        # Return a non-existent path; caller raises FileNotFoundError.
        return self._store_dir / f"{scan_id}.json"


# ---------------------------------------------------------------------------
# Module-level helpers (not part of the public API)
# ---------------------------------------------------------------------------


def _sanitize_hostname(hostname: str) -> str:
    """Strip non-filesystem-safe characters from a hostname string.

    Also collapses ``..`` sequences so the result can never escape the
    store directory when used as a Path component.
    """
    safe = _SAFE_CHAR_RE.sub("_", hostname)
    while ".." in safe:
        safe = safe.replace("..", "_")
    return (safe or "unknown")[:_MAX_HOSTNAME_LEN]


def _hostname_from_url(url: str) -> str:
    """Extract the hostname component from a URL string."""
    parsed = urlparse(url)
    return parsed.hostname or "unknown"


def _read_metadata(json_file: Path) -> BaselineMetadata | None:
    """Parse only envelope fields from *json_file*; return None on any error."""
    try:
        envelope = json.loads(json_file.read_text(encoding="utf-8"))
        return BaselineMetadata(
            scan_id=envelope["scan_id"],
            target_url=envelope["target_url"],
            created_at=envelope["created_at"],
            page_count=int(envelope["page_count"]),
            file_path=json_file,
        )
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        return None
