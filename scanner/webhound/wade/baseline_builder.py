# WebHound — scanner/webhound/wade/baseline_builder.py
# Captures a security-relevant snapshot of a site's observable state from a
# completed crawl so diff_engine can detect changes on the next scan.
# No live external calls are made.

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from webhound.core.crawler import CrawlResult
from webhound.models.scan_result import ScanResult


@dataclass
class PageSnapshot:
    """Security-relevant state captured for one crawled page."""

    url: str
    status_code: int
    content_hash: str                   # SHA-256[:16] of page body
    headers: dict[str, str]             # lowercase response headers
    script_sources: list[str]           # sorted external script src URLs
    inline_hashes: list[str]            # SHA-256[:16] of each inline script block
    external_domains: list[str]         # sorted unique hostnames from external links
    form_signatures: list[str]          # sorted "METHOD|action_url|f1,f2,..."
    cookie_signatures: dict[str, str]   # cookie_name → "Secure;HttpOnly;..."


@dataclass
class SiteBaseline:
    """Aggregated WADE baseline produced from one complete site crawl."""

    target_url: str
    scan_id: str                        # UUID string of source ScanResult
    created_at: str                     # ISO-8601 timestamp
    pages: dict[str, PageSnapshot]      # url → PageSnapshot
    all_script_sources: list[str]       # sorted, deduplicated across all pages
    all_external_domains: list[str]     # sorted, deduplicated across all pages
    page_count: int


class BaselineBuilder:
    """Build a :class:`SiteBaseline` from a completed crawl (no I/O)."""

    def build(
        self,
        crawl_results: list[CrawlResult],
        scan_result: ScanResult,
    ) -> SiteBaseline:
        pages: dict[str, PageSnapshot] = {}
        all_scripts: set[str] = set()
        all_domains: set[str] = set()

        for cr in crawl_results:
            if cr.response.failed or cr.artifacts is None:
                continue
            snap = self._snapshot(cr)
            pages[cr.url] = snap
            all_scripts.update(snap.script_sources)
            all_domains.update(snap.external_domains)

        return SiteBaseline(
            target_url=scan_result.target.base_url,
            scan_id=str(scan_result.id),
            created_at=datetime.now(timezone.utc).isoformat(),
            pages=pages,
            all_script_sources=sorted(all_scripts),
            all_external_domains=sorted(all_domains),
            page_count=len(pages),
        )

    def _snapshot(self, cr: CrawlResult) -> PageSnapshot:
        arts = cr.artifacts
        resp = cr.response

        script_sources = sorted({
            s.src for s in arts.scripts if not s.is_inline and s.src
        })
        inline_hashes = sorted({
            _sha16(s.content) for s in arts.scripts if s.is_inline and s.content
        })
        external_domains = sorted({
            urlparse(link).hostname.lower()
            for link in arts.external_links
            if urlparse(link).hostname
        })
        form_signatures = sorted({_form_sig(f) for f in arts.forms})

        cookie_signatures: dict[str, str] = {}
        for raw in arts.cookies:
            name, flags = _parse_cookie(raw)
            if name:
                cookie_signatures[name] = flags

        return PageSnapshot(
            url=cr.url,
            status_code=resp.status_code,
            content_hash=_sha16(resp.body or ""),
            headers={k.lower(): v for k, v in arts.response_headers.items()},
            script_sources=script_sources,
            inline_hashes=inline_hashes,
            external_domains=external_domains,
            form_signatures=form_signatures,
            cookie_signatures=cookie_signatures,
        )

    # ------------------------------------------------------------------
    # Serialization — round-trips cleanly through JSON
    # ------------------------------------------------------------------

    def to_dict(self, baseline: SiteBaseline) -> dict[str, Any]:
        return asdict(baseline)

    def from_dict(self, data: dict[str, Any]) -> SiteBaseline:
        pages = {url: PageSnapshot(**snap) for url, snap in data["pages"].items()}
        return SiteBaseline(
            target_url=data["target_url"],
            scan_id=data["scan_id"],
            created_at=data["created_at"],
            pages=pages,
            all_script_sources=data["all_script_sources"],
            all_external_domains=data["all_external_domains"],
            page_count=data["page_count"],
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _form_sig(form: Any) -> str:
    """Stable string key: METHOD|action_url|sorted_field_names."""
    method = (form.method or "GET").upper()
    action = form.action_url or form.action or ""
    fields = ",".join(sorted(inp.name for inp in form.inputs if inp.name))
    return f"{method}|{action}|{fields}"


def _parse_cookie(raw: str) -> tuple[str, str]:
    """Return (name, security_flags_string) for a raw Set-Cookie header."""
    if not raw:
        return "", ""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return "", ""
    name = parts[0].split("=", 1)[0].strip()
    flags: list[str] = []
    for part in parts[1:]:
        pl = part.lower()
        if pl == "secure":
            flags.append("Secure")
        elif pl == "httponly":
            flags.append("HttpOnly")
        elif pl.startswith("samesite="):
            flags.append(f"SameSite={part.split('=',1)[1].strip()}")
    return name, ";".join(sorted(flags))
