# WebHound — scanner/webhound/engines/javascript/js_collector.py
# Collects and structures JavaScript artifacts from extracted page data.
#
# Safe-mode: reads PageArtifacts only.
# JavaScript is never executed, fetched, or evaluated.
# External script content is not fetched — only src URLs are recorded.

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlparse

from webhound.core.extractor import PageArtifacts

_ENGINE = "js_collector"


@dataclass
class CollectedScript:
    """A single JavaScript resource collected from a page.

    Inline scripts carry content; external scripts carry only the src URL.
    content_hash enables deduplication across multiple pages.
    """

    src: str | None           # External src URL, or None for inline scripts
    content: str | None       # Inline body, or None for external scripts
    content_hash: str         # SHA-256 of content (inline) or src URL (external)
    is_inline: bool
    is_external: bool
    is_third_party: bool      # External domain differs from the originating page
    origin_url: str           # Page URL where this script was found
    domain: str | None        # Hostname of external src, or None for inline


@dataclass
class JsCollection:
    """All JavaScript resources collected from a single page."""

    origin_url: str
    scripts: list[CollectedScript] = field(default_factory=list)

    @property
    def inline_scripts(self) -> list[CollectedScript]:
        return [s for s in self.scripts if s.is_inline]

    @property
    def external_scripts(self) -> list[CollectedScript]:
        return [s for s in self.scripts if s.is_external]

    @property
    def third_party_scripts(self) -> list[CollectedScript]:
        return [s for s in self.scripts if s.is_third_party]

    @property
    def third_party_domains(self) -> list[str]:
        return list({s.domain for s in self.third_party_scripts if s.domain})

    @property
    def inline_contents(self) -> list[str]:
        return [s.content for s in self.inline_scripts if s.content]

    @property
    def external_src_urls(self) -> list[str]:
        return [s.src for s in self.external_scripts if s.src]


class JsCollectorEngine:
    """Collects JavaScript artifacts from :class:`~webhound.core.extractor.PageArtifacts`.

    Deduplicates inline scripts by content hash and external scripts by src URL.
    Safe-mode: reads pre-extracted data only — no network activity.
    """

    NAME = _ENGINE

    def collect(self, artifacts: PageArtifacts) -> JsCollection:
        """Build a :class:`JsCollection` from page artifacts.

        Inline scripts with identical content are deduplicated.
        External scripts with the same src URL appear at most once.
        """
        seen_hashes: set[str] = set()
        seen_srcs: set[str] = set()
        collected: list[CollectedScript] = []

        for script in artifacts.scripts:
            if script.is_inline and script.content and script.content.strip():
                h = _sha256(script.content)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                collected.append(
                    CollectedScript(
                        src=None,
                        content=script.content,
                        content_hash=h,
                        is_inline=True,
                        is_external=False,
                        is_third_party=False,
                        origin_url=artifacts.url,
                        domain=None,
                    )
                )
            elif script.is_external and script.src:
                if script.src in seen_srcs:
                    continue
                seen_srcs.add(script.src)
                h = _sha256(script.src)
                domain = urlparse(script.src).hostname or None
                collected.append(
                    CollectedScript(
                        src=script.src,
                        content=None,
                        content_hash=h,
                        is_inline=False,
                        is_external=True,
                        is_third_party=script.is_external_domain,
                        origin_url=artifacts.url,
                        domain=domain,
                    )
                )

        return JsCollection(origin_url=artifacts.url, scripts=collected)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
