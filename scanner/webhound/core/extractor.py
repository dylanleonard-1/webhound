# WebHound — scanner/webhound/core/extractor.py
# HTML artifact extractor: links, scripts, forms, and header artifacts.
#
# Safe-mode guarantees:
#   - JavaScript is NEVER executed.
#   - Forms are NEVER submitted.
#   - External resources are NEVER fetched.
#   - All extracted URLs are normalized but not crawled.
#
# The extractor is stateless; create one instance per scan and reuse it.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from webhound.core.http_client import HttpResponse
from webhound.core.scope import UrlNormalizer

# lxml is the fastest and most lenient HTML parser available.
_BS_PARSER = "lxml"

_HTML_CONTENT_TYPES: frozenset[str] = frozenset(
    {"text/html", "application/xhtml+xml"}
)


# ---------------------------------------------------------------------------
# Extracted artifact types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FormInput:
    """A single input field discovered inside a form.  Value is never submitted."""

    name: str | None
    input_type: str          # 'text', 'password', 'hidden', 'email', 'submit', …
    value: str | None        # Default/pre-filled value only — not used for submission


@dataclass(frozen=True)
class ExtractedForm:
    """A <form> element captured for security analysis (never submitted)."""

    action: str | None       # Raw 'action' attribute from HTML
    action_url: str | None   # Resolved, normalized action URL (may be None)
    method: str              # 'GET' or 'POST' (uppercased; default 'GET')
    inputs: tuple[FormInput, ...]
    has_password_field: bool
    has_csrf_token: bool     # Heuristic: hidden input whose name hints at CSRF


@dataclass(frozen=True)
class ExtractedScript:
    """A <script> element — either inline content or an external src reference."""

    src: str | None          # Resolved external src URL, or None for inline
    content: str | None      # Inline script body, or None for external scripts
    is_inline: bool
    is_external: bool
    is_external_domain: bool  # src hostname differs from the page hostname


@dataclass
class PageArtifacts:
    """All artifacts extracted from a single HTML page response."""

    url: str                          # Final page URL (after redirects)
    status_code: int
    content_type: str | None
    title: str | None

    # Links — classified by hostname, not by scan scope
    all_links: list[str]              # Every resolved, normalized <a href>
    internal_links: list[str]         # Same hostname as the page
    external_links: list[str]         # Different hostname

    # Scripts (JavaScript is never executed)
    scripts: list[ExtractedScript]
    inline_scripts: list[str]         # Shortcut: content of inline scripts
    external_script_urls: list[str]   # Shortcut: src of external scripts

    # Forms (analysed but never submitted)
    forms: list[ExtractedForm]

    # HTTP-level artifacts
    cookies: list[str]                # Raw Set-Cookie header values
    response_headers: dict[str, str]

    # Page metadata
    meta_tags: dict[str, str]         # name/property → content

    extracted_at: datetime


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class Extractor:
    """Extracts security-relevant artifacts from HTML responses.

    Stateless — safe to reuse across many pages in a single scan.
    Never performs network activity or executes JavaScript.
    """

    def extract(self, response: HttpResponse) -> PageArtifacts | None:
        """Parse *response* and return a :class:`PageArtifacts`, or ``None``
        if the response is not HTML or has an empty body."""
        if not _is_html(response.content_type):
            return None
        body = response.body.strip()
        if not body:
            return None

        try:
            soup = BeautifulSoup(body, _BS_PARSER)
        except Exception:
            return None

        page_url = response.url
        page_hostname = (urlparse(page_url).hostname or "").lower()

        # Honour <base href> — it overrides relative URL resolution for this page.
        base_url = _effective_base(soup, page_url)

        all_links, internal_links, external_links = self._extract_links(
            soup, base_url, page_hostname
        )
        scripts = self._extract_scripts(soup, base_url, page_hostname)
        forms = self._extract_forms(soup, base_url)
        cookies = self._extract_cookies(response)
        meta_tags = self._extract_meta(soup)
        title = self._extract_title(soup)

        return PageArtifacts(
            url=page_url,
            status_code=response.status_code,
            content_type=response.content_type,
            title=title,
            all_links=all_links,
            internal_links=internal_links,
            external_links=external_links,
            scripts=scripts,
            inline_scripts=[s.content for s in scripts if s.is_inline and s.content],
            external_script_urls=[s.src for s in scripts if s.is_external and s.src],
            forms=forms,
            cookies=cookies,
            response_headers=dict(response.headers),
            meta_tags=meta_tags,
            extracted_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    def _extract_links(
        self,
        soup: BeautifulSoup,
        base_url: str,
        page_hostname: str,
    ) -> tuple[list[str], list[str], list[str]]:
        seen: set[str] = set()
        all_links: list[str] = []
        internal_links: list[str] = []
        external_links: list[str] = []

        for tag in soup.find_all("a", href=True):
            raw = tag.get("href", "")
            if not raw or not isinstance(raw, str):
                continue
            normalized = UrlNormalizer.normalize(raw.strip(), base_url=base_url)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            all_links.append(normalized)
            link_host = (urlparse(normalized).hostname or "").lower()
            if link_host == page_hostname:
                internal_links.append(normalized)
            else:
                external_links.append(normalized)

        return all_links, internal_links, external_links

    # ------------------------------------------------------------------
    # Script extraction
    # ------------------------------------------------------------------

    def _extract_scripts(
        self,
        soup: BeautifulSoup,
        base_url: str,
        page_hostname: str,
    ) -> list[ExtractedScript]:
        scripts: list[ExtractedScript] = []

        for tag in soup.find_all("script"):
            if not isinstance(tag, Tag):
                continue
            src_raw = tag.get("src")
            if src_raw and isinstance(src_raw, str) and src_raw.strip():
                resolved = UrlNormalizer.normalize(src_raw.strip(), base_url=base_url)
                if not resolved:
                    continue
                src_host = (urlparse(resolved).hostname or "").lower()
                scripts.append(
                    ExtractedScript(
                        src=resolved,
                        content=None,
                        is_inline=False,
                        is_external=True,
                        is_external_domain=(src_host != page_hostname),
                    )
                )
            else:
                content = tag.get_text() or ""
                if content.strip():
                    scripts.append(
                        ExtractedScript(
                            src=None,
                            content=content,
                            is_inline=True,
                            is_external=False,
                            is_external_domain=False,
                        )
                    )

        return scripts

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------

    def _extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str,
    ) -> list[ExtractedForm]:
        forms: list[ExtractedForm] = []

        for form_tag in soup.find_all("form"):
            if not isinstance(form_tag, Tag):
                continue
            raw_action = form_tag.get("action") or ""
            action_url = (
                UrlNormalizer.normalize(str(raw_action).strip(), base_url=base_url)
                if raw_action
                else None
            )
            method_raw = str(form_tag.get("method") or "get").upper()
            method = method_raw if method_raw in ("GET", "POST") else "GET"

            inputs: list[FormInput] = []
            has_password = False
            has_csrf = False

            for inp in form_tag.find_all(["input", "button", "textarea", "select"]):
                if not isinstance(inp, Tag):
                    continue
                inp_type = str(inp.get("type") or "text").lower()
                inp_name = inp.get("name")
                inp_value = inp.get("value")

                if inp_type == "password":
                    has_password = True
                if inp_name and isinstance(inp_name, str):
                    nl = inp_name.lower()
                    if "csrf" in nl or "_token" in nl or nl == "token":
                        has_csrf = True

                inputs.append(
                    FormInput(
                        name=str(inp_name) if inp_name else None,
                        input_type=inp_type,
                        value=str(inp_value) if inp_value else None,
                    )
                )

            forms.append(
                ExtractedForm(
                    action=str(raw_action) if raw_action else None,
                    action_url=action_url,
                    method=method,
                    inputs=tuple(inputs),
                    has_password_field=has_password,
                    has_csrf_token=has_csrf,
                )
            )

        return forms

    # ------------------------------------------------------------------
    # Header artifact extraction
    # ------------------------------------------------------------------

    def _extract_cookies(self, response: HttpResponse) -> list[str]:
        """Collect raw Set-Cookie header values (observation only — never sent back)."""
        return [v for k, v in response.headers.items() if k.lower() == "set-cookie"]

    def _extract_meta(self, soup: BeautifulSoup) -> dict[str, str]:
        meta: dict[str, str] = {}
        for tag in soup.find_all("meta"):
            if not isinstance(tag, Tag):
                continue
            name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
            content = tag.get("content")
            if name and content and isinstance(name, str) and isinstance(content, str):
                meta[name.lower()] = content
        return meta

    def _extract_title(self, soup: BeautifulSoup) -> str | None:
        title_tag = soup.find("title")
        if title_tag:
            text = title_tag.get_text(strip=True)
            return text or None
        return None


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _effective_base(soup: BeautifulSoup, page_url: str) -> str:
    """Return the effective base URL for resolving relative hrefs on this page."""
    base_tag = soup.find("base", href=True)
    if not isinstance(base_tag, Tag):
        return page_url
    raw = str(base_tag.get("href") or "").strip()
    if not raw:
        return page_url
    if raw.startswith(("http://", "https://")):
        return raw
    return UrlNormalizer.normalize(raw, base_url=page_url) or page_url


def _is_html(content_type: str | None) -> bool:
    """True when content-type indicates parseable HTML."""
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct in _HTML_CONTENT_TYPES
