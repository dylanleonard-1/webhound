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

import re
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
    integrity: str | None = None  # Raw `integrity=` attribute, if present (SRI hash)
    crossorigin: str | None = None  # Raw `crossorigin=` attribute, if present


@dataclass(frozen=True)
class ExtractedIframe:
    """An <iframe> element captured for security analysis (never loaded)."""

    src_url: str | None       # Resolved src URL, or None for no-src iframes
    is_external_domain: bool  # src hostname differs from the page hostname
    is_hidden: bool           # Heuristic: width/height ≤1 or CSS-hidden
    sandbox: str | None       # Raw sandbox attribute value, if present


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

    # Expanded artifact detection (V2) — default to empty so existing callers are unaffected
    iframes: list[ExtractedIframe] = field(default_factory=list)
    external_image_urls: list[str] = field(default_factory=list)
    external_stylesheet_urls: list[str] = field(default_factory=list)
    inline_css_import_urls: list[str] = field(default_factory=list)
    inline_js_request_urls: list[str] = field(default_factory=list)

    # Inline HTML event-handler attribute values (onclick, onmouseover, etc).
    # Stored as `(tag_name, attribute_name, value)` triples. JavaScript pattern
    # engines analyse these the same way they analyse <script> bodies — a
    # `javascript:` URL or eval() inside an onclick is no less dangerous.
    event_handlers: list[tuple[str, str, str]] = field(default_factory=list)

    # Phase-2 audit: broader third-party discovery surfaces. Each list holds
    # absolute, resolved URLs whose hostname differs from the page hostname.
    # All default to empty so prior callers + serialisers stay backward-
    # compatible — the threat_intel engine consults them additively.
    external_srcset_urls: list[str] = field(default_factory=list)        # <img srcset>, <source srcset>
    external_video_audio_urls: list[str] = field(default_factory=list)   # <video/audio src>, <source src>, poster
    external_object_embed_urls: list[str] = field(default_factory=list)  # <object data>, <embed src>
    external_meta_refresh_urls: list[str] = field(default_factory=list)  # <meta http-equiv="refresh">
    external_preconnect_urls: list[str] = field(default_factory=list)    # <link rel="preconnect">
    external_dns_prefetch_urls: list[str] = field(default_factory=list)  # <link rel="dns-prefetch">
    external_preload_urls: list[str] = field(default_factory=list)       # <link rel="preload"/"modulepreload">
    external_manifest_urls: list[str] = field(default_factory=list)      # <link rel="manifest">
    external_canonical_urls: list[str] = field(default_factory=list)     # <link rel="canonical">
    external_og_twitter_urls: list[str] = field(default_factory=list)    # <meta property="og:image"/twitter:*>
    external_jsonld_urls: list[str] = field(default_factory=list)        # @id / url fields in <script type="application/ld+json">
    external_inline_style_urls: list[str] = field(default_factory=list)  # url(...) in style attributes / <style> blocks
    external_favicon_urls: list[str] = field(default_factory=list)       # <link rel="icon"/"shortcut icon">/"apple-touch-icon">


# Regex patterns used by the V2 extraction methods.
_CSS_IMPORT_RE = re.compile(
    r'@import\s+(?:url\s*\(\s*)?["\']([^"\']+)["\']', re.IGNORECASE
)
_JS_FETCH_RE = re.compile(r'\bfetch\s*\(\s*["\']([^"\']+)["\']')
_JS_XHR_OPEN_RE = re.compile(
    r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_JS_WS_RE = re.compile(r'\bnew\s+WebSocket\s*\(\s*["\']([^"\']+)["\']')
_IFRAME_HIDDEN_CSS_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE
)


def _iframe_is_hidden(tag: Tag) -> bool:
    """Heuristic: iframe is CSS-hidden or dimensioned to ≤1 pixel."""
    style = tag.get("style") or ""
    if isinstance(style, list):
        style = " ".join(style)
    if _IFRAME_HIDDEN_CSS_RE.search(str(style)):
        return True
    for attr in ("width", "height"):
        val = tag.get(attr, "")
        if isinstance(val, list):
            val = val[0] if val else ""
        try:
            if int(str(val).strip()) <= 1:
                return True
        except (ValueError, TypeError):
            pass
    return False


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
            iframes=self._extract_iframes(soup, base_url, page_hostname),
            external_image_urls=self._extract_external_images(soup, base_url, page_hostname),
            external_stylesheet_urls=self._extract_external_stylesheets(soup, base_url, page_hostname),
            inline_css_import_urls=self._extract_css_imports(soup),
            inline_js_request_urls=self._extract_js_request_urls(scripts),
            event_handlers=self._extract_event_handlers(soup),
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
                integrity_raw = tag.get("integrity")
                crossorigin_raw = tag.get("crossorigin")
                scripts.append(
                    ExtractedScript(
                        src=resolved,
                        content=None,
                        is_inline=False,
                        is_external=True,
                        is_external_domain=(src_host != page_hostname),
                        integrity=integrity_raw.strip() if isinstance(integrity_raw, str) and integrity_raw.strip() else None,
                        crossorigin=crossorigin_raw.strip() if isinstance(crossorigin_raw, str) and crossorigin_raw.strip() else None,
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

    # ------------------------------------------------------------------
    # V2 artifact extraction
    # ------------------------------------------------------------------

    def _extract_iframes(
        self,
        soup: BeautifulSoup,
        base_url: str,
        page_hostname: str,
    ) -> list[ExtractedIframe]:
        iframes: list[ExtractedIframe] = []
        for tag in soup.find_all("iframe"):
            if not isinstance(tag, Tag):
                continue
            src_raw = tag.get("src") or ""
            if isinstance(src_raw, list):
                src_raw = src_raw[0] if src_raw else ""
            src_url = (
                UrlNormalizer.normalize(str(src_raw).strip(), base_url=base_url)
                if str(src_raw).strip()
                else None
            )
            src_host = (urlparse(src_url).hostname or "").lower() if src_url else ""
            sandbox_raw = tag.get("sandbox")
            iframes.append(ExtractedIframe(
                src_url=src_url,
                is_external_domain=bool(src_host and src_host != page_hostname),
                is_hidden=_iframe_is_hidden(tag),
                sandbox=str(sandbox_raw) if sandbox_raw is not None else None,
            ))
        return iframes

    def _extract_external_images(
        self,
        soup: BeautifulSoup,
        base_url: str,
        page_hostname: str,
    ) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for tag in soup.find_all("img", src=True):
            if not isinstance(tag, Tag):
                continue
            src_raw = tag.get("src", "")
            if not src_raw or not isinstance(src_raw, str):
                continue
            resolved = UrlNormalizer.normalize(src_raw.strip(), base_url=base_url)
            if not resolved or resolved in seen:
                continue
            host = (urlparse(resolved).hostname or "").lower()
            if host and host != page_hostname:
                seen.add(resolved)
                urls.append(resolved)
        return urls

    def _extract_external_stylesheets(
        self,
        soup: BeautifulSoup,
        base_url: str,
        page_hostname: str,
    ) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for tag in soup.find_all("link"):
            if not isinstance(tag, Tag):
                continue
            rel = tag.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            if "stylesheet" not in [r.lower() for r in rel]:
                continue
            href_raw = tag.get("href", "")
            if not href_raw or not isinstance(href_raw, str):
                continue
            resolved = UrlNormalizer.normalize(href_raw.strip(), base_url=base_url)
            if not resolved or resolved in seen:
                continue
            host = (urlparse(resolved).hostname or "").lower()
            if host and host != page_hostname:
                seen.add(resolved)
                urls.append(resolved)
        return urls

    def _extract_css_imports(self, soup: BeautifulSoup) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for style_tag in soup.find_all("style"):
            if not isinstance(style_tag, Tag):
                continue
            content = style_tag.get_text() or ""
            for m in _CSS_IMPORT_RE.finditer(content):
                url = m.group(1).strip()
                if url.startswith(("http://", "https://")) and url not in seen:
                    seen.add(url)
                    urls.append(url)
        return urls

    def _extract_js_request_urls(self, scripts: list[ExtractedScript]) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for script in scripts:
            if not script.is_inline or not script.content:
                continue
            content = script.content
            for pattern in (_JS_FETCH_RE, _JS_XHR_OPEN_RE, _JS_WS_RE):
                for m in pattern.finditer(content):
                    url = m.group(1).strip()
                    if (
                        url.startswith(("http://", "https://", "wss://", "ws://"))
                        and url not in seen
                    ):
                        seen.add(url)
                        urls.append(url)
        return urls

    # ------------------------------------------------------------------
    # HTML event-handler attributes
    # ------------------------------------------------------------------

    def _extract_event_handlers(self, soup: BeautifulSoup) -> list[tuple[str, str, str]]:
        """Collect inline `on*=...` attribute values across the page.

        Returns triples of `(tag_name, attribute_name, value)`. We capture the
        attribute *value* — the JS-pattern engine analyses these the same way
        it analyses <script> bodies. Attribute names are lower-cased so
        downstream consumers don't have to.
        """
        out: list[tuple[str, str, str]] = []
        for tag in soup.find_all(True):  # all tags
            if not isinstance(tag, Tag) or not tag.attrs:
                continue
            for attr, value in tag.attrs.items():
                if not isinstance(attr, str):
                    continue
                attr_lc = attr.lower()
                # Standard DOM event handlers all start with "on" + lowercase letter.
                if not (attr_lc.startswith("on") and len(attr_lc) > 2 and attr_lc[2].isalpha()):
                    continue
                # Attribute values may be lists when BeautifulSoup parses an
                # attribute spelled multiple times — collapse to a string.
                if isinstance(value, list):
                    val_str = " ".join(str(v) for v in value).strip()
                else:
                    val_str = str(value).strip() if value is not None else ""
                if not val_str:
                    continue
                out.append((tag.name.lower(), attr_lc, val_str))
        return out


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
