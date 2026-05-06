# WebHound — scanner/webhound/core/scope.py
# Domain scope validation and URL normalization.
#
# ScopeChecker answers "may the crawler visit this URL?" based on the Target's
# scope rules (FULL_DOMAIN, SUBDIRECTORY, SINGLE_PAGE, URL_LIST).
#
# UrlNormalizer converts raw URLs into a stable canonical form so that the
# same page reached via different representations is only crawled once.

from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse

import tldextract

from webhound.models.target import ScanOptions, Target, TargetScope


class UrlNormalizer:
    """Stateless URL normalization.  All methods are class-level utilities."""

    # Schemes the scanner is allowed to follow.
    _ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

    @classmethod
    def normalize(cls, url: str, base_url: str | None = None) -> str | None:
        """Return a canonical form of *url*, or None if it should not be crawled.

        Canonicalization rules:
        - Relative URLs are resolved against *base_url* (required for relative links).
        - Scheme and hostname are lowercased.
        - Default ports (80/http, 443/https) are stripped from the netloc.
        - URL fragments (#...) are discarded — they are client-side anchors.
        - Double slashes in the path are collapsed.
        - An empty path is normalised to ``/``.
        - Query strings are preserved as-is (order is not normalised).
        - mailto:, javascript:, data:, tel: and other non-HTTP(S) schemes return None.
        """
        url = url.strip()
        if not url or url.startswith(("javascript:", "mailto:", "data:", "tel:", "#")):
            return None

        # Resolve relative URLs
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)

        try:
            parsed = urlparse(url)
        except ValueError:
            return None

        scheme = (parsed.scheme or "").lower()
        if scheme not in cls._ALLOWED_SCHEMES:
            return None

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None

        # Rebuild netloc — include port only when non-default
        port = parsed.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        # Normalize path
        path = parsed.path or "/"
        while "//" in path:
            path = path.replace("//", "/")

        return urlunparse((scheme, netloc, path, "", parsed.query, ""))

    @classmethod
    def resolve(cls, href: str, page_url: str) -> str | None:
        """Resolve *href* found on *page_url* and return its canonical form."""
        return cls.normalize(href, base_url=page_url)

    @staticmethod
    def path_segments(url: str) -> list[str]:
        """Return non-empty path segments for *url*."""
        return [s for s in urlparse(url).path.split("/") if s]


class ScopeChecker:
    """Validates whether a URL may be crawled given the Target's scope rules.

    Construct once per scan; the instance is stateless (safe to share between
    coroutines).

    Scope rules:
    - SINGLE_PAGE   — only the exact target URL.
    - SUBDIRECTORY  — target URL and any URL whose path starts with the target path.
    - FULL_DOMAIN   — any URL on the same registered domain (optionally + subdomains).
    - URL_LIST      — only URLs explicitly listed in ``Target.scope_urls``.
    """

    def __init__(self, target: Target) -> None:
        self._target = target
        self._options: ScanOptions = target.scan_options

        parsed_target = urlparse(UrlNormalizer.normalize(target.url) or target.url)
        self._target_hostname: str = (parsed_target.hostname or "").lower()
        self._target_path: str = parsed_target.path or "/"

        tld = tldextract.extract(self._target_hostname)
        self._target_registered: str = tld.top_domain_under_public_suffix

        # Pre-normalise URL_LIST for O(1) lookup
        self._scope_url_set: frozenset[str] = frozenset(
            u for raw in target.scope_urls if (u := UrlNormalizer.normalize(raw))
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, url: str) -> bool:
        """Return True if *url* is within the scan's permitted scope."""
        normalized = UrlNormalizer.normalize(url)
        if not normalized:
            return False

        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()

        scope = self._target.scope

        if scope == TargetScope.URL_LIST:
            return normalized in self._scope_url_set

        if scope == TargetScope.SINGLE_PAGE:
            target_norm = UrlNormalizer.normalize(self._target.url)
            return normalized == target_norm

        # For SUBDIRECTORY and FULL_DOMAIN, check the registered domain first.
        tld_url = tldextract.extract(hostname)
        if tld_url.top_domain_under_public_suffix != self._target_registered:
            return False

        # Subdomain check — allow exact host or, when enabled, any subdomain.
        if not self._options.include_subdomains:
            if hostname != self._target_hostname:
                return False
        # else: same registered domain is sufficient.

        if scope == TargetScope.SUBDIRECTORY:
            url_path = parsed.path or "/"
            return url_path.startswith(self._target_path)

        # FULL_DOMAIN — registered-domain match (+ subdomain policy) is sufficient.
        return True

    def out_of_scope_reason(self, url: str) -> str | None:
        """Return a human-readable reason why *url* is out of scope, or None."""
        normalized = UrlNormalizer.normalize(url)
        if not normalized:
            return "not a valid http/https URL"

        if self.is_in_scope(url):
            return None

        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
        scope = self._target.scope

        if scope == TargetScope.URL_LIST:
            return "URL not in explicit scope list"

        if scope == TargetScope.SINGLE_PAGE:
            return "scope is SINGLE_PAGE — only the root URL is allowed"

        tld_url = tldextract.extract(hostname)
        if tld_url.top_domain_under_public_suffix != self._target_registered:
            return f"external domain: {hostname}"

        if not self._options.include_subdomains and hostname != self._target_hostname:
            return f"subdomain not in scope: {hostname}"

        if scope == TargetScope.SUBDIRECTORY:
            return f"path {parsed.path!r} not under target path {self._target_path!r}"

        return "out of scope"

    def is_valid_url(self, url: str) -> bool:
        """True if *url* is a syntactically valid http/https URL (ignores scope)."""
        return UrlNormalizer.normalize(url) is not None
