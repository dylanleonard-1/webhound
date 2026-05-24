# WebHound — scanner/webhound/utils/html_parser.py
# Safe BeautifulSoup wrapper that never raises on malformed input.
#
# The scanner ingests HTML from untrusted servers — broken encoding,
# truncated responses, deliberately malformed tags. This module centralises
# the parser-choice + error-handling logic so engines stay focused on
# their security analysis.

from __future__ import annotations

from bs4 import BeautifulSoup

# Preferred parser order: lxml is fastest and most tolerant, html.parser
# is stdlib and always available.
_PARSER_PREFERENCES = ("lxml", "html.parser")


def safe_parse(html: str | bytes | None) -> BeautifulSoup:
    """Return a BeautifulSoup over *html*; never raises.

    Falls back through the parser preference list. Returns an empty soup
    (`BeautifulSoup("", "html.parser")`) for None / empty / wholly broken
    input rather than raising — engines that walk the tree should always
    get a usable object.
    """
    if html is None:
        return BeautifulSoup("", "html.parser")
    if isinstance(html, bytes):
        try:
            html = html.decode("utf-8", errors="replace")
        except Exception:
            return BeautifulSoup("", "html.parser")
    if not html:
        return BeautifulSoup("", "html.parser")
    for parser in _PARSER_PREFERENCES:
        try:
            return BeautifulSoup(html, parser)
        except Exception:
            continue
    return BeautifulSoup("", "html.parser")


def text_only(html: str | bytes | None, *, separator: str = " ") -> str:
    """Return all visible text from *html* with whitespace collapsed.

    Strips `<script>` and `<style>` blocks before extracting text — used
    when the engine wants to scan the visible page text (e.g. SEO-spam
    keyword matching) without false positives from script bodies.
    """
    soup = safe_parse(html)
    for tag in soup(("script", "style", "noscript", "template")):
        tag.decompose()
    return soup.get_text(separator=separator, strip=True)
