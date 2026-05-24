# WebHound — scanner/webhound/utils/url_tools.py
# URL parsing / classification helpers used across engines.
#
# Lowercases hostnames, swallows malformed input, returns sensible empty
# defaults instead of raising. Designed to be safe to call on attacker-
# controlled URLs harvested from the page.

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def hostname(url: str | None) -> str:
    """Lowercase hostname or empty string when URL is None / malformed."""
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except (ValueError, TypeError):
        return ""


def scheme(url: str | None) -> str:
    """Lowercase URL scheme (http / https / ws / wss / …) or empty string."""
    if not url:
        return ""
    try:
        return (urlparse(url).scheme or "").lower()
    except (ValueError, TypeError):
        return ""


def path_only(url: str | None) -> str:
    """Path component of *url*, normalised to lowercase. Empty on failure."""
    if not url:
        return ""
    try:
        return (urlparse(url).path or "").lower()
    except (ValueError, TypeError):
        return ""


def is_same_origin(a: str | None, b: str | None) -> bool:
    """True when both URLs share scheme + hostname + port."""
    if not a or not b:
        return False
    try:
        pa, pb = urlparse(a), urlparse(b)
    except (ValueError, TypeError):
        return False
    return (
        (pa.scheme or "").lower() == (pb.scheme or "").lower()
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and pa.port == pb.port
    )


def is_private_host(url_or_host: str | None) -> bool:
    """True when host resolves to an RFC1918 / loopback / link-local IP.

    Accepts a full URL or a bare hostname. Returns False for normal public
    hostnames — DNS resolution is NOT performed; only literal IPs are
    checked.
    """
    if not url_or_host:
        return False
    host = hostname(url_or_host) or url_or_host.strip().lower()
    try:
        ip = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def strip_default_port(url: str) -> str:
    """Remove `:80` from http URLs and `:443` from https URLs.

    Used to canonicalise URLs before deduplication — `http://x.com:80/a`
    and `http://x.com/a` should be treated as the same endpoint.
    """
    try:
        p = urlparse(url)
    except (ValueError, TypeError):
        return url
    if p.port is None:
        return url
    if (p.scheme == "http" and p.port == 80) or (p.scheme == "https" and p.port == 443):
        netloc = p.hostname or ""
        if p.username:
            netloc = (
                f"{p.username}:{p.password}@{netloc}" if p.password
                else f"{p.username}@{netloc}"
            )
        return p._replace(netloc=netloc).geturl()
    return url
