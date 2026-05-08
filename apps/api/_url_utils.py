from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_BLOCKED_SCHEMES = frozenset(
    {"ftp", "file", "javascript", "data", "mailto", "tel", "blob", "vbscript"}
)
_PRIVATE_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "0.0.0.0", "broadcasthost"}
)
_PRIVATE_TLD_SUFFIXES = (".local", ".internal", ".localhost", ".corp", ".home")

# Valid hostname: labels separated by dots, each label: alnum + hyphens, may include port
_VALID_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]*$")


class URLValidationError(ValueError):
    pass


def normalize_url(raw: str) -> tuple[str, str, str]:
    """Validate and normalize a URL.

    Returns (normalized_url, scheme, hostname).
    Raises URLValidationError for invalid, unsupported, or private URLs.
    """
    raw = raw.strip()
    if not raw:
        raise URLValidationError("URL must not be empty")

    # Before adding a default scheme, detect blocked schemes in the raw input
    # (e.g. "javascript:alert(1)" or "data:text/html,...")
    raw_lower = raw.lower()
    for blocked in _BLOCKED_SCHEMES:
        if raw_lower.startswith(blocked + ":"):
            raise URLValidationError(
                f"Scheme '{blocked}' is not allowed. Only http and https are supported."
            )

    # Add scheme if missing — assume https
    if "://" not in raw:
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise URLValidationError(f"Could not parse URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()

    if scheme in _BLOCKED_SCHEMES:
        raise URLValidationError(
            f"Scheme '{scheme}' is not allowed. Only http and https are supported."
        )
    if scheme not in _ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Scheme '{scheme}' is not supported. Use http or https."
        )

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL must include a hostname")

    hostname = hostname.lower()

    # Reject hostnames containing characters illegal in DNS labels
    if not _VALID_HOSTNAME_RE.match(hostname):
        raise URLValidationError(f"Invalid hostname: '{hostname}'")

    if _is_private_host(hostname):
        raise URLValidationError(
            f"Private or local hostnames are not permitted: {hostname}"
        )

    # Normalize: lowercase scheme + host, keep path, strip query and fragment
    path = parsed.path or "/"
    netloc = parsed.netloc.lower()
    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    return normalized, scheme, hostname


def _is_private_host(hostname: str) -> bool:
    if hostname in _PRIVATE_HOSTNAMES:
        return True
    lower = hostname.lower()
    if any(lower.endswith(suffix) for suffix in _PRIVATE_TLD_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False
