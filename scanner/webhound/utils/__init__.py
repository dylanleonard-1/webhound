# WebHound — scanner/webhound/utils/__init__.py
# Shared utilities used across engines and core modules.

from .fingerprints import (
    form_fingerprint,
    form_signature,
    host_fingerprint,
    inline_script_hash,
    script_url_fingerprint,
)
from .hashing import (
    combine_hashes,
    content_fingerprint,
    sha256_bytes,
    sha256_hex,
    short_hash,
)
from .html_parser import safe_parse, text_only
from .logger import get_logger, set_level
from .url_tools import (
    hostname,
    is_private_host,
    is_same_origin,
    path_only,
    scheme,
    strip_default_port,
)

__all__ = [
    # hashing
    "sha256_hex", "sha256_bytes", "short_hash", "content_fingerprint",
    "combine_hashes",
    # fingerprints
    "script_url_fingerprint", "inline_script_hash", "host_fingerprint",
    "form_signature", "form_fingerprint",
    # url tools
    "hostname", "scheme", "path_only", "is_same_origin", "is_private_host",
    "strip_default_port",
    # html
    "safe_parse", "text_only",
    # logging
    "get_logger", "set_level",
]
