# WebHound — scanner/webhound/utils/logger.py
# Tiny stdlib-only logger factory with consistent format across scanner code.
#
# Avoids pulling in structlog as a hard dependency. Engines that want
# structured per-event logging can import `get_logger(__name__)` and rely
# on the format below. The runtime log level is read from the
# WEBHOUND_LOG_LEVEL env var (defaults to INFO).

from __future__ import annotations

import logging
import os
import sys
from functools import lru_cache

_DEFAULT_LEVEL = os.getenv("WEBHOUND_LOG_LEVEL", "INFO").upper()
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def _configure_root_once() -> None:
    root = logging.getLogger("webhound")
    if root.handlers:
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    root.addHandler(handler)
    try:
        root.setLevel(getattr(logging, _DEFAULT_LEVEL))
    except AttributeError:
        root.setLevel(logging.INFO)
    root.propagate = False


@lru_cache(maxsize=None)
def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the `webhound.*` namespace.

    Children inherit the format / level set on the `webhound` root logger.
    Repeated calls with the same name return the same instance (cached).
    """
    _configure_root_once()
    if not name.startswith("webhound"):
        name = f"webhound.{name}"
    return logging.getLogger(name)


def set_level(level: str | int) -> None:
    """Override the runtime log level for the `webhound` namespace."""
    _configure_root_once()
    root = logging.getLogger("webhound")
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(level)
