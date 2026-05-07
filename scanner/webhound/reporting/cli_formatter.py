# WebHound — scanner/webhound/reporting/cli_formatter.py
# Terminal formatting helpers for CLI output and summary reports.
# All functions are pure — no I/O, no side effects.

from __future__ import annotations

DEFAULT_WIDTH: int = 60
_URL_MAX_LEN: int = 70

_RISK_LABELS: dict[str, str] = {
    "low": "Low Risk",
    "medium": "Medium Risk",
    "high": "High Risk",
    "critical": "Critical Risk",
}

_RISK_DESCRIPTIONS: dict[str, str] = {
    "low": "No critical issues detected. Review flagged findings and remediate as time allows.",
    "medium": "Actionable security issues found. Remediation is recommended.",
    "high": "Significant security weaknesses detected. Prompt remediation advised.",
    "critical": "Critical vulnerabilities present. Immediate remediation required.",
}


# ---------------------------------------------------------------------------
# Dividers / rules
# ---------------------------------------------------------------------------


def divider(width: int = DEFAULT_WIDTH, char: str = "─") -> str:
    """Return a horizontal rule of *char* repeated *width* times."""
    return char * width


def bold_divider(width: int = DEFAULT_WIDTH) -> str:
    """Return a heavy horizontal rule (═)."""
    return "═" * width


def thin_divider(width: int = DEFAULT_WIDTH) -> str:
    """Return a light horizontal rule (─)."""
    return "─" * width


# ---------------------------------------------------------------------------
# Severity / risk formatting
# ---------------------------------------------------------------------------


def fmt_severity(severity_str: str) -> str:
    """Return a fixed-width bracketed severity label.

    Examples: ``[CRITICAL]``, ``[HIGH    ]``, ``[MEDIUM  ]``.
    """
    return f"[{severity_str.upper():<8}]"


def fmt_risk(score: int | float, level: str) -> str:
    """Return a concise risk summary: ``'93 / 100  (Low Risk)'``."""
    label = _RISK_LABELS.get(level.lower(), f"{level.title()} Risk")
    return f"{score} / 100  ({label})"


def fmt_risk_description(level: str) -> str:
    """Return a one-sentence description of the risk level."""
    return _RISK_DESCRIPTIONS.get(level.lower(), "")


# ---------------------------------------------------------------------------
# URL / text helpers
# ---------------------------------------------------------------------------


def fmt_url(url: str, max_len: int = _URL_MAX_LEN) -> str:
    """Truncate *url* to *max_len* characters, appending ``…`` if shortened."""
    if len(url) <= max_len:
        return url
    return url[: max_len - 1] + "…"


def fmt_duration(seconds: float) -> str:
    """Return a human-readable duration string.

    Examples: ``'4.2s'``, ``'1m 23s'``.
    """
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = seconds % 60
    return f"{mins}m {secs:.0f}s"


# ---------------------------------------------------------------------------
# Column / table helpers
# ---------------------------------------------------------------------------


def col(text: str, width: int, align: str = "left") -> str:
    """Fit *text* into a field of *width* characters (truncate + pad).

    *align* may be ``'left'`` (default) or ``'right'``.
    """
    truncated = text[:width]
    if align == "right":
        return truncated.rjust(width)
    return truncated.ljust(width)
