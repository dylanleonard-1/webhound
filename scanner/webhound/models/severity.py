# WebHound — scanner/webhound/models/severity.py
# Severity levels for security findings with numeric scoring and ordering.
#
# Numeric scores follow a CVSS-inspired scale:
#   CRITICAL ≥ 9.0 | HIGH 7.0–8.9 | MEDIUM 4.0–6.9 | LOW 0.1–3.9 | INFO 0.0

from __future__ import annotations

from enum import Enum
from functools import total_ordering

# Module-level lookups — kept outside the class to avoid Enum member pollution.
_SCORES: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
    "info": 0.0,
    "unknown": -1.0,
}

_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "green",
    "unknown": "grey",
}


@total_ordering
class Severity(str, Enum):
    """Ordered severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    # ------------------------------------------------------------------
    # str Enum override — return bare value, not 'Severity.HIGH'
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return self.value

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def numeric_score(self) -> float:
        """Midpoint numeric score on a 0–10 scale."""
        return _SCORES[self.value]

    @property
    def rank(self) -> int:
        """Ordinal rank for comparison (higher = more severe)."""
        return _RANK[self.value]

    # ------------------------------------------------------------------
    # Ordering — CRITICAL > HIGH > MEDIUM > LOW > INFO > UNKNOWN
    # ------------------------------------------------------------------

    # str mixin defines its own __gt__ etc. via MRO, so we must override all four.

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _RANK[self.value] < _RANK[other.value]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _RANK[self.value] <= _RANK[other.value]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _RANK[self.value] > _RANK[other.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _RANK[self.value] >= _RANK[other.value]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS v3 base score to a Severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        """Case-insensitive lookup with fallback to UNKNOWN."""
        try:
            return cls(label.lower())
        except ValueError:
            return cls.UNKNOWN

    def is_actionable(self) -> bool:
        """True when the finding warrants immediate remediation attention."""
        return self in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

    def color_code(self) -> str:
        """ANSI-safe colour name for terminal / report rendering."""
        return _COLORS[self.value]
