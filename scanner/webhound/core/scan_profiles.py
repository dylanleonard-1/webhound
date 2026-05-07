# WebHound — scanner/webhound/core/scan_profiles.py
# Named scan profiles that map to validated ScanOptions presets.
#
# All profiles enforce safe-mode constraints:
#   - GET / HEAD only (no POST, no form submission)
#   - No JavaScript execution
#   - No external threat-intel calls
#   - rate_limit_rps ≤ 2.0 (polite crawling)
#
# Usage::
#
#     profile = get_profile("quick")
#     options = profile.to_scan_options()
#     scanner = Scanner(Target.from_url(url, scan_options=options))

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webhound.models.target import ScanOptions


@dataclass(frozen=True)
class ScanProfile:
    """Immutable preset that controls crawler behaviour and resource limits.

    All profiles are passive-only.  No profile may enable form submission,
    JavaScript execution, or external API calls.
    """

    name: str
    description: str
    max_pages: int
    max_depth: int
    rate_limit_rps: float
    request_timeout_seconds: int
    include_subdomains: bool
    respect_robots_txt: bool
    verify_tls: bool

    def to_scan_options(self) -> ScanOptions:
        """Return a :class:`ScanOptions` instance configured from this profile."""
        return ScanOptions(
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            rate_limit_rps=self.rate_limit_rps,
            request_timeout_seconds=self.request_timeout_seconds,
            include_subdomains=self.include_subdomains,
            respect_robots_txt=self.respect_robots_txt,
            verify_tls=self.verify_tls,
        )

    def summary(self) -> dict[str, Any]:
        """Return a plain dict summary suitable for logging or reporting."""
        return {
            "name": self.name,
            "description": self.description,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "rate_limit_rps": self.rate_limit_rps,
            "request_timeout_seconds": self.request_timeout_seconds,
            "include_subdomains": self.include_subdomains,
            "respect_robots_txt": self.respect_robots_txt,
            "verify_tls": self.verify_tls,
        }


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

#: Fast surface check — homepage and immediate links only.
QUICK = ScanProfile(
    name="quick",
    description="Fast surface check: homepage and immediate links only.",
    max_pages=5,
    max_depth=1,
    rate_limit_rps=1.0,
    request_timeout_seconds=15,
    include_subdomains=False,
    respect_robots_txt=True,
    verify_tls=True,
)

#: Balanced scan — good coverage for most sites.
STANDARD = ScanProfile(
    name="standard",
    description="Balanced scan with good coverage for most sites.",
    max_pages=25,
    max_depth=2,
    rate_limit_rps=1.0,
    request_timeout_seconds=15,
    include_subdomains=False,
    respect_robots_txt=True,
    verify_tls=True,
)

#: Thorough passive crawl — maximum page coverage at a slower rate.
DEEP = ScanProfile(
    name="deep",
    description="Thorough passive crawl for maximum page coverage.",
    max_pages=100,
    max_depth=4,
    rate_limit_rps=0.5,
    request_timeout_seconds=30,
    include_subdomains=False,
    respect_robots_txt=True,
    verify_tls=True,
)

#: Lightweight periodic check optimised for WADE baseline comparison.
MONITOR = ScanProfile(
    name="monitor",
    description="Lightweight periodic check optimised for WADE baseline comparison.",
    max_pages=10,
    max_depth=1,
    rate_limit_rps=0.5,
    request_timeout_seconds=15,
    include_subdomains=False,
    respect_robots_txt=True,
    verify_tls=True,
)

#: Registry of all built-in profiles, keyed by name.
PROFILES: dict[str, ScanProfile] = {
    p.name: p for p in (QUICK, STANDARD, DEEP, MONITOR)
}

PROFILE_NAMES: tuple[str, ...] = tuple(sorted(PROFILES))


def get_profile(name: str) -> ScanProfile:
    """Return the :class:`ScanProfile` for *name*.

    Raises :exc:`ValueError` with a hint listing valid names when *name*
    is not recognised.
    """
    try:
        return PROFILES[name]
    except KeyError:
        valid = ", ".join(PROFILE_NAMES)
        raise ValueError(
            f"Unknown scan profile {name!r}. Valid profiles: {valid}"
        ) from None
