# WebHound — scanner/webhound/core/visibility/robots_policy.py
# Phase 2: minimal robots.txt allow/deny matcher for the visibility frontier.
#
# The legacy crawl loop does NOT enforce robots.txt (the robots_sitemap engine
# only emits findings). Because the visibility layer WIDENS the crawl frontier
# — feeding sitemap/JS/form/ASM URLs the homepage never linked — we honour
# robots.txt here by default so the wider crawl stays polite. A verified
# customer can override via ScanOptions.respect_robots_txt=False.
#
# Scope: the ``User-agent: *`` group's Disallow/Allow directives, matched by
# path prefix with Allow taking precedence (longest-match wins), supporting the
# common ``*`` wildcard and ``$`` end-anchor. This is deliberately conservative:
# when in doubt we ALLOW (robots is a crawl hint, and over-blocking would hide
# legitimately public pages). Reuses robots_sitemap parsing conventions.
#
# Safe-mode: pure string parsing. No network.

from __future__ import annotations

import re
from urllib.parse import urlparse


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    r"""Translate a robots path pattern into a regex. ``*`` → ``.*``; a
    trailing ``$`` anchors the end. Everything else is matched literally."""
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        else:
            out.append(re.escape(ch))
    if anchored:
        out.append("$")
    return re.compile("".join(out))


class RobotsRules:
    """Allow/Disallow rules for the ``*`` user-agent group."""

    def __init__(self, disallow: list[str], allow: list[str]) -> None:
        # Keep raw paths for length-based precedence; compile lazily.
        self._disallow = [(p, _glob_to_regex(p)) for p in disallow if p]
        self._allow = [(p, _glob_to_regex(p)) for p in allow if p]

    @classmethod
    def from_robots_txt(cls, content: str) -> "RobotsRules":
        """Parse robots.txt, extracting the ``User-agent: *`` group's rules.

        Lines before any ``User-agent`` and groups for other agents are
        ignored. An empty / missing star group yields permissive rules
        (nothing disallowed)."""
        disallow: list[str] = []
        allow: list[str] = []
        in_star_group = False
        # A run of consecutive User-agent lines share the following rules.
        pending_agents: list[str] = []
        saw_rule_since_agent = False

        for raw in (content or "").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            field, _, value = line.partition(":")
            field = field.strip().lower()
            value = value.strip()
            if field == "user-agent":
                if saw_rule_since_agent:
                    # New group starts — reset the agent run.
                    pending_agents = []
                    saw_rule_since_agent = False
                pending_agents.append(value)
                in_star_group = "*" in pending_agents
            elif field == "disallow":
                saw_rule_since_agent = True
                if in_star_group and value:
                    disallow.append(value)
            elif field == "allow":
                saw_rule_since_agent = True
                if in_star_group and value:
                    allow.append(value)
        return cls(disallow, allow)

    def is_allowed(self, url: str) -> bool:
        """True if *url*'s path may be crawled under these rules.

        Allow overrides Disallow when its matching pattern is at least as
        specific (longest-match precedence, per the de-facto standard)."""
        path = urlparse(url).path or "/"
        if path == "":
            path = "/"
        # Empty "Disallow:" means allow-all; an explicit "Disallow: /" blocks all.
        best_disallow = -1
        for pat, rx in self._disallow:
            if rx.match(path):
                best_disallow = max(best_disallow, len(pat))
        if best_disallow < 0:
            return True  # nothing disallows this path
        best_allow = -1
        for pat, rx in self._allow:
            if rx.match(path):
                best_allow = max(best_allow, len(pat))
        # Allow wins ties (>= ) — conservative toward visibility.
        return best_allow >= best_disallow

    @property
    def has_rules(self) -> bool:
        return bool(self._disallow)


# A permissive singleton for "no robots / robots disabled".
ALLOW_ALL = RobotsRules([], [])
