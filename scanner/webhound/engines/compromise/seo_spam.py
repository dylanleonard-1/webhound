# WebHound — scanner/webhound/engines/compromise/seo_spam.py
# Passive detection of SEO spam injection (pharma, casino, adult, loans).
#
# Safe-mode: reads pre-extracted PageArtifacts and optional raw HTML.
# No active probing, no JavaScript execution.

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "seo_spam"

_PHARMA_TERMS = re.compile(
    r"\b(?:viagra|cialis|levitra|sildenafil|tadalafil|"
    r"cheap\s+pills?|online\s+pharmacy|buy\s+(?:drugs?|meds?|pills?)|"
    r"prescription\s+(?:drugs?|meds?)|no\s+prescription)\b",
    re.I,
)

_CASINO_TERMS = re.compile(
    r"\b(?:online\s+casino|free\s+slots?|jackpot\s+(?:win|bonus)|"
    r"(?:play|bet)\s+online|sports?\s+betting|gambling\s+site|"
    r"poker\s+online|casino\s+bonus)\b",
    re.I,
)

_ADULT_TERMS = re.compile(
    r"\b(?:porn|xxx\b|adult\s+(?:video|site|content|dating)|"
    r"sex\s+(?:video|site|chat)|live\s+(?:sex|cam)|"
    r"nude\s+(?:photo|video))\b",
    re.I,
)

_LOAN_TERMS = re.compile(
    r"\b(?:payday\s+loans?|cash\s+advance|instant\s+(?:loan|credit|cash)|"
    r"bad\s+credit\s+loan|no\s+credit\s+check|fast\s+cash\s+loan|"
    r"personal\s+loan\s+online)\b",
    re.I,
)

_ALL_SPAM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pharma spam", _PHARMA_TERMS),
    ("casino/gambling spam", _CASINO_TERMS),
    ("adult content spam", _ADULT_TERMS),
    ("loan/financial spam", _LOAN_TERMS),
]

_EXTERNAL_LINK_THRESHOLD = 40

_DISPLAY_NONE = re.compile(r"display\s*:\s*none", re.I)
_VISIBILITY_HIDDEN = re.compile(r"visibility\s*:\s*hidden", re.I)
_OPACITY_ZERO = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I)
_OFFSCREEN = re.compile(r"(?:top|left)\s*:\s*-\d{3,}", re.I)
_FONT_SIZE_ZERO = re.compile(r"font-size\s*:\s*0", re.I)
_COLOR_WHITE_ON_WHITE = re.compile(r"color\s*:\s*(?:white|#fff(?:fff)?)\b", re.I)


def _is_hidden_element(tag: Tag) -> bool:
    style = tag.get("style", "")
    if isinstance(style, list):
        style = " ".join(style)
    return bool(
        _DISPLAY_NONE.search(style)
        or _VISIBILITY_HIDDEN.search(style)
        or _OPACITY_ZERO.search(style)
        or _OFFSCREEN.search(style)
        or _FONT_SIZE_ZERO.search(style)
        or _COLOR_WHITE_ON_WHITE.search(style)
    )


def _page_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


class SeoSpamEngine:
    """Passive detection of SEO spam injection.

    Checks for pharma, casino, adult, and loan spam terms in:
    - Page title and meta description (via ``PageArtifacts.meta_tags``)
    - Excessive outbound external links (via ``PageArtifacts.all_links``)
    - Hidden DOM elements containing spam text (requires ``html_body``)
    - Hidden links containing spam text (requires ``html_body``)

    Call ``analyze(artifacts, html_body=...)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        html_body: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_meta_spam(artifacts))
        findings.extend(self._check_excessive_links(artifacts))
        if html_body:
            soup = BeautifulSoup(html_body, "lxml")
            findings.extend(self._check_hidden_spam_blocks(soup, artifacts))
            findings.extend(self._check_hidden_spam_links(soup, artifacts))
        return findings

    # ------------------------------------------------------------------

    def _check_meta_spam(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        title = artifacts.meta_tags.get("title", "")
        description = artifacts.meta_tags.get("description", "")
        combined = f"{title} {description}"

        for label, pattern in _ALL_SPAM_PATTERNS:
            m = pattern.search(combined)
            if m:
                findings.append(Finding(
                    title=f"SEO spam in page metadata ({label})",
                    description=(
                        f"The page title or meta description contains {label} terms "
                        f"(matched: '{m.group()}'). This indicates the site may have been "
                        "compromised and injected with SEO spam to boost rankings for "
                        "illicit content."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.COMPROMISE,
                    evidence=[Evidence(
                        evidence_type=EvidenceType.HTML_ELEMENT,
                        content=f"title={title!r} description={description!r}",
                        location=artifacts.url,
                        source_engine=_ENGINE,
                        extra={"matched_term": m.group(), "spam_type": label},
                    )],
                    confidence=0.85,
                    remediation=(
                        "Remove the spam content from page metadata. "
                        "Audit server files for unauthorized modifications. "
                        "Change all CMS and server credentials."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A08:2021"],
                        cwe_ids=["CWE-506"],
                        nist_controls=["SI-3", "IR-4"],
                    ),
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url},
                ))
        return findings

    def _check_excessive_links(self, artifacts: PageArtifacts) -> list[Finding]:
        page_domain = _page_domain(artifacts.url)
        external = [
            link for link in artifacts.all_links
            if link.startswith("http")
            and _page_domain(link) != page_domain
        ]
        if len(external) <= _EXTERNAL_LINK_THRESHOLD:
            return []
        return [Finding(
            title="Excessive external links detected",
            description=(
                f"The page contains {len(external)} external links, which exceeds the "
                f"threshold of {_EXTERNAL_LINK_THRESHOLD}. "
                "Large numbers of outbound links are a hallmark of SEO spam injection, "
                "where compromised pages are used to boost third-party site rankings."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=f"External link count: {len(external)}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"external_link_count": len(external)},
            )],
            confidence=0.7,
            remediation=(
                "Audit the page source for link injection. "
                "Check CMS templates and database for unauthorized content. "
                "If links are injected, treat the site as compromised."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A08:2021"],
                cwe_ids=["CWE-506"],
                nist_controls=["SI-3"],
            ),
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "external_link_count": len(external)},
        )]

    def _check_hidden_spam_blocks(
        self,
        soup: BeautifulSoup,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_labels: set[str] = set()

        for tag in soup.find_all(["div", "p", "span", "section", "article"]):
            if not isinstance(tag, Tag):
                continue
            if not _is_hidden_element(tag):
                continue
            text = tag.get_text(" ", strip=True)
            if not text:
                continue
            for label, pattern in _ALL_SPAM_PATTERNS:
                if label in seen_labels:
                    continue
                m = pattern.search(text)
                if m:
                    seen_labels.add(label)
                    snippet = text[:200]
                    findings.append(Finding(
                        title=f"Hidden spam block detected ({label})",
                        description=(
                            f"A hidden HTML element contains {label} terms "
                            f"(matched: '{m.group()}'). Hidden spam blocks are injected "
                            "by attackers to boost SEO rankings while remaining invisible "
                            "to site visitors."
                        ),
                        severity=Severity.HIGH,
                        category=FindingCategory.COMPROMISE,
                        evidence=[Evidence(
                            evidence_type=EvidenceType.HTML_ELEMENT,
                            content=snippet,
                            location=artifacts.url,
                            source_engine=_ENGINE,
                            extra={"matched_term": m.group(), "spam_type": label},
                        )],
                        confidence=0.9,
                        remediation=(
                            "Remove all hidden spam elements from the page. "
                            "Audit server files and database for injected content. "
                            "Rotate all CMS and server credentials immediately."
                        ),
                        framework=FrameworkAlignment(
                            owasp_top10=["A08:2021"],
                            cwe_ids=["CWE-506"],
                            nist_controls=["SI-3", "IR-4"],
                        ),
                        scanner_engine=_ENGINE,
                        metadata={"url": artifacts.url},
                    ))
        return findings

    def _check_hidden_spam_links(
        self,
        soup: BeautifulSoup,
        artifacts: PageArtifacts,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_labels: set[str] = set()

        for a_tag in soup.find_all("a"):
            if not isinstance(a_tag, Tag):
                continue
            if not _is_hidden_element(a_tag):
                continue
            href = a_tag.get("href", "")
            link_text = a_tag.get_text(" ", strip=True)
            combined = f"{href} {link_text}"

            for label, pattern in _ALL_SPAM_PATTERNS:
                if label in seen_labels:
                    continue
                m = pattern.search(combined)
                if m:
                    seen_labels.add(label)
                    findings.append(Finding(
                        title=f"Hidden spam link detected ({label})",
                        description=(
                            f"A hidden <a> element with {label} content was found "
                            f"(matched: '{m.group()}', href: {str(href)[:100]}). "
                            "Hidden spam links are injected to manipulate search rankings."
                        ),
                        severity=Severity.HIGH,
                        category=FindingCategory.COMPROMISE,
                        evidence=[Evidence(
                            evidence_type=EvidenceType.HTML_ELEMENT,
                            content=f"<a href='{str(href)[:100]}'>{link_text[:100]}</a>",
                            location=artifacts.url,
                            source_engine=_ENGINE,
                            extra={"matched_term": m.group(), "spam_type": label, "href": str(href)},
                        )],
                        confidence=0.9,
                        remediation=(
                            "Remove all hidden spam links. "
                            "Audit CMS database content for injected links. "
                            "Rotate all credentials and audit access logs."
                        ),
                        framework=FrameworkAlignment(
                            owasp_top10=["A08:2021"],
                            cwe_ids=["CWE-506"],
                            nist_controls=["SI-3", "IR-4"],
                        ),
                        scanner_engine=_ENGINE,
                        metadata={"url": artifacts.url},
                    ))
        return findings
