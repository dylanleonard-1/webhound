# WebHound — scanner/webhound/engines/compromise/seo_spam.py
# Passive detection of SEO spam injection (pharma, casino, adult, loan,
# cryptocurrency, fake services).
#
# Safe-mode: reads pre-extracted PageArtifacts and optional raw HTML.
# No active probing, no JavaScript execution.

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
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
    r"poker\s+online|casino\s+bonus|slot\s+machine)\b",
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

# Cryptocurrency / forex / "make money fast" — common 2023-2026 spam class.
_CRYPTO_SCAM_TERMS = re.compile(
    r"\b(?:bitcoin\s+(?:profit|trader|generator|miner|scam|investment)|"
    r"crypto\s+(?:profit|signal|airdrop|pump|recovery|recover)|"
    r"forex\s+(?:signal|expert|advisor|robot)|"
    r"binary\s+options?|trade\s+bot|"
    r"get\s+rich\s+(?:quick|fast)|"
    r"passive\s+income\s+(?:online|crypto)|"
    r"hack(?:ed)?\s+wallet|recover\s+(?:lost\s+)?bitcoin|"
    r"free\s+(?:btc|eth|usdt))\b",
    re.I,
)

# Counterfeit/replica goods spam.
_REPLICA_TERMS = re.compile(
    r"\b(?:replica\s+(?:watch|handbag|bag|shoe|jersey)|"
    r"fake\s+(?:watch|rolex|gucci)|cheap\s+(?:rolex|gucci|prada|hermes)|"
    r"discount\s+(?:designer|luxury))\b",
    re.I,
)

# Fake essay / writing services — a huge SEO-spam category for compromised
# academic sites.
_ESSAY_MILL_TERMS = re.compile(
    r"\b(?:write\s+my\s+(?:essay|paper|thesis|assignment)|"
    r"essay\s+writing\s+service|paper\s+writing\s+service|"
    r"buy\s+(?:essay|term\s+paper|dissertation))\b",
    re.I,
)

_ALL_SPAM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pharma spam", _PHARMA_TERMS),
    ("casino/gambling spam", _CASINO_TERMS),
    ("adult content spam", _ADULT_TERMS),
    ("loan/financial spam", _LOAN_TERMS),
    ("cryptocurrency scam spam", _CRYPTO_SCAM_TERMS),
    ("replica/counterfeit spam", _REPLICA_TERMS),
    ("essay-mill spam", _ESSAY_MILL_TERMS),
]

_EXTERNAL_LINK_THRESHOLD = 40

_DISPLAY_NONE = re.compile(r"display\s*:\s*none", re.I)
_VISIBILITY_HIDDEN = re.compile(r"visibility\s*:\s*hidden", re.I)
_OPACITY_ZERO = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I)
_OFFSCREEN = re.compile(r"(?:top|left)\s*:\s*-\d{3,}", re.I)
_FONT_SIZE_ZERO = re.compile(r"font-size\s*:\s*0", re.I)
_COLOR_WHITE_ON_WHITE = re.compile(r"color\s*:\s*(?:white|#fff(?:fff)?)\b", re.I)


_FA: dict[str, FrameworkAlignment] = {
    "meta_spam": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        cvss_score=7.1,
        pci_dss=["11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.5.30"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(6)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "excessive_links": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["11.6.1"],
        iso_27001=["A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "hidden_spam_block": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        cvss_score=7.1,
        pci_dss=["11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.5.30"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(6)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "hidden_spam_link": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",
        cvss_score=7.1,
        pci_dss=["11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.5.30"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(6)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
}


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

    Pattern categories: pharma, casino, adult, loan, crypto-scam, replica/
    counterfeit, essay-mill. Locations checked: page title/meta description,
    excessive external link count, hidden-styled DOM elements, hidden
    anchor links.
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

    def _check_meta_spam(self, artifacts):
        findings = []
        title = artifacts.meta_tags.get("title", "")
        description = artifacts.meta_tags.get("description", "")
        combined = f"{title} {description}"
        for label, pattern in _ALL_SPAM_PATTERNS:
            m = pattern.search(combined)
            if not m:
                continue
            findings.append(Finding(
                title=f"SEO spam in page metadata ({label})",
                description=(
                    f"The page's `<title>` or meta description contains "
                    f"{label} terms — matched '{m.group()}'. Compromised "
                    "sites typically inject these phrases server-side to "
                    "push their own search rankings to ride on the host "
                    "site's reputation. Once Google notices, the host site "
                    "loses its rank too; the cleanup often takes weeks of "
                    "manual reindex requests."
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
                    "Treat as an active compromise: remove the spam content, "
                    "rotate every CMS admin credential, audit recent plugin/"
                    "theme installs (the most common entry point), and "
                    "search server-side files for the same terms in case "
                    "the attacker dropped backdoors. After cleanup, request "
                    "reindexing in Google Search Console and submit a "
                    "Reconsideration Request if the site was manually "
                    "penalised."
                ),
                framework=_FA["meta_spam"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "spam_type": label},
            ))
        return findings

    def _check_excessive_links(self, artifacts):
        page_domain = _page_domain(artifacts.url)
        external = [
            link for link in artifacts.all_links
            if link.startswith("http") and _page_domain(link) != page_domain
        ]
        if len(external) <= _EXTERNAL_LINK_THRESHOLD:
            return []
        return [Finding(
            title=f"Excessive external links on a single page ({len(external)})",
            description=(
                f"The page contains {len(external)} external links — well "
                f"above the {_EXTERNAL_LINK_THRESHOLD}-link threshold. A "
                "link farm of this size is rarely organic content; usually "
                "it's the output of an SEO-spam compromise where the "
                "attacker pushes hundreds of links to boost third-party "
                "domains. The host site eventually loses search ranking "
                "for being a low-quality outbound source."
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
                "Audit the page template, the CMS database content, and "
                "any user-generated comment system for injected link blocks. "
                "If the links are clearly third-party junk, treat as "
                "compromise and rotate credentials. Add `rel=\"nofollow "
                "ugc\"` to legitimate user-supplied outbound links so "
                "they don't pass PageRank."
            ),
            framework=_FA["excessive_links"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "external_link_count": len(external)},
        )]

    def _check_hidden_spam_blocks(self, soup, artifacts):
        findings = []
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
                if not m:
                    continue
                seen_labels.add(label)
                snippet = text[:200]
                findings.append(Finding(
                    title=f"Hidden spam block on page ({label})",
                    description=(
                        f"A DOM element styled to be invisible (display:none, "
                        f"font-size:0, off-screen positioning, white-on-white "
                        f"text, or opacity:0) contains {label} terms — "
                        f"matched '{m.group()}'. Hidden spam blocks are "
                        "specifically designed for search-engine crawlers, "
                        "which read CSS-hidden content the same as visible "
                        "content. Real users see nothing; the site's ranking "
                        "still suffers when Google catches the trick."
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
                        "Locate the injected block in the page template or "
                        "database (search for the matched phrase against "
                        "wp_posts, wp_options, or your CMS equivalent). "
                        "Remove the content, rotate CMS credentials, and "
                        "audit recent admin activity. Once clean, submit a "
                        "URL inspection request in Google Search Console so "
                        "the spam isn't cached at the search-index layer."
                    ),
                    framework=_FA["hidden_spam_block"],
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url, "spam_type": label},
                ))
        return findings

    def _check_hidden_spam_links(self, soup, artifacts):
        findings = []
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
                if not m:
                    continue
                seen_labels.add(label)
                findings.append(Finding(
                    title=f"Hidden spam link on page ({label})",
                    description=(
                        f"A hidden `<a>` tag carries {label} text and/or "
                        f"href — matched '{m.group()}', target "
                        f"{str(href)[:100]}. Hidden links bypass user "
                        "interaction (they can't be clicked when they're "
                        "invisible) but they're indexed by search engines "
                        "and pass PageRank to the destination. This is "
                        "the most common payload of WordPress-plugin "
                        "compromises that 'pharma hack' sites at scale."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.COMPROMISE,
                    evidence=[Evidence(
                        evidence_type=EvidenceType.HTML_ELEMENT,
                        content=f"<a href='{str(href)[:100]}'>{link_text[:100]}</a>",
                        location=artifacts.url,
                        source_engine=_ENGINE,
                        extra={"matched_term": m.group(), "spam_type": label,
                               "href": str(href)},
                    )],
                    confidence=0.9,
                    remediation=(
                        "Treat the site as compromised. Remove the hidden "
                        "links, search the database for the same destination "
                        "URL (there are usually dozens), rotate CMS "
                        "credentials, audit recent admin sessions and "
                        "plugin installs. After cleanup, request "
                        "reindexing in Search Console and watch for "
                        "re-infection — pharma-hack toolkits typically "
                        "leave a persistence mechanism."
                    ),
                    framework=_FA["hidden_spam_link"],
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url, "spam_type": label,
                              "href": str(href)},
                ))
        return findings
