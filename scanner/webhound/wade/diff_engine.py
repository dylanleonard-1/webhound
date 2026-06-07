# WebHound — scanner/webhound/wade/diff_engine.py
# Compares current page snapshots against a baseline across the full WADE 2.0
# inventory: scripts (added/removed), inline scripts, external + third-party
# domains, API endpoints, headers (removed/added), cookies, forms, iframes,
# redirects, technologies, DOM structure, status codes. No external calls.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from webhound.wade.baseline_builder import PageSnapshot, SiteBaseline, _host


class DiffType(str, Enum):
    # --- WADE 1.x diff types (unchanged) -----------------------------------
    NEW_SCRIPT_SOURCE     = "new_script_source"
    CHANGED_INLINE_SCRIPT = "changed_inline_script"
    NEW_EXTERNAL_DOMAIN   = "new_external_domain"
    HEADER_REGRESSION     = "header_regression"
    COOKIE_REGRESSION     = "cookie_regression"
    NEW_FORM              = "new_form"
    FORM_FIELD_CHANGE     = "form_field_change"
    STATUS_CODE_CHANGE    = "status_code_change"

    # --- WADE 2.0 diff types -----------------------------------------------
    REMOVED_SCRIPT_SOURCE     = "removed_script_source"
    REMOVED_EXTERNAL_DOMAIN   = "removed_external_domain"
    NEW_THIRD_PARTY_DOMAIN    = "new_third_party_domain"
    REMOVED_THIRD_PARTY_DOMAIN = "removed_third_party_domain"
    NEW_API_ENDPOINT          = "new_api_endpoint"
    REMOVED_API_ENDPOINT      = "removed_api_endpoint"
    HEADER_ADDED              = "header_added"
    COOKIE_BEHAVIOR_CHANGE    = "cookie_behavior_change"
    NEW_IFRAME                = "new_iframe"
    REDIRECT_CHANGE           = "redirect_change"
    TECHNOLOGY_CHANGE         = "technology_change"
    DOM_STRUCTURE_CHANGE      = "dom_structure_change"


# Default severity hint per diff type
DIFF_SEVERITY: dict[DiffType, str] = {
    DiffType.NEW_SCRIPT_SOURCE:     "high",
    DiffType.CHANGED_INLINE_SCRIPT: "high",
    DiffType.NEW_EXTERNAL_DOMAIN:   "medium",
    DiffType.HEADER_REGRESSION:     "medium",
    DiffType.COOKIE_REGRESSION:     "medium",
    DiffType.NEW_FORM:              "medium",
    DiffType.FORM_FIELD_CHANGE:     "medium",
    DiffType.STATUS_CODE_CHANGE:    "low",
    DiffType.REMOVED_SCRIPT_SOURCE:      "low",
    DiffType.REMOVED_EXTERNAL_DOMAIN:    "info",
    DiffType.NEW_THIRD_PARTY_DOMAIN:     "medium",
    DiffType.REMOVED_THIRD_PARTY_DOMAIN: "info",
    DiffType.NEW_API_ENDPOINT:           "medium",
    DiffType.REMOVED_API_ENDPOINT:       "low",
    DiffType.HEADER_ADDED:               "info",
    DiffType.COOKIE_BEHAVIOR_CHANGE:     "low",
    DiffType.NEW_IFRAME:                 "high",
    DiffType.REDIRECT_CHANGE:            "medium",
    DiffType.TECHNOLOGY_CHANGE:          "low",
    DiffType.DOM_STRUCTURE_CHANGE:       "info",
}

# Security headers tracked for regression detection
_SECURITY_HEADERS: frozenset[str] = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
})

# Cookie flags whose removal is a security regression
_SECURITY_FLAGS: frozenset[str] = frozenset({"Secure", "HttpOnly"})


@dataclass
class DiffItem:
    """A single security-relevant change detected between baseline and current."""

    diff_type: DiffType
    url: str
    detail: str
    baseline_value: str | None
    current_value: str | None
    severity_hint: str


class DiffEngine:
    """Produce :class:`DiffItem` objects by comparing snapshots to a baseline."""

    def diff_site(
        self,
        current_pages: dict[str, PageSnapshot],
        baseline: SiteBaseline,
    ) -> list[DiffItem]:
        """Diff all current pages against the baseline; handles new pages too."""
        items: list[DiffItem] = []
        for url, snap in current_pages.items():
            b_snap = baseline.pages.get(url)
            if b_snap is None:
                items.extend(self._diff_new_page(snap, baseline))
            else:
                items.extend(self.diff_page(snap, b_snap))
        return items

    def diff_page(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        """Return all diff items for one page against its per-page baseline snapshot."""
        items: list[DiffItem] = []
        items.extend(self._scripts(current, baseline))
        items.extend(self._external_domains(current, baseline))
        items.extend(self._third_party_domains(current, baseline))
        items.extend(self._api_endpoints(current, baseline))
        items.extend(self._security_headers(current, baseline))
        items.extend(self._headers_added(current, baseline))
        items.extend(self._cookies(current, baseline))
        items.extend(self._cookie_behavior(current, baseline))
        items.extend(self._forms(current, baseline))
        items.extend(self._iframes(current, baseline))
        items.extend(self._redirects(current, baseline))
        items.extend(self._technologies(current, baseline))
        items.extend(self._status_code(current, baseline))
        items.extend(self._dom_structure(current, baseline))
        return items

    # ------------------------------------------------------------------
    # Private diff helpers
    # ------------------------------------------------------------------

    def _diff_new_page(
        self, current: PageSnapshot, baseline: SiteBaseline
    ) -> list[DiffItem]:
        """Check a page that was absent from the baseline against site-wide sets."""
        items: list[DiffItem] = []
        known_srcs = set(baseline.all_script_sources)
        for src in current.script_sources:
            if src not in known_srcs:
                items.append(DiffItem(
                    diff_type=DiffType.NEW_SCRIPT_SOURCE,
                    url=current.url,
                    detail=f"New script on previously-unseen page: {src}",
                    baseline_value=None,
                    current_value=src,
                    severity_hint="high",
                ))
        known_domains = set(baseline.all_external_domains)
        for d in current.external_domains:
            if d not in known_domains:
                items.append(DiffItem(
                    diff_type=DiffType.NEW_EXTERNAL_DOMAIN,
                    url=current.url,
                    detail=f"New external domain on previously-unseen page: {d}",
                    baseline_value=None,
                    current_value=d,
                    severity_hint="medium",
                ))
        return items

    def _scripts(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        items: list[DiffItem] = []
        b_srcs = set(baseline.script_sources)
        c_srcs = set(current.script_sources)
        for src in current.script_sources:
            if src not in b_srcs:
                items.append(DiffItem(
                    diff_type=DiffType.NEW_SCRIPT_SOURCE,
                    url=current.url,
                    detail=f"New external script: {src}",
                    baseline_value=None,
                    current_value=src,
                    severity_hint=DIFF_SEVERITY[DiffType.NEW_SCRIPT_SOURCE],
                ))
        for src in sorted(b_srcs - c_srcs):
            items.append(DiffItem(
                diff_type=DiffType.REMOVED_SCRIPT_SOURCE,
                url=current.url,
                detail=f"External script removed since last scan: {src}",
                baseline_value=src,
                current_value=None,
                severity_hint=DIFF_SEVERITY[DiffType.REMOVED_SCRIPT_SOURCE],
            ))
        new_inline = set(current.inline_hashes) - set(baseline.inline_hashes)
        if new_inline:
            items.append(DiffItem(
                diff_type=DiffType.CHANGED_INLINE_SCRIPT,
                url=current.url,
                detail=f"{len(new_inline)} new/changed inline script block(s)",
                baseline_value=",".join(sorted(baseline.inline_hashes)[:3]) or None,
                current_value=",".join(sorted(new_inline)[:3]),
                severity_hint=DIFF_SEVERITY[DiffType.CHANGED_INLINE_SCRIPT],
            ))
        return items

    def _external_domains(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        b_domains = set(baseline.external_domains)
        c_domains = set(current.external_domains)
        items: list[DiffItem] = [
            DiffItem(
                diff_type=DiffType.NEW_EXTERNAL_DOMAIN,
                url=current.url,
                detail=f"New external domain: {d}",
                baseline_value=None,
                current_value=d,
                severity_hint=DIFF_SEVERITY[DiffType.NEW_EXTERNAL_DOMAIN],
            )
            for d in current.external_domains
            if d not in b_domains
        ]
        items.extend(
            DiffItem(
                diff_type=DiffType.REMOVED_EXTERNAL_DOMAIN,
                url=current.url,
                detail=f"External domain no longer referenced: {d}",
                baseline_value=d,
                current_value=None,
                severity_hint=DIFF_SEVERITY[DiffType.REMOVED_EXTERNAL_DOMAIN],
            )
            for d in sorted(b_domains - c_domains)
        )
        return items

    def _third_party_domains(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        """New/removed resource-loading third-party hosts. A host that only
        appeared because of an already-flagged new script is skipped — the
        NEW_SCRIPT_SOURCE item covers it (alert-fatigue reduction)."""
        b_tp = set(baseline.third_party_domains)
        c_tp = set(current.third_party_domains)
        new_script_hosts = {
            _host(src) for src in (set(current.script_sources)
                                   - set(baseline.script_sources))
        }
        items: list[DiffItem] = []
        for d in sorted(c_tp - b_tp):
            if d in new_script_hosts:
                continue  # already covered by a NEW_SCRIPT_SOURCE item
            items.append(DiffItem(
                diff_type=DiffType.NEW_THIRD_PARTY_DOMAIN,
                url=current.url,
                detail=f"Page now loads resources from a new third party: {d}",
                baseline_value=None,
                current_value=d,
                severity_hint=DIFF_SEVERITY[DiffType.NEW_THIRD_PARTY_DOMAIN],
            ))
        for d in sorted(b_tp - c_tp):
            items.append(DiffItem(
                diff_type=DiffType.REMOVED_THIRD_PARTY_DOMAIN,
                url=current.url,
                detail=f"Third-party resource host no longer loaded: {d}",
                baseline_value=d,
                current_value=None,
                severity_hint=DIFF_SEVERITY[DiffType.REMOVED_THIRD_PARTY_DOMAIN],
            ))
        return items

    def _api_endpoints(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        b_api = set(baseline.api_endpoints)
        c_api = set(current.api_endpoints)
        items: list[DiffItem] = []
        for ep in sorted(c_api - b_api):
            items.append(DiffItem(
                diff_type=DiffType.NEW_API_ENDPOINT,
                url=current.url,
                detail=f"New API endpoint surfaced: {ep}",
                baseline_value=None,
                current_value=ep,
                severity_hint=DIFF_SEVERITY[DiffType.NEW_API_ENDPOINT],
            ))
        for ep in sorted(b_api - c_api):
            items.append(DiffItem(
                diff_type=DiffType.REMOVED_API_ENDPOINT,
                url=current.url,
                detail=f"API endpoint no longer referenced: {ep}",
                baseline_value=ep,
                current_value=None,
                severity_hint=DIFF_SEVERITY[DiffType.REMOVED_API_ENDPOINT],
            ))
        return items

    def _security_headers(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        items: list[DiffItem] = []
        for hdr in _SECURITY_HEADERS:
            b_val = baseline.headers.get(hdr)
            c_val = current.headers.get(hdr)
            if b_val and not c_val:
                items.append(DiffItem(
                    diff_type=DiffType.HEADER_REGRESSION,
                    url=current.url,
                    detail=f"Security header removed: {hdr}",
                    baseline_value=b_val,
                    current_value=None,
                    severity_hint=DIFF_SEVERITY[DiffType.HEADER_REGRESSION],
                ))
        return items

    def _cookies(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        items: list[DiffItem] = []
        for name, b_flags_str in baseline.cookie_signatures.items():
            c_flags_str = current.cookie_signatures.get(name)
            if c_flags_str is None:
                continue  # cookie no longer set — not tracked in v1
            b_sec = set(b_flags_str.split(";") if b_flags_str else []) & _SECURITY_FLAGS
            c_sec = set(c_flags_str.split(";") if c_flags_str else []) & _SECURITY_FLAGS
            lost = b_sec - c_sec
            if lost:
                items.append(DiffItem(
                    diff_type=DiffType.COOKIE_REGRESSION,
                    url=current.url,
                    detail=(
                        f"Cookie '{name}' lost security flag(s): "
                        f"{', '.join(sorted(lost))}"
                    ),
                    baseline_value=b_flags_str or None,
                    current_value=c_flags_str or None,
                    severity_hint=DIFF_SEVERITY[DiffType.COOKIE_REGRESSION],
                ))
        return items

    def _forms(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        items: list[DiffItem] = []
        b_sigs = set(baseline.form_signatures)
        c_sigs = set(current.form_signatures)
        new_sigs = c_sigs - b_sigs
        if not new_sigs:
            return items

        b_actions = {sig.split("|", 2)[1] for sig in b_sigs}
        for sig in sorted(new_sigs):
            _, action, _ = sig.split("|", 2)
            if action in b_actions:
                b_match = next(
                    (s for s in b_sigs if s.split("|", 2)[1] == action), None
                )
                items.append(DiffItem(
                    diff_type=DiffType.FORM_FIELD_CHANGE,
                    url=current.url,
                    detail=f"Form fields changed for action '{action}'",
                    baseline_value=b_match,
                    current_value=sig,
                    severity_hint=DIFF_SEVERITY[DiffType.FORM_FIELD_CHANGE],
                ))
            else:
                method, _, _ = sig.split("|", 2)
                items.append(DiffItem(
                    diff_type=DiffType.NEW_FORM,
                    url=current.url,
                    detail=f"New form detected: {method} {action}",
                    baseline_value=None,
                    current_value=sig,
                    severity_hint=DIFF_SEVERITY[DiffType.NEW_FORM],
                ))
        return items

    def _status_code(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        if current.status_code == baseline.status_code:
            return []
        return [DiffItem(
            diff_type=DiffType.STATUS_CODE_CHANGE,
            url=current.url,
            detail=(
                f"Status code changed: {baseline.status_code} → {current.status_code}"
            ),
            baseline_value=str(baseline.status_code),
            current_value=str(current.status_code),
            severity_hint=DIFF_SEVERITY[DiffType.STATUS_CODE_CHANGE],
        )]

    def _headers_added(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        """A newly-present security header is informational (hardening)."""
        items: list[DiffItem] = []
        for hdr in _SECURITY_HEADERS:
            if current.headers.get(hdr) and not baseline.headers.get(hdr):
                items.append(DiffItem(
                    diff_type=DiffType.HEADER_ADDED,
                    url=current.url,
                    detail=f"Security header added: {hdr}",
                    baseline_value=None,
                    current_value=current.headers.get(hdr),
                    severity_hint=DIFF_SEVERITY[DiffType.HEADER_ADDED],
                ))
        return items

    def _cookie_behavior(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        """A new cookie name appearing. Loss of a flag on an existing cookie
        is handled by _cookies; this catches *new* cookies."""
        b_names = set(baseline.cookie_signatures)
        c_names = set(current.cookie_signatures)
        items: list[DiffItem] = []
        for name in sorted(c_names - b_names):
            flags = current.cookie_signatures.get(name) or "(no security flags)"
            items.append(DiffItem(
                diff_type=DiffType.COOKIE_BEHAVIOR_CHANGE,
                url=current.url,
                detail=f"New cookie set since last scan: '{name}' [{flags}]",
                baseline_value=None,
                current_value=f"{name}: {flags}",
                severity_hint=DIFF_SEVERITY[DiffType.COOKIE_BEHAVIOR_CHANGE],
            ))
        return items

    def _iframes(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        b_frames = set(baseline.iframe_signatures)
        return [
            DiffItem(
                diff_type=DiffType.NEW_IFRAME,
                url=current.url,
                detail=f"New iframe embedded: {sig}",
                baseline_value=None,
                current_value=sig,
                severity_hint=DIFF_SEVERITY[DiffType.NEW_IFRAME],
            )
            for sig in current.iframe_signatures
            if sig not in b_frames
        ]

    def _redirects(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        if current.redirect_chain == baseline.redirect_chain:
            return []
        return [DiffItem(
            diff_type=DiffType.REDIRECT_CHANGE,
            url=current.url,
            detail=(
                "Redirect behaviour changed: "
                f"{' → '.join(baseline.redirect_chain) or '(none)'} ⇒ "
                f"{' → '.join(current.redirect_chain) or '(none)'}"
            ),
            baseline_value=" → ".join(baseline.redirect_chain) or None,
            current_value=" → ".join(current.redirect_chain) or None,
            severity_hint=DIFF_SEVERITY[DiffType.REDIRECT_CHANGE],
        )]

    def _technologies(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        b_tech = set(baseline.technologies)
        c_tech = set(current.technologies)
        added = sorted(c_tech - b_tech)
        removed = sorted(b_tech - c_tech)
        if not added and not removed:
            return []
        parts: list[str] = []
        if added:
            parts.append(f"added: {', '.join(added)}")
        if removed:
            parts.append(f"removed: {', '.join(removed)}")
        return [DiffItem(
            diff_type=DiffType.TECHNOLOGY_CHANGE,
            url=current.url,
            detail=f"Detected technology stack changed ({'; '.join(parts)})",
            baseline_value=", ".join(sorted(b_tech)) or None,
            current_value=", ".join(sorted(c_tech)) or None,
            severity_hint=DIFF_SEVERITY[DiffType.TECHNOLOGY_CHANGE],
        )]

    def _dom_structure(
        self, current: PageSnapshot, baseline: PageSnapshot
    ) -> list[DiffItem]:
        """Structural DOM change — low signal alone (often a deploy)."""
        if (not current.dom_hash or not baseline.dom_hash
                or current.dom_hash == baseline.dom_hash):
            return []
        return [DiffItem(
            diff_type=DiffType.DOM_STRUCTURE_CHANGE,
            url=current.url,
            detail="Page structure (tag layout) changed since last scan",
            baseline_value=baseline.dom_hash,
            current_value=current.dom_hash,
            severity_hint=DIFF_SEVERITY[DiffType.DOM_STRUCTURE_CHANGE],
        )]
