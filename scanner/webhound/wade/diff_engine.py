# WebHound — scanner/webhound/wade/diff_engine.py
# Compares current page snapshots against a baseline to find security-relevant
# changes: new scripts, changed inline scripts, new external domains, header
# regressions, cookie flag regressions, new or changed forms, status code shifts.
# No live external calls are made.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from webhound.wade.baseline_builder import PageSnapshot, SiteBaseline


class DiffType(str, Enum):
    NEW_SCRIPT_SOURCE     = "new_script_source"
    CHANGED_INLINE_SCRIPT = "changed_inline_script"
    NEW_EXTERNAL_DOMAIN   = "new_external_domain"
    HEADER_REGRESSION     = "header_regression"
    COOKIE_REGRESSION     = "cookie_regression"
    NEW_FORM              = "new_form"
    FORM_FIELD_CHANGE     = "form_field_change"
    STATUS_CODE_CHANGE    = "status_code_change"


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
        items.extend(self._security_headers(current, baseline))
        items.extend(self._cookies(current, baseline))
        items.extend(self._forms(current, baseline))
        items.extend(self._status_code(current, baseline))
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
        return [
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
