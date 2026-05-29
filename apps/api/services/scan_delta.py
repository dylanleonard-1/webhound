# WebHound — apps/api/services/scan_delta.py
# Phase-4 continuous monitoring: scan-to-scan diff computation.
#
# Reads the scanner_metadata blob each ScanResult ships with (external
# domains, technologies, fetch stats, etc.), compares against the prior
# scan's blob, and emits a structured :class:`ScanDelta` capturing the
# operational drift. The dashboard reads from the persisted delta; the
# notification engine reads ``drift_severity`` to decide whether to
# alert.
#
# Pure-Python — no DB I/O inside ``compute_delta`` so it's
# unit-testable without a session. ``persist_delta`` does the DB write.

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import DriftSeverity
from apps.api.models.scan_delta import ScanDelta
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord


# ---------------------------------------------------------------------------
# Plain-Python view used by the diff function. Keeps the diff logic
# decoupled from the SQLAlchemy ORM — tests just pass dataclasses.
# ---------------------------------------------------------------------------


@dataclass
class ScanFingerprint:
    """Compact, comparable summary of one scan's externally-visible
    surface. Built from a ScanResultRecord.scanner_metadata blob — the
    scanner already aggregates everything we need into ``metadata``
    today, so this just normalises the shape."""

    scan_job_id: uuid.UUID
    website_id: uuid.UUID
    org_id: uuid.UUID | None = None
    risk_score: int | None = None
    external_domains: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    security_headers: dict[str, str] = field(default_factory=dict)
    tls_summary: dict[str, Any] = field(default_factory=dict)
    forms: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    finding_severity_counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_scan_result(
        cls,
        scan_result: ScanResultRecord,
        *,
        scan_job: ScanJob | None = None,
    ) -> "ScanFingerprint":
        meta = (scan_result.scanner_metadata or {}) if scan_result else {}
        # The scanner already deduplicates external_domains scan-wide.
        external = set(meta.get("external_domains") or [])
        tech = set(meta.get("technologies") or [])
        headers = dict(meta.get("security_headers") or {})
        tls = dict(meta.get("tls_summary") or {})
        forms = list(meta.get("forms") or [])
        apis = list(meta.get("apis") or [])
        sev = dict(scan_result.severity_breakdown or {})
        return cls(
            scan_job_id=scan_result.scan_job_id,
            website_id=(scan_job.website_id if scan_job
                         else getattr(scan_result, "website_id", None)
                         or uuid.UUID(int=0)),
            org_id=(getattr(scan_job, "org_id", None)
                     if scan_job else None),
            risk_score=scan_result.risk_score,
            external_domains=external,
            technologies=tech,
            security_headers=headers,
            tls_summary=tls,
            forms=forms,
            apis=apis,
            finding_severity_counts=sev,
        )


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------


@dataclass
class ComputedDelta:
    """In-memory representation of the diff between two fingerprints.
    Persisted to :class:`ScanDelta` by :func:`persist_delta`."""

    website_id: uuid.UUID
    org_id: uuid.UUID | None
    current_scan_job_id: uuid.UUID
    previous_scan_job_id: uuid.UUID | None
    new_domains: list[dict[str, str]] = field(default_factory=list)
    removed_domains: list[dict[str, str]] = field(default_factory=list)
    changed_headers: list[dict[str, str]] = field(default_factory=list)
    changed_tls: dict[str, Any] = field(default_factory=dict)
    new_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    new_forms: list[str] = field(default_factory=list)
    new_apis: list[str] = field(default_factory=list)
    new_third_party_dependencies: list[str] = field(default_factory=list)
    new_findings_summary: dict[str, int] = field(default_factory=dict)
    drift_severity: DriftSeverity = DriftSeverity.NONE
    drift_summary: str | None = None
    risk_score_delta: int | None = None


# Header keys that materially change the security posture of a site —
# changes here always warrant the user's attention.
_HIGH_SIGNAL_HEADERS = frozenset({
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
})


def compute_delta(
    current: ScanFingerprint,
    previous: ScanFingerprint | None,
) -> ComputedDelta:
    """Compute the structured diff between two fingerprints.

    ``previous=None`` represents the first-ever scan for a target —
    every change list is left empty and the severity is
    :class:`DriftSeverity.NONE`. The first scan still gets a delta row
    so the dashboard shows "monitoring began" provenance."""
    delta = ComputedDelta(
        website_id=current.website_id,
        org_id=current.org_id,
        current_scan_job_id=current.scan_job_id,
        previous_scan_job_id=(previous.scan_job_id if previous else None),
    )

    if previous is None:
        delta.drift_severity = DriftSeverity.NONE
        delta.drift_summary = "Initial scan — baseline established."
        return delta

    # --- Domain set diff ---
    new_domains = sorted(current.external_domains - previous.external_domains)
    removed_domains = sorted(
        previous.external_domains - current.external_domains,
    )
    delta.new_domains = [{"domain": d} for d in new_domains]
    delta.removed_domains = [{"domain": d} for d in removed_domains]

    # --- Technology drift ---
    delta.new_technologies = sorted(current.technologies - previous.technologies)
    delta.removed_technologies = sorted(
        previous.technologies - current.technologies,
    )

    # --- Header drift (only meaningful headers) ---
    changed_headers: list[dict[str, str]] = []
    all_keys = (set(current.security_headers.keys())
                 | set(previous.security_headers.keys()))
    for key in sorted(all_keys):
        key_lower = key.lower()
        cur_v = current.security_headers.get(key, "")
        prev_v = previous.security_headers.get(key, "")
        if cur_v == prev_v:
            continue
        is_high_signal = key_lower in _HIGH_SIGNAL_HEADERS
        changed_headers.append({
            "header": key,
            "previous": prev_v,
            "current": cur_v,
            "high_signal": "true" if is_high_signal else "false",
        })
    delta.changed_headers = changed_headers

    # --- TLS drift (minimum version, cipher suite, expiry change) ---
    tls_diff: dict[str, Any] = {}
    for k in ("min_tls_version", "cipher_suite", "expires_at",
               "issuer", "is_self_signed"):
        if current.tls_summary.get(k) != previous.tls_summary.get(k):
            tls_diff[k] = {
                "previous": previous.tls_summary.get(k),
                "current": current.tls_summary.get(k),
            }
    delta.changed_tls = tls_diff

    # --- New forms / APIs (URL-shaped, so use a list comparison) ---
    prev_forms = set(previous.forms)
    delta.new_forms = [f for f in current.forms if f not in prev_forms]
    prev_apis = set(previous.apis)
    delta.new_apis = [a for a in current.apis if a not in prev_apis]

    # --- Risk score delta ---
    if (current.risk_score is not None
            and previous.risk_score is not None):
        delta.risk_score_delta = current.risk_score - previous.risk_score

    # --- Roll up severity ---
    delta.drift_severity, delta.drift_summary = _classify_drift(delta)
    return delta


def _classify_drift(d: ComputedDelta) -> tuple[DriftSeverity, str]:
    """Roll the diff up to a single drift severity + one-line summary
    the alert engine can use as a notification body.

    Heuristic rules (deliberately conservative — every threshold tuned
    to avoid alert fatigue):

      * CRITICAL — risk_score worsened by ≥20, or ≥1 high-signal header
        was removed entirely, or any TLS config moved to a lower-security
        state.
      * HIGH — ≥5 new external domains, or ≥1 high-signal header value
        changed, or any new admin/login form appeared.
      * MEDIUM — ≥3 new external domains, or ≥3 new technologies, or any
        non-high-signal header changed.
      * LOW — small surface change (1-2 new domains/techs).
      * NONE — no meaningful changes.
    """
    bits: list[str] = []

    high_signal_changed = [
        h for h in d.changed_headers
        if h.get("high_signal") == "true"
    ]
    high_signal_removed = [
        h for h in high_signal_changed
        if (h.get("current") or "") == ""
    ]
    new_admin_form = any(
        ("login" in f.lower() or "admin" in f.lower() or "auth" in f.lower())
        for f in d.new_forms
    )

    severity = DriftSeverity.NONE
    if (d.risk_score_delta is not None and d.risk_score_delta >= 20):
        severity = DriftSeverity.CRITICAL
        bits.append(f"risk score worsened by +{d.risk_score_delta}")
    if high_signal_removed:
        severity = DriftSeverity.CRITICAL
        bits.append(
            f"{len(high_signal_removed)} high-signal header(s) removed",
        )
    if d.changed_tls:
        # Any TLS change is treated as CRITICAL — operators expect
        # transport security to be stable between scans.
        severity = DriftSeverity.CRITICAL
        bits.append("TLS configuration changed")

    if severity != DriftSeverity.CRITICAL:
        if len(d.new_domains) >= 5:
            severity = DriftSeverity.HIGH
            bits.append(f"{len(d.new_domains)} new third-party domain(s)")
        if high_signal_changed:
            severity = DriftSeverity.HIGH
            bits.append(
                f"{len(high_signal_changed)} high-signal header(s) changed",
            )
        if new_admin_form:
            severity = DriftSeverity.HIGH
            bits.append("new admin/login form appeared")

    if severity == DriftSeverity.NONE:
        if (len(d.new_domains) >= 3 or len(d.new_technologies) >= 3
                or d.changed_headers):
            severity = DriftSeverity.MEDIUM
            if d.new_domains:
                bits.append(f"{len(d.new_domains)} new third-party domain(s)")
            if d.new_technologies:
                bits.append(
                    f"{len(d.new_technologies)} new tech(s) detected",
                )
            if d.changed_headers and not high_signal_changed:
                bits.append(
                    f"{len(d.changed_headers)} header(s) changed",
                )

    if severity == DriftSeverity.NONE:
        if d.new_domains or d.new_technologies or d.new_apis or d.new_forms:
            severity = DriftSeverity.LOW
            if d.new_domains:
                bits.append(f"{len(d.new_domains)} new third-party domain(s)")
            if d.new_technologies:
                bits.append(f"{len(d.new_technologies)} new tech(s)")
            if d.new_apis:
                bits.append(f"{len(d.new_apis)} new API endpoint(s)")
            if d.new_forms:
                bits.append(f"{len(d.new_forms)} new form(s)")

    summary = ("No meaningful changes vs prior scan."
                if severity == DriftSeverity.NONE
                else " • ".join(bits) + ".")
    return severity, summary


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


async def persist_delta(
    db: AsyncSession, computed: ComputedDelta,
) -> ScanDelta:
    """Insert a :class:`ScanDelta` row for the given computed diff. At
    most one delta per ``current_scan_job_id`` (unique constraint), so
    re-running this for the same scan returns the existing row."""
    existing = await db.execute(
        sa.select(ScanDelta).where(
            ScanDelta.current_scan_job_id == computed.current_scan_job_id,
        ),
    )
    found = existing.scalar_one_or_none()
    if found is not None:
        return found

    row = ScanDelta(
        org_id=computed.org_id,
        website_id=computed.website_id,
        current_scan_job_id=computed.current_scan_job_id,
        previous_scan_job_id=computed.previous_scan_job_id,
        new_domains=computed.new_domains,
        removed_domains=computed.removed_domains,
        changed_headers=computed.changed_headers,
        changed_tls=computed.changed_tls,
        new_technologies=computed.new_technologies,
        removed_technologies=computed.removed_technologies,
        new_forms=computed.new_forms,
        new_apis=computed.new_apis,
        new_third_party_dependencies=computed.new_third_party_dependencies,
        new_findings_summary=computed.new_findings_summary,
        drift_severity=computed.drift_severity,
        drift_summary=computed.drift_summary,
        risk_score_delta=computed.risk_score_delta,
    )
    db.add(row)
    await db.flush()
    return row
