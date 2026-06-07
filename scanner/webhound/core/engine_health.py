# WebHound — scanner/webhound/core/engine_health.py
# Phase-19 production hardening (Task 5): aggregate per-engine health
# ACROSS many scans so a broken engine is visible. Each scan records
# per-engine status (engine_diagnostics on ScanResult); this rolls those
# up into success/failure/timeout counts, average duration, and findings
# rate per engine, and flags engines that look broken (e.g. one that
# suddenly returns zero findings on every scan).
#
# Pure — operates on EngineStatus dicts the caller collected from many
# scans. No I/O. The worker/API stores scans; this turns their
# diagnostics into an operational signal.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# An engine flagged when its failure rate exceeds this across the window.
_FAILURE_RATE_ALERT = 0.5
# An engine flagged "silent" when it ran on >= this many scans and
# produced zero findings on all of them (possible breakage / drift).
_SILENT_MIN_RUNS = 10


@dataclass
class EngineHealth:
    name: str
    runs: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    skips: int = 0
    total_findings: int = 0
    total_duration_ms: float = 0.0
    scans_with_findings: int = 0

    @property
    def failure_rate(self) -> float:
        return round(self.failures / self.runs, 4) if self.runs else 0.0

    @property
    def avg_duration_ms(self) -> float:
        return round(self.total_duration_ms / self.runs, 2) if self.runs else 0.0

    @property
    def findings_rate(self) -> float:
        """Share of runs that produced >=1 finding."""
        return (round(self.scans_with_findings / self.runs, 4)
                if self.runs else 0.0)

    @property
    def is_unhealthy(self) -> bool:
        if self.runs and self.failure_rate >= _FAILURE_RATE_ALERT:
            return True
        # Silent: ran a lot, never found anything (and never errored — a
        # pure error spike is caught by failure_rate above).
        if (self.successes >= _SILENT_MIN_RUNS
                and self.total_findings == 0):
            return True
        return False

    def health_note(self) -> str | None:
        if not self.is_unhealthy:
            return None
        if self.failure_rate >= _FAILURE_RATE_ALERT:
            return (f"{self.name}: {self.failure_rate:.0%} of runs failed "
                    f"({self.failures}/{self.runs})")
        return (f"{self.name}: produced 0 findings across {self.successes} "
                "successful runs — possible breakage or signature drift")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "runs": self.runs,
            "successes": self.successes, "failures": self.failures,
            "timeouts": self.timeouts, "skips": self.skips,
            "total_findings": self.total_findings,
            "avg_duration_ms": self.avg_duration_ms,
            "failure_rate": self.failure_rate,
            "findings_rate": self.findings_rate,
            "unhealthy": self.is_unhealthy,
            "health_note": self.health_note(),
        }


def _status_of(d: dict[str, Any]) -> str:
    return str(d.get("status", "")).lower()


def aggregate_engine_health(
    engine_status_records: Iterable[dict[str, Any]],
) -> dict[str, EngineHealth]:
    """Roll up a flat stream of per-engine status dicts (one per engine
    per scan) into {engine_name: EngineHealth}.

    Each record is an EngineStatus.to_dict()-shaped dict: name, status
    ('passed'/'findings'/'failed'/'skipped'/'timeout'), findings_count,
    duration_ms, error_message."""
    out: dict[str, EngineHealth] = {}
    for rec in engine_status_records:
        name = rec.get("name")
        if not name:
            continue
        h = out.setdefault(name, EngineHealth(name=name))
        status = _status_of(rec)
        findings = int(rec.get("findings_count", 0) or 0)
        duration = float(rec.get("duration_ms", 0) or 0.0)
        err = (rec.get("error_message") or "").lower()

        h.runs += 1
        h.total_duration_ms += duration
        if status == "skipped":
            h.skips += 1
            h.runs -= 1  # a skip isn't a run for rate purposes
            continue
        if status in ("failed", "error") or rec.get("error_message"):
            h.failures += 1
            if "timeout" in err or status == "timeout":
                h.timeouts += 1
        else:
            h.successes += 1
            h.total_findings += findings
            if findings > 0:
                h.scans_with_findings += 1
    return out


def health_report(
    engine_status_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """A flat report: per-engine health + the list of unhealthy engines
    (the operational alert surface)."""
    health = aggregate_engine_health(engine_status_records)
    unhealthy = [h.health_note() for h in health.values()
                 if h.is_unhealthy]
    return {
        "engine_count": len(health),
        "unhealthy_count": len(unhealthy),
        "unhealthy_engines": [n for n in unhealthy if n],
        "engines": {name: h.to_dict() for name, h in sorted(health.items())},
    }
