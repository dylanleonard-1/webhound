# WebHound — scanner/webhound/advisor/business_impact.py
# Phase-15 Task 4: translate a finding into business-language impact
# dimensions a non-technical owner understands — customer trust, business
# operations, revenue, authentication, payment, and data-exposure risk.
#
# Each dimension is scored none/low/medium/high so a dashboard can show
# "this affects: Payment (High), Customer Trust (Medium)". Pure.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.core.trust_policy import finding_type_of


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3}[self.value]


# The six business dimensions (Task 4).
DIMENSIONS = (
    "customer_trust", "business_operations", "revenue",
    "authentication_risk", "payment_risk", "data_exposure_risk",
)


@dataclass
class BusinessImpact:
    dimensions: dict[str, ImpactLevel] = field(default_factory=dict)
    summary: str = ""

    @property
    def primary(self) -> str | None:
        """The highest-impact dimension (for headline display)."""
        if not self.dimensions:
            return None
        return max(self.dimensions.items(),
                   key=lambda kv: kv[1].rank)[0]

    @property
    def max_level(self) -> ImpactLevel:
        return max(self.dimensions.values(),
                   key=lambda l: l.rank, default=ImpactLevel.NONE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimensions": {k: v.value for k, v in self.dimensions.items()
                           if v != ImpactLevel.NONE},
            "primary_dimension": self.primary,
            "max_level": self.max_level.value,
            "summary": self.summary,
        }


def _engine(f: Any) -> str:
    return getattr(f, "scanner_engine", "") or ""


def _category(f: Any) -> str:
    c = getattr(f, "category", None)
    return getattr(c, "value", str(c or ""))


def _title(f: Any) -> str:
    return (getattr(f, "title", "") or "").lower()


def _severity_rank(f: Any) -> int:
    s = getattr(f, "severity", None)
    return getattr(s, "rank", 0)


_H, _M, _L, _N = (ImpactLevel.HIGH, ImpactLevel.MEDIUM,
                  ImpactLevel.LOW, ImpactLevel.NONE)


def assess_impact(f: Any) -> BusinessImpact:
    """Score the six business dimensions for one finding."""
    eng = _engine(f)
    cat = _category(f)
    title = _title(f)
    ftype = finding_type_of(f)
    dims: dict[str, ImpactLevel] = {d: _N for d in DIMENSIONS}

    # Inventory has no business impact by itself.
    if ftype == "inventory":
        return BusinessImpact(dimensions=dims,
                              summary="Discovered asset — no direct business impact.")

    # --- Payment ---------------------------------------------------------
    if ("payment" in title or "checkout" in title or "card" in title
            or "credit" in title):
        dims["payment_risk"] = _H
        dims["revenue"] = _M
        dims["customer_trust"] = _M

    # --- Authentication / credentials -----------------------------------
    if (eng == "sensitive_paths" and ("admin" in title or "login" in title)) \
            or "auth" in title or "login" in title or "password" in title \
            or "session" in title:
        dims["authentication_risk"] = (
            _H if eng in ("sensitive_paths", "form_risk", "cookie_scanner")
            else _M)
        dims["customer_trust"] = max(dims["customer_trust"], _M,
                                     key=lambda l: l.rank)

    # --- Data exposure ---------------------------------------------------
    if (eng == "secret_scanner" or "secret" in title or "credential" in title
            or "environment variable" in title or ".env" in title
            or "api key" in title or "token" in title):
        dims["data_exposure_risk"] = _H
        dims["customer_trust"] = _H

    # --- Compromise indicators → trust + operations ---------------------
    if cat == "compromise" or eng in ("injected_js", "hidden_iframes",
                                      "suspicious_redirects",
                                      "obfuscation_detector"):
        dims["customer_trust"] = _H
        dims["business_operations"] = _M
        if "checkout" in title or "payment" in title:
            dims["payment_risk"] = _H

    # --- Threat-intel / supply chain → trust ----------------------------
    if eng in ("threat_intel", "third_party_domains") and ftype != "inventory":
        if _severity_rank(f) >= 3:  # high+
            dims["customer_trust"] = max(dims["customer_trust"], _M,
                                         key=lambda l: l.rank)

    # --- Hardening: low operational impact ------------------------------
    if ftype == "hardening":
        dims["business_operations"] = max(dims["business_operations"], _L,
                                          key=lambda l: l.rank)

    # Build a plain-language summary from the active dimensions.
    active = {k: v for k, v in dims.items() if v != _N}
    if not active:
        summary = "Limited direct business impact."
    else:
        label = {
            "customer_trust": "customer trust",
            "business_operations": "business operations",
            "revenue": "revenue",
            "authentication_risk": "account security",
            "payment_risk": "payment security",
            "data_exposure_risk": "data exposure",
        }
        parts = [f"{label[k]} ({v.value})"
                 for k, v in sorted(active.items(),
                                    key=lambda kv: kv[1].rank, reverse=True)]
        summary = "Primarily affects " + ", ".join(parts) + "."

    return BusinessImpact(dimensions=dims, summary=summary)
