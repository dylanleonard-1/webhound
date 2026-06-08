# WebHound — scanner/webhound/engines/forms/parameter_discovery.py
# FIX 12 — passive parameter discovery.
#
# Enumerates every input PARAMETER the scanner can see, without ever sending a
# value. Three sources:
#   * URL query params — from the page URL and every discovered link.
#   * Form params      — input names per <form>, with the form's method/action.
#   * API query params — from request URLs observed statically (fetch/XHR URLs
#     parsed out of inline JS) or supplied from browser network telemetry.
#
# SAFE-MODE CONTRACT:
#   * Read-only. Parameters are catalogued, never fuzzed or submitted.
#   * No network calls — operates purely on already-extracted artifacts.

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from webhound.core.extractor import PageArtifacts

_ENGINE = "parameter_discovery"


@dataclass(frozen=True)
class FormParameter:
    source_page: str | None
    action: str | None
    method: str
    names: tuple[str, ...]


@dataclass(frozen=True)
class ApiParameter:
    url: str
    method: str
    names: tuple[str, ...]


@dataclass
class ParameterDiscoveryReport:
    url_query_params: list[str] = field(default_factory=list)
    form_params: list[FormParameter] = field(default_factory=list)
    api_query_params: list[ApiParameter] = field(default_factory=list)

    @property
    def all_param_names(self) -> tuple[str, ...]:
        seen: list[str] = []
        for name in self.url_query_params:
            if name not in seen:
                seen.append(name)
        for fp in self.form_params:
            for name in fp.names:
                if name not in seen:
                    seen.append(name)
        for ap in self.api_query_params:
            for name in ap.names:
                if name not in seen:
                    seen.append(name)
        return tuple(seen)


def _query_names(url: str | None) -> tuple[str, ...]:
    if not url:
        return ()
    try:
        qs = urlparse(url).query
    except Exception:  # noqa: BLE001
        return ()
    if not qs:
        return ()
    # keep_blank_values so ?flag= is still discovered; preserve first-seen order.
    parsed = parse_qs(qs, keep_blank_values=True)
    return tuple(parsed.keys())


def _coerce_request(obj: object) -> tuple[str, str] | None:
    """Accept either a plain URL string or an object/dict with .url/.method."""
    if isinstance(obj, str):
        return obj, "GET"
    if isinstance(obj, dict):
        url = obj.get("url")
        if isinstance(url, str) and url:
            return url, str(obj.get("method") or "GET").upper()
        return None
    url = getattr(obj, "url", None)
    if isinstance(url, str) and url:
        return url, str(getattr(obj, "method", "GET") or "GET").upper()
    return None


class ParameterDiscoveryEngine:
    """Passive parameter catalogue from URLs, forms, and observed requests.

    Call ``discover(artifacts, observed_requests=...)`` to get a
    :class:`ParameterDiscoveryReport`. Read-only; never submits a value.
    """

    NAME = _ENGINE

    def discover(
        self,
        artifacts: PageArtifacts,
        observed_requests: list | tuple | None = None,
    ) -> ParameterDiscoveryReport:
        report = ParameterDiscoveryReport()

        # 1. URL query params — page URL + every discovered link.
        url_seen: list[str] = []
        url_sources: list[str | None] = [artifacts.url]
        url_sources.extend(artifacts.all_links or [])
        for src in url_sources:
            for name in _query_names(src):
                if name not in url_seen:
                    url_seen.append(name)
        report.url_query_params = url_seen

        # 2. Form params.
        for form in (artifacts.forms or []):
            names = tuple(i.name for i in form.inputs if i.name)
            if not names:
                continue
            report.form_params.append(FormParameter(
                source_page=artifacts.url,
                action=form.action_url or form.action,
                method=(form.method or "GET").upper(),
                names=names,
            ))

        # 3. API query params from observed request URLs. Default source is the
        # statically-parsed fetch/XHR URLs from inline JS; the browser pass can
        # supply richer network telemetry via observed_requests.
        requests: list[object] = list(observed_requests or [])
        if not requests:
            requests = list(getattr(artifacts, "inline_js_request_urls", []) or [])
        api_seen: set[tuple[str, str]] = set()
        for raw in requests:
            coerced = _coerce_request(raw)
            if coerced is None:
                continue
            url, method = coerced
            names = _query_names(url)
            if not names:
                continue
            key = (url, method)
            if key in api_seen:
                continue
            api_seen.add(key)
            report.api_query_params.append(
                ApiParameter(url=url, method=method, names=names)
            )

        return report


__all__ = [
    "FormParameter",
    "ApiParameter",
    "ParameterDiscoveryReport",
    "ParameterDiscoveryEngine",
]
