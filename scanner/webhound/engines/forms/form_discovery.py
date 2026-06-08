# WebHound — scanner/webhound/engines/forms/form_discovery.py
# FIX 12 — passive form discovery.
#
# Inventories every <form> the scanner saw, from both the STATIC HTML
# (PageArtifacts.forms) and the RENDERED DOM (browser RenderedForm telemetry).
# It records *metadata only* — action, method, input names/types, and the
# password/file/hidden flags — so downstream engines and the dashboard have a
# single normalised list of input surfaces.
#
# SAFE-MODE CONTRACT:
#   * Read-only. No form is ever submitted, focused, filled, or POSTed.
#   * No network calls — operates purely on already-extracted artifacts.

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from webhound.core.extractor import ExtractedForm, PageArtifacts

_ENGINE = "form_discovery"


@dataclass(frozen=True)
class DiscoveredForm:
    """One form discovered on a page. Metadata only — never submitted."""

    source_page: str | None
    action: str | None
    action_url: str | None
    method: str
    input_names: tuple[str, ...]
    input_types: tuple[str, ...]
    has_password_field: bool
    has_file_field: bool
    hidden_field_names: tuple[str, ...]
    action_is_external: bool
    action_domain: str | None
    origin: str  # "static" | "rendered"


@dataclass(frozen=True)
class FormDiscoveryReport:
    forms: tuple[DiscoveredForm, ...] = ()

    @property
    def total(self) -> int:
        return len(self.forms)

    @property
    def external_action_domains(self) -> tuple[str, ...]:
        seen: list[str] = []
        for f in self.forms:
            if f.action_is_external and f.action_domain and f.action_domain not in seen:
                seen.append(f.action_domain)
        return tuple(seen)


def _hostname(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


def _action_is_external(action_url: str | None, page_url: str | None) -> tuple[bool, str | None]:
    """(is_external, action_domain). External = action hostname differs from the
    page hostname. Falls back to "not external" when either side is unknown
    (relative actions, no page url) so we never over-report."""
    a_host = _hostname(action_url)
    if a_host is None:
        return False, None
    p_host = _hostname(page_url)
    if p_host is None:
        return False, a_host
    return (a_host != p_host), a_host


def _from_static(form: ExtractedForm, page_url: str | None) -> DiscoveredForm:
    names = tuple(i.name for i in form.inputs if i.name)
    types = tuple(i.input_type for i in form.inputs if i.input_type)
    has_file = any((i.input_type or "").lower() == "file" for i in form.inputs)
    hidden = tuple(
        i.name for i in form.inputs
        if i.name and (i.input_type or "").lower() == "hidden"
    )
    is_ext, domain = _action_is_external(form.action_url, page_url)
    return DiscoveredForm(
        source_page=page_url,
        action=form.action,
        action_url=form.action_url,
        method=(form.method or "GET").upper(),
        input_names=names,
        input_types=types,
        has_password_field=bool(form.has_password_field)
        or any((i.input_type or "").lower() == "password" for i in form.inputs),
        has_file_field=has_file,
        hidden_field_names=hidden,
        action_is_external=is_ext,
        action_domain=domain,
        origin="static",
    )


def _from_rendered(form: object) -> DiscoveredForm:
    """Build from a browser RenderedForm (duck-typed to avoid importing the
    optional browser package)."""
    fields = tuple(getattr(form, "fields", ()) or ())
    names = tuple(f.name for f in fields if getattr(f, "name", None))
    types = tuple(
        getattr(f, "input_type", None) for f in fields
        if getattr(f, "input_type", None)
    )
    action_url = getattr(form, "action", None)
    page_url = getattr(form, "page_url", None)
    # RenderedForm already computes action_is_external against the registrable
    # domain; trust it but recompute the domain string for display.
    is_ext = bool(getattr(form, "action_is_external", False))
    domain = _hostname(action_url)
    return DiscoveredForm(
        source_page=page_url,
        action=action_url,
        action_url=action_url,
        method=str(getattr(form, "method", "GET") or "GET").upper(),
        input_names=names,
        input_types=types,
        has_password_field=bool(getattr(form, "has_password_field", False)),
        has_file_field=bool(getattr(form, "has_file_input", False)),
        hidden_field_names=tuple(getattr(form, "hidden_field_names", ()) or ()),
        action_is_external=is_ext,
        action_domain=domain,
        origin="rendered",
    )


class FormDiscoveryEngine:
    """Passive inventory of static + rendered forms.

    Call ``discover(artifacts, rendered_forms=...)`` to get a
    :class:`FormDiscoveryReport`. Read-only; never submits a form.
    """

    NAME = _ENGINE

    def discover(
        self,
        artifacts: PageArtifacts,
        rendered_forms: list | tuple | None = None,
    ) -> FormDiscoveryReport:
        discovered: list[DiscoveredForm] = []
        for form in (artifacts.forms or []):
            discovered.append(_from_static(form, artifacts.url))
        for rform in (rendered_forms or []):
            discovered.append(_from_rendered(rform))
        return FormDiscoveryReport(forms=tuple(discovered))


__all__ = [
    "DiscoveredForm",
    "FormDiscoveryReport",
    "FormDiscoveryEngine",
]
