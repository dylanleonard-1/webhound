# WebHound — scanner/tests/test_forms_discovery.py
# FIX 12 — tests for the form/parameter discovery engines and the passive
# (no-op) safe input tester.

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from webhound.core.extractor import ExtractedForm, FormInput, PageArtifacts
from webhound.engines.forms.form_discovery import FormDiscoveryEngine
from webhound.engines.forms.parameter_discovery import ParameterDiscoveryEngine
from webhound.engines.forms.safe_input_tester import SafeInputTester


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inp(name, itype="text", value=None):
    return FormInput(name=name, input_type=itype, value=value)


def _form(action="/login", action_url="https://example.com/login", method="POST",
          inputs=None, has_password=False, has_csrf=True):
    return ExtractedForm(
        action=action, action_url=action_url, method=method,
        inputs=tuple(inputs or []), has_password_field=has_password,
        has_csrf_token=has_csrf,
    )


def _artifacts(url="https://example.com/page?ref=home", forms=None, all_links=None,
               inline_js_request_urls=None):
    return PageArtifacts(
        url=url, status_code=200, content_type="text/html", title=None,
        all_links=all_links or [], internal_links=[], external_links=[],
        scripts=[], inline_scripts=[], external_script_urls=[],
        forms=forms or [], cookies=[], response_headers={}, meta_tags={},
        extracted_at=datetime.now(timezone.utc),
        inline_js_request_urls=inline_js_request_urls or [],
    )


@dataclass(frozen=True)
class _RFField:
    name: str | None
    input_type: str


@dataclass(frozen=True)
class _RenderedForm:
    action: str | None
    method: str = "POST"
    fields: tuple = ()
    has_password_field: bool = False
    page_url: str | None = None
    has_file_input: bool = False
    hidden_field_names: tuple = ()
    action_is_external: bool = False


# ---------------------------------------------------------------------------
# FormDiscoveryEngine
# ---------------------------------------------------------------------------

def test_static_form_metadata():
    form = _form(inputs=[
        _inp("username"), _inp("password", "password"),
        _inp("avatar", "file"), _inp("csrf", "hidden"),
    ], has_password=True)
    report = FormDiscoveryEngine().discover(_artifacts(forms=[form]))
    assert report.total == 1
    f = report.forms[0]
    assert f.origin == "static"
    assert f.method == "POST"
    assert f.source_page == "https://example.com/page?ref=home"
    assert "username" in f.input_names
    assert "text" in f.input_types and "password" in f.input_types
    assert f.has_password_field is True
    assert f.has_file_field is True
    assert f.hidden_field_names == ("csrf",)


def test_external_action_domain_detected():
    form = _form(action="https://evil.test/collect",
                 action_url="https://evil.test/collect")
    report = FormDiscoveryEngine().discover(
        _artifacts(url="https://example.com/checkout", forms=[form])
    )
    f = report.forms[0]
    assert f.action_is_external is True
    assert f.action_domain == "evil.test"
    assert "evil.test" in report.external_action_domains


def test_same_domain_action_not_external():
    form = _form(action="/submit", action_url="https://example.com/submit")
    report = FormDiscoveryEngine().discover(
        _artifacts(url="https://example.com/x", forms=[form])
    )
    assert report.forms[0].action_is_external is False
    assert report.external_action_domains == ()


def test_rendered_forms_merged():
    rf = _RenderedForm(
        action="https://cdn.other.test/upload",
        fields=(_RFField("file", "file"), _RFField("token", "hidden")),
        has_file_input=True, hidden_field_names=("token",),
        page_url="https://example.com/spa", action_is_external=True,
    )
    report = FormDiscoveryEngine().discover(_artifacts(), rendered_forms=[rf])
    rendered = [f for f in report.forms if f.origin == "rendered"]
    assert len(rendered) == 1
    assert rendered[0].has_file_field is True
    assert rendered[0].action_is_external is True
    assert rendered[0].input_names == ("file", "token")


def test_no_forms_is_empty():
    report = FormDiscoveryEngine().discover(_artifacts(forms=[]))
    assert report.total == 0
    assert report.external_action_domains == ()


# ---------------------------------------------------------------------------
# ParameterDiscoveryEngine
# ---------------------------------------------------------------------------

def test_url_query_params_from_page_and_links():
    arts = _artifacts(
        url="https://example.com/s?q=test&page=2",
        all_links=["https://example.com/list?sort=asc", "https://example.com/x"],
    )
    report = ParameterDiscoveryEngine().discover(arts)
    assert "q" in report.url_query_params
    assert "page" in report.url_query_params
    assert "sort" in report.url_query_params


def test_form_params_collected():
    form = _form(inputs=[_inp("email", "email"), _inp("subscribe", "checkbox")])
    report = ParameterDiscoveryEngine().discover(_artifacts(forms=[form]))
    assert len(report.form_params) == 1
    assert report.form_params[0].names == ("email", "subscribe")
    assert report.form_params[0].method == "POST"


def test_api_query_params_from_inline_js_requests():
    arts = _artifacts(inline_js_request_urls=[
        "https://api.example.com/v1/search?term=abc&limit=10",
        "https://api.example.com/v1/health",  # no params -> skipped
    ])
    report = ParameterDiscoveryEngine().discover(arts)
    assert len(report.api_query_params) == 1
    ap = report.api_query_params[0]
    assert set(ap.names) == {"term", "limit"}


def test_api_query_params_accepts_dicts():
    arts = _artifacts()
    observed = [{"url": "https://api.x.test/q?a=1", "method": "post"}]
    report = ParameterDiscoveryEngine().discover(arts, observed_requests=observed)
    assert report.api_query_params[0].method == "POST"
    assert report.api_query_params[0].names == ("a",)


def test_all_param_names_dedup():
    form = _form(inputs=[_inp("q")])  # 'q' also in url
    arts = _artifacts(url="https://example.com/p?q=1", forms=[form])
    report = ParameterDiscoveryEngine().discover(arts)
    assert report.all_param_names.count("q") == 1


# ---------------------------------------------------------------------------
# SafeInputTester — passive no-op invariants
# ---------------------------------------------------------------------------

def test_safe_input_tester_never_submits():
    form = _form(inputs=[_inp("user"), _inp("pass", "password"), _inp("go", "submit")])
    plans = SafeInputTester().analyze(_artifacts(forms=[form]))
    assert len(plans) == 1
    plan = plans[0]
    # Hard invariants: nothing is ever sent.
    assert plan.submitted is False
    assert plan.method == "none"
    # 'submit' button is not a testable input; user/pass are.
    assert "user" in plan.candidate_inputs
    assert "pass" in plan.candidate_inputs
    assert "go" not in plan.candidate_inputs


def test_safe_input_tester_no_forms():
    assert SafeInputTester().analyze(_artifacts(forms=[])) == []
