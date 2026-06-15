# WebHound — scanner/tests/test_safe_input_tester_and_param_discovery.py
# Phase 9B: Unit tests for safe_input_tester and parameter_discovery engines.
# Previously STATIC-only — this file brings both to full unit-test coverage.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import ExtractedForm, FormInput, PageArtifacts
from webhound.engines.forms.safe_input_tester import SafeInputTester, InputTestPlan
from webhound.engines.forms.parameter_discovery import (
    ParameterDiscoveryEngine,
    ParameterDiscoveryReport,
    FormParameter,
    ApiParameter,
)

_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inp(name: str, itype: str = "text", value: str | None = None) -> FormInput:
    return FormInput(name=name, input_type=itype, value=value)


def _form(
    action: str | None = "/submit",
    action_url: str | None = "https://example.com/submit",
    method: str = "POST",
    inputs: list[FormInput] | None = None,
    has_password: bool = False,
) -> ExtractedForm:
    return ExtractedForm(
        action=action,
        action_url=action_url,
        method=method,
        inputs=tuple(inputs or []),
        has_password_field=has_password,
        has_csrf_token=True,
        method_explicit=True,
    )


def _artifacts(
    url: str = "https://example.com/",
    forms: list[ExtractedForm] | None = None,
    all_links: list[str] | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test",
        all_links=all_links or [],
        internal_links=[],
        external_links=[],
        scripts=[],
        inline_scripts=[],
        external_script_urls=[],
        forms=forms or [],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=_NOW,
    )


# ---------------------------------------------------------------------------
# SafeInputTester
# ---------------------------------------------------------------------------

class TestSafeInputTester:
    def setup_method(self):
        self.engine = SafeInputTester()

    def test_engine_name(self):
        assert self.engine.NAME == "safe_input_tester"

    def test_no_forms_returns_empty(self):
        a = _artifacts(forms=[])
        plans = self.engine.analyze(a)
        assert plans == []

    def test_one_form_returns_one_plan(self):
        form = _form(inputs=[_inp("username"), _inp("password", "password")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert len(plans) == 1

    def test_multiple_forms_returns_multiple_plans(self):
        forms = [
            _form(inputs=[_inp("q")]),
            _form(action="/login", inputs=[_inp("user"), _inp("pass", "password")]),
        ]
        a = _artifacts(forms=forms)
        plans = self.engine.analyze(a)
        assert len(plans) == 2

    # ---- CRITICAL PASSIVE-MODE INVARIANTS ----

    def test_submitted_is_always_false(self):
        form = _form(inputs=[_inp("user"), _inp("pass", "password")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        for plan in plans:
            assert plan.submitted is False

    def test_method_is_always_none(self):
        form = _form(inputs=[_inp("q")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        for plan in plans:
            assert plan.method == "none"

    def test_note_mentions_passive(self):
        form = _form(inputs=[_inp("q")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert "passive" in plans[0].note.lower()

    def test_submitted_invariant_not_overridable(self):
        plan = InputTestPlan(source_page="https://example.com", action="/submit", candidate_inputs=())
        assert plan.submitted is False
        # Dataclass field default cannot change the invariant
        assert plan.method == "none"

    # ---- Candidate inputs ----

    def test_text_inputs_in_candidates(self):
        form = _form(inputs=[_inp("query", "text"), _inp("email", "email")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert "query" in plans[0].candidate_inputs
        assert "email" in plans[0].candidate_inputs

    def test_password_input_in_candidates(self):
        form = _form(inputs=[_inp("pw", "password")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert "pw" in plans[0].candidate_inputs

    def test_hidden_input_in_candidates(self):
        form = _form(inputs=[_inp("csrf_token", "hidden")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert "csrf_token" in plans[0].candidate_inputs

    def test_submit_button_not_in_candidates(self):
        form = _form(inputs=[_inp("q", "text"), _inp("submit", "submit")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert "submit" not in plans[0].candidate_inputs

    def test_unnamed_inputs_excluded(self):
        form = _form(inputs=[FormInput(name=None, input_type="text", value=None)])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert plans[0].candidate_inputs == ()

    def test_source_page_captured(self):
        form = _form(inputs=[_inp("q")])
        a = _artifacts(url="https://example.com/search", forms=[form])
        plans = self.engine.analyze(a)
        assert plans[0].source_page == "https://example.com/search"

    def test_action_captured(self):
        form = _form(action="/submit", inputs=[_inp("q")])
        a = _artifacts(forms=[form])
        plans = self.engine.analyze(a)
        assert plans[0].action is not None


# ---------------------------------------------------------------------------
# ParameterDiscoveryEngine
# ---------------------------------------------------------------------------

class TestParameterDiscoveryEngine:
    def setup_method(self):
        self.engine = ParameterDiscoveryEngine()

    def test_engine_name(self):
        assert self.engine.NAME == "parameter_discovery"

    def test_empty_page_returns_empty_report(self):
        a = _artifacts()
        report = self.engine.discover(a)
        assert isinstance(report, ParameterDiscoveryReport)
        assert report.url_query_params == []
        assert report.form_params == []
        assert report.api_query_params == []

    # ---- URL query params ----

    def test_url_query_params_extracted_from_page_url(self):
        a = _artifacts(url="https://example.com/search?q=test&page=1")
        report = self.engine.discover(a)
        assert "q" in report.url_query_params
        assert "page" in report.url_query_params

    def test_url_query_params_from_links(self):
        a = _artifacts(
            url="https://example.com/",
            all_links=["https://example.com/search?q=hello&lang=en"],
        )
        report = self.engine.discover(a)
        assert "q" in report.url_query_params
        assert "lang" in report.url_query_params

    def test_url_params_deduplicated(self):
        a = _artifacts(
            url="https://example.com/?q=a",
            all_links=["https://example.com/?q=b"],
        )
        report = self.engine.discover(a)
        assert report.url_query_params.count("q") == 1

    def test_url_no_query_string_no_params(self):
        a = _artifacts(url="https://example.com/")
        report = self.engine.discover(a)
        assert report.url_query_params == []

    # ---- Form params ----

    def test_form_params_extracted(self):
        form = _form(inputs=[_inp("username"), _inp("password", "password")])
        a = _artifacts(forms=[form])
        report = self.engine.discover(a)
        assert len(report.form_params) == 1
        assert "username" in report.form_params[0].names
        assert "password" in report.form_params[0].names

    def test_multiple_forms_all_captured(self):
        forms = [
            _form(action="/login", inputs=[_inp("user"), _inp("pass", "password")]),
            _form(action="/search", inputs=[_inp("q")]),
        ]
        a = _artifacts(forms=forms)
        report = self.engine.discover(a)
        assert len(report.form_params) == 2

    def test_form_with_no_inputs_excluded(self):
        form = _form(inputs=[])
        a = _artifacts(forms=[form])
        report = self.engine.discover(a)
        assert report.form_params == []

    def test_form_method_captured(self):
        form = _form(method="GET", inputs=[_inp("q")])
        a = _artifacts(forms=[form])
        report = self.engine.discover(a)
        assert report.form_params[0].method == "GET"

    def test_form_action_captured(self):
        form = _form(action_url="https://example.com/login", inputs=[_inp("user")])
        a = _artifacts(forms=[form])
        report = self.engine.discover(a)
        assert report.form_params[0].action == "https://example.com/login"

    # ---- API query params ----

    def test_api_params_from_observed_requests(self):
        a = _artifacts()
        requests = ["https://api.example.com/users?sort=name&page=1"]
        report = self.engine.discover(a, observed_requests=requests)
        assert len(report.api_query_params) == 1
        assert "sort" in report.api_query_params[0].names
        assert "page" in report.api_query_params[0].names

    def test_api_request_without_query_string_excluded(self):
        a = _artifacts()
        requests = ["https://api.example.com/users"]
        report = self.engine.discover(a, observed_requests=requests)
        assert report.api_query_params == []

    def test_api_request_dict_format(self):
        a = _artifacts()
        requests = [{"url": "https://api.example.com/search?q=test", "method": "GET"}]
        report = self.engine.discover(a, observed_requests=requests)
        assert len(report.api_query_params) == 1
        assert "q" in report.api_query_params[0].names

    def test_api_request_deduplication(self):
        a = _artifacts()
        requests = [
            "https://api.example.com/search?q=test",
            "https://api.example.com/search?q=test",
        ]
        report = self.engine.discover(a, observed_requests=requests)
        # Identical URL+method pair — deduped to one entry
        assert len(report.api_query_params) == 1

    # ---- all_param_names ----

    def test_all_param_names_aggregates_all_sources(self):
        form = _form(inputs=[_inp("username")])
        a = _artifacts(
            url="https://example.com/?page=1",
            forms=[form],
        )
        requests = ["https://api.example.com/data?sort=asc"]
        report = self.engine.discover(a, observed_requests=requests)
        all_names = report.all_param_names
        assert "page" in all_names
        assert "username" in all_names
        assert "sort" in all_names

    def test_all_param_names_no_duplicates(self):
        form = _form(inputs=[_inp("q")])
        a = _artifacts(
            url="https://example.com/?q=test",
            forms=[form],
        )
        report = self.engine.discover(a)
        all_names = report.all_param_names
        assert all_names.count("q") == 1

    def test_empty_page_all_param_names_empty(self):
        a = _artifacts()
        report = self.engine.discover(a)
        assert report.all_param_names == ()
