# WebHound — scanner/tests/test_forms_engines.py
# Tests for Phase 8 form risk and input analysis engines.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import ExtractedForm, FormInput, PageArtifacts
from webhound.engines.forms.form_risk import FormRiskEngine
from webhound.engines.forms.input_analysis import InputAnalysisEngine
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inp(name: str | None, itype: str = "text", value: str | None = None) -> FormInput:
    return FormInput(name=name, input_type=itype, value=value)


def _form(
    action: str | None = "/submit",
    action_url: str | None = "https://example.com/submit",
    method: str = "POST",
    inputs: list[FormInput] | None = None,
    has_password: bool = False,
    has_csrf: bool = True,
) -> ExtractedForm:
    return ExtractedForm(
        action=action,
        action_url=action_url,
        method=method,
        inputs=tuple(inputs or []),
        has_password_field=has_password,
        has_csrf_token=has_csrf,
    )


def _artifacts(
    url: str = "https://example.com",
    forms: list[ExtractedForm] | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title=None,
        all_links=[],
        internal_links=[],
        external_links=[],
        scripts=[],
        inline_scripts=[],
        external_script_urls=[],
        forms=forms or [],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=datetime.now(timezone.utc),
    )


def _all_titles(findings) -> list[str]:
    return [f.title for f in findings]


# ---------------------------------------------------------------------------
# FormRiskEngine
# ---------------------------------------------------------------------------

class TestFormRiskEngine:
    def setup_method(self):
        self.engine = FormRiskEngine()

    def test_engine_name(self):
        assert FormRiskEngine.NAME == "form_risk"

    def test_no_forms_returns_empty(self):
        art = _artifacts(forms=[])
        assert self.engine.analyze(art) == []

    def test_password_over_http_critical(self):
        form = _form(
            action_url="http://example.com/login",
            has_password=True,
        )
        art = _artifacts(url="http://example.com/login", forms=[form])
        findings = self.engine.analyze(art)
        titles = _all_titles(findings)
        assert any("password" in t.lower() and "http" in t.lower() for t in titles)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_password_over_https_no_http_finding(self):
        form = _form(has_password=True)
        art = _artifacts(url="https://example.com/login", forms=[form])
        findings = self.engine.analyze(art)
        # Should not trigger "password over HTTP page" (page is HTTPS)
        assert not any(
            "password" in f.title.lower() and "http page" in f.title.lower()
            for f in findings
        )

    def test_https_form_posting_to_http_high(self):
        form = _form(
            action="http://example.com/login",
            action_url="http://example.com/login",
            has_password=True,
        )
        art = _artifacts(url="https://example.com", forms=[form])
        findings = self.engine.analyze(art)
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("http" in f.title.lower() or "downgrade" in f.title.lower() for f in findings)

    def test_external_login_action_critical(self):
        form = _form(
            action="https://evil.com/collect",
            action_url="https://evil.com/collect",
            has_password=True,
        )
        art = _artifacts(url="https://example.com/login", forms=[form])
        findings = self.engine.analyze(art)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("external" in f.title.lower() or "login" in f.title.lower() for f in findings)

    def test_external_action_no_credentials_high(self):
        form = _form(
            action="https://analytics.com/track",
            action_url="https://analytics.com/track",
            inputs=[_inp("email"), _inp("subscribe", "checkbox")],
            has_password=False,
        )
        art = _artifacts(url="https://example.com", forms=[form])
        findings = self.engine.analyze(art)
        external_findings = [f for f in findings if "external" in f.title.lower()]
        assert external_findings
        assert all(f.severity == Severity.HIGH for f in external_findings)

    def test_external_payment_form_critical(self):
        form = _form(
            action="https://skimmer.io/card",
            action_url="https://skimmer.io/card",
            inputs=[
                _inp("card_number"),
                _inp("cvv"),
                _inp("exp_month"),
            ],
            has_csrf=False,
        )
        art = _artifacts(url="https://shop.example.com/checkout", forms=[form])
        findings = self.engine.analyze(art)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("payment" in f.title.lower() or "login" in f.title.lower() for f in findings)

    def test_missing_csrf_on_post_medium(self):
        form = _form(
            inputs=[_inp("email"), _inp("name")],
            has_csrf=False,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        csrf_findings = [f for f in findings if "csrf" in f.title.lower()]
        assert csrf_findings
        assert all(f.severity == Severity.MEDIUM for f in csrf_findings)

    def test_csrf_present_no_csrf_finding(self):
        form = _form(
            inputs=[_inp("email"), _inp("_csrf_token", "hidden")],
            has_csrf=True,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert not any("csrf" in f.title.lower() for f in findings)

    def test_get_form_with_password_high(self):
        form = _form(
            method="GET",
            inputs=[_inp("username"), _inp("password", "password")],
            has_password=True,
            has_csrf=False,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        get_cred_findings = [f for f in findings if "get" in f.title.lower() or "credential" in f.title.lower()]
        assert get_cred_findings
        assert all(f.severity == Severity.HIGH for f in get_cred_findings)

    def test_file_upload_form_medium(self):
        form = _form(
            inputs=[_inp("username"), _inp("avatar", "file")],
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        upload_findings = [f for f in findings if "upload" in f.title.lower()]
        assert upload_findings
        assert all(f.severity == Severity.MEDIUM for f in upload_findings)

    def test_hidden_sensitive_field_medium(self):
        form = _form(
            inputs=[
                _inp("email"),
                _inp("api_key", "hidden", value="sk-test-123"),
            ],
            has_csrf=False,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        hidden_findings = [f for f in findings if "hidden" in f.title.lower() and "sensitive" in f.title.lower()]
        assert hidden_findings
        assert all(f.severity == Severity.MEDIUM for f in hidden_findings)

    def test_excessive_hidden_inputs_low(self):
        hidden = [_inp(f"h{i}", "hidden") for i in range(10)]
        form = _form(inputs=hidden + [_inp("submit", "submit")], has_csrf=False)
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        excessive = [f for f in findings if "excessive" in f.title.lower() or "unusual" in f.title.lower()]
        assert excessive
        assert all(f.severity == Severity.LOW for f in excessive)

    def test_suspicious_action_url_medium(self):
        form = _form(
            action="/debug/submit",
            action_url="https://example.com/debug/submit",
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        suspicious = [f for f in findings if "suspicious" in f.title.lower() or "debug" in f.title.lower()]
        assert suspicious
        assert all(f.severity == Severity.MEDIUM for f in suspicious)

    def test_clean_form_no_findings(self):
        form = _form(
            inputs=[_inp("email"), _inp("message", "textarea")],
            has_csrf=True,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        # Only legitimate finding might be CSRF check — form has CSRF so none expected
        assert len(findings) == 0

    def test_findings_have_required_fields(self):
        form = _form(
            action="https://evil.com/steal",
            action_url="https://evil.com/steal",
            has_password=True,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert findings
        for f in findings:
            assert f.title
            assert f.description
            assert f.severity
            assert f.category == FindingCategory.FORM
            assert f.evidence
            assert f.remediation
            assert f.framework.owasp_top10
            assert f.framework.cwe_ids
            assert f.scanner_engine == "form_risk"

    def test_findings_have_evidence_location(self):
        form = _form(has_password=True)
        art = _artifacts(url="http://example.com/login", forms=[form])
        findings = self.engine.analyze(art)
        for f in findings:
            for ev in f.evidence:
                assert ev.location


# ---------------------------------------------------------------------------
# InputAnalysisEngine
# ---------------------------------------------------------------------------

class TestInputAnalysisEngine:
    def setup_method(self):
        self.engine = InputAnalysisEngine()

    def test_engine_name(self):
        assert InputAnalysisEngine.NAME == "input_analysis"

    def test_no_forms_returns_empty(self):
        art = _artifacts(forms=[])
        assert self.engine.analyze(art) == []

    def test_no_sensitive_inputs_no_findings(self):
        form = _form(inputs=[_inp("email"), _inp("name"), _inp("message", "textarea")])
        art = _artifacts(forms=[form])
        assert self.engine.analyze(art) == []

    def test_payment_card_fields_high(self):
        form = _form(
            inputs=[
                _inp("card_number"),
                _inp("cvv"),
                _inp("exp_month"),
                _inp("cardholder"),
            ],
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        payment = [f for f in findings if "payment" in f.title.lower()]
        assert payment
        assert all(f.severity == Severity.HIGH for f in payment)

    def test_ssn_field_high(self):
        form = _form(inputs=[_inp("ssn"), _inp("full_name")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        ssn = [f for f in findings if "ssn" in f.title.lower() or "government" in f.title.lower()]
        assert ssn
        assert all(f.severity == Severity.HIGH for f in ssn)

    def test_tax_id_field_detected(self):
        form = _form(inputs=[_inp("tax_id"), _inp("company_name")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert any("ssn" in f.title.lower() or "government" in f.title.lower() or "id" in f.title.lower() for f in findings)

    def test_admin_debug_param_medium(self):
        form = _form(inputs=[_inp("debug_mode", "hidden"), _inp("username")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        admin = [f for f in findings if "admin" in f.title.lower() or "debug" in f.title.lower()]
        assert admin
        assert all(f.severity == Severity.MEDIUM for f in admin)

    def test_redirect_param_medium(self):
        form = _form(inputs=[_inp("redirect_url", "hidden"), _inp("username")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        redirect = [f for f in findings if "redirect" in f.title.lower()]
        assert redirect
        assert all(f.severity == Severity.MEDIUM for f in redirect)

    def test_next_param_detected(self):
        form = _form(inputs=[_inp("next"), _inp("username")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert any("redirect" in f.title.lower() for f in findings)

    def test_token_session_field_medium(self):
        form = _form(inputs=[_inp("access_token", "hidden"), _inp("action")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        token = [f for f in findings if "token" in f.title.lower() or "session" in f.title.lower()]
        assert token
        assert all(f.severity == Severity.MEDIUM for f in token)

    def test_csrf_token_excluded_from_token_check(self):
        form = _form(
            inputs=[_inp("_csrf_token", "hidden"), _inp("email")],
            has_csrf=True,
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        # CSRF tokens are expected — should not trigger token/session exposure finding
        assert not any("token" in f.title.lower() and "session" in f.title.lower() for f in findings)

    def test_api_key_hidden_field_medium(self):
        form = _form(inputs=[_inp("api_key", "hidden"), _inp("query")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert any("secret" in f.title.lower() or "key" in f.title.lower() or "hidden" in f.title.lower() for f in findings)

    def test_file_upload_input_low(self):
        form = _form(inputs=[_inp("attachment", "file"), _inp("description")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        upload = [f for f in findings if "upload" in f.title.lower() or "file" in f.title.lower()]
        assert upload
        assert all(f.severity == Severity.LOW for f in upload)

    def test_findings_have_required_fields(self):
        form = _form(
            inputs=[
                _inp("card_number"),
                _inp("cvv"),
                _inp("redirect_url", "hidden"),
            ],
        )
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        assert findings
        for f in findings:
            assert f.title
            assert f.description
            assert f.severity
            assert f.category == FindingCategory.FORM
            assert f.evidence
            assert f.remediation
            assert f.framework.owasp_top10
            assert f.framework.cwe_ids
            assert f.scanner_engine == "input_analysis"

    def test_multiple_forms_all_analyzed(self):
        form1 = _form(inputs=[_inp("card_number"), _inp("cvv")])
        form2 = _form(
            action_url="https://example.com/profile",
            inputs=[_inp("ssn"), _inp("dob")],
        )
        art = _artifacts(forms=[form1, form2])
        findings = self.engine.analyze(art)
        titles = _all_titles(findings)
        assert any("payment" in t.lower() for t in titles)
        assert any("ssn" in t.lower() or "government" in t.lower() for t in titles)

    def test_evidence_source_engine(self):
        form = _form(inputs=[_inp("card_number")])
        art = _artifacts(forms=[form])
        findings = self.engine.analyze(art)
        for f in findings:
            for ev in f.evidence:
                assert ev.source_engine == "input_analysis"
