"""Phase 6F: Vulnerability taxonomy retrieval self-tests.

LOCAL + READ-ONLY: no network, no DB, no scanner/WADE/provider-access changes.
Run with: .venv-api/Scripts/python -m pytest tests/ai -q
"""
from __future__ import annotations

import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _vt_norm(subdir: str, basename: str) -> str:
    return _read("corpus", "normalized", "vulnerability-taxonomy", subdir, basename)


def _vt_note(*parts: str) -> str:
    return _read("knowledge", "vulnerability-taxonomy", *parts)


def _manifest_records():
    rows = []
    for line in _read("corpus", "manifests", "manifest.jsonl").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


# ---- 22 Retrieval Self-Tests -----------------------------------------------

def test_vt_cve_vs_cwe():
    txt = _vt_note("cve-vs-cwe-vs-nvd.md")
    assert "cve" in txt.lower() and "cwe" in txt.lower()
    assert "specific" in txt.lower() or "product" in txt.lower()
    overview = _vt_note("vulnerability-taxonomy-overview.md")
    assert "weakness" in overview.lower() and "vulnerability" in overview.lower()


def test_vt_nvd_role_vs_cve():
    txt = _vt_note("cve-vs-cwe-vs-nvd.md")
    assert "nvd" in txt.lower() and "nist" in txt.lower()
    assert "cvss" in txt.lower()
    norm = _vt_norm("nvd", "pd-vt-nvd--cvss.md")
    assert "enriching" in norm.lower() or "enrich" in norm.lower() or "scores" in norm.lower()


def test_vt_how_webhound_uses_cvss():
    txt = _vt_note("webhound-cvss-usage-policy.md")
    assert "cvss" in txt.lower()
    assert "not" in txt.lower() and ("non-cve" in txt.lower() or "missing header" in txt.lower()
                                       or "misconfiguration" in txt.lower())


def test_vt_severity_vs_confidence():
    txt = _vt_note("severity-vs-confidence.md")
    assert "severity" in txt.lower() and "confidence" in txt.lower()
    assert "separate" in txt.lower() or "dimension" in txt.lower()


def test_vt_when_not_to_assign_cve():
    txt = _vt_note("when-not-to-assign-cve.md")
    assert "cve" in txt.lower()
    assert "missing" in txt.lower() or "misconfiguration" in txt.lower()
    assert "not" in txt.lower()


def test_vt_cwe_for_xss():
    txt = _vt_note("cwe", "cwe-79-xss.md")
    assert "79" in txt and ("xss" in txt.lower() or "cross-site scripting" in txt.lower())
    norm = _vt_norm("cwe", "pd-vt-cwe--79-xss.md")
    assert "reflected" in norm.lower() or "stored" in norm.lower()


def test_vt_cwe_for_sqli():
    txt = _vt_note("cwe", "cwe-89-sql-injection.md")
    assert "89" in txt and "sql" in txt.lower()
    norm = _vt_norm("cwe", "pd-vt-cwe--89-sqli.md")
    assert "parameterized" in norm.lower() or "prepared" in norm.lower()


def test_vt_cwe_for_csrf():
    txt = _vt_note("cwe", "cwe-352-csrf.md")
    assert "352" in txt and "csrf" in txt.lower()
    assert "samesite" in txt.lower() or "token" in txt.lower()


def test_vt_cwe_for_ssrf():
    txt = _vt_note("cwe", "cwe-918-ssrf.md")
    assert "918" in txt and "ssrf" in txt.lower()
    norm = _vt_norm("cwe", "pd-vt-cwe--918-ssrf.md")
    assert "allowlist" in norm.lower() or "whitelist" in norm.lower()


def test_vt_cwe_for_hardcoded_credentials():
    txt = _vt_note("cwe", "cwe-798-hardcoded-credentials.md")
    assert "798" in txt and ("hardcoded" in txt.lower() or "hard-coded" in txt.lower())
    norm = _vt_norm("cwe", "pd-vt-cwe--798-hardcoded-creds.md")
    assert "credential" in norm.lower() or "secret" in norm.lower()


def test_vt_cwe_for_insecure_cookie_flags():
    secure_txt = _vt_note("cwe", "cwe-614-cookie-without-secure.md")
    httponly_txt = _vt_note("cwe", "cwe-1004-cookie-without-httponly.md")
    assert "614" in secure_txt and "secure" in secure_txt.lower()
    assert "1004" in httponly_txt and "httponly" in httponly_txt.lower()


def test_vt_owasp_top10_injection():
    txt = _vt_note("owasp-top-10-mapping.md")
    assert "a03" in txt.lower() or "injection" in txt.lower()
    assert "xss" in txt.lower() or "sql" in txt.lower()


def test_vt_owasp_top10_security_misconfiguration():
    txt = _vt_note("owasp-top-10-mapping.md")
    assert "a05" in txt.lower() or "misconfiguration" in txt.lower()
    assert "csp" in txt.lower() or "hsts" in txt.lower() or "header" in txt.lower()


def test_vt_wade_uses_cisa_kev():
    txt = _vt_note("wade-taxonomy-relevance.md")
    assert "kev" in txt.lower()
    assert "escalat" in txt.lower() or "priority" in txt.lower()
    kev = _vt_note("cisa-kev-known-exploited-model.md")
    assert "actively exploited" in kev.lower() or "active" in kev.lower()


def test_vt_explain_missing_csp():
    txt = _vt_note("webhound-finding-taxonomy.md")
    assert "csp" in txt.lower() or "content-security-policy" in txt.lower()
    cwe = _vt_note("cwe", "cwe-1021-clickjacking-ui-redress.md")
    assert "frame" in cwe.lower() or "clickjack" in cwe.lower()


def test_vt_explain_exposed_env():
    txt = _vt_note("webhound-finding-taxonomy.md")
    assert ".env" in txt.lower() or "env file" in txt.lower()
    assert "cwe-200" in txt.lower() or "cwe-798" in txt.lower()


def test_vt_explain_third_party_script_risk():
    txt = _vt_note("webhound-finding-taxonomy.md")
    assert "third-party" in txt.lower() or "third party" in txt.lower()
    assert "sri" in txt.lower() or "script" in txt.lower()


def test_vt_avoid_overstating_threat_intel():
    txt = _vt_note("customer-safe-vulnerability-language.md")
    assert "confirm" in txt.lower() or "confirmed" in txt.lower()
    assert "prohibited" in txt.lower() or "prohibit" in txt.lower() or "must not" in txt.lower()
    svc = _vt_note("severity-vs-confidence.md")
    assert "confidence" in svc.lower() and "severity" in svc.lower()


def test_vt_provider_blocked_scans():
    txt = _vt_note("webhound-finding-taxonomy.md")
    assert "provider" in txt.lower() and "blocked" in txt.lower()
    assert "informational" in txt.lower()


def test_vt_nuclei_zap_external_findings():
    txt = _vt_note("webhound-finding-taxonomy.md")
    assert "nuclei" in txt.lower() or "zap" in txt.lower()
    assert "cve" in txt.lower()


def test_vt_customer_report_severity_language():
    txt = _vt_note("customer-safe-vulnerability-language.md")
    assert "critical" in txt.lower() and "high" in txt.lower() and "medium" in txt.lower()
    assert "confirmed" in txt.lower() or "suspected" in txt.lower()


def test_vt_wade_combines_taxonomy_with_evidence():
    txt = _vt_note("wade-taxonomy-relevance.md")
    assert "must not" in txt.lower()
    assert "cwe" in txt.lower() and "confidence" in txt.lower()


# ---- Structural validation tests -------------------------------------------

def test_vt_manifest_records_present():
    rows = _manifest_records()
    vt_official = [r for r in rows if r.get("source_type") == "official_taxonomy_doc"]
    assert len(vt_official) >= 22, f"Expected >=22 official_taxonomy_doc records, got {len(vt_official)}"
    cwe_rows = [r for r in vt_official if "cwe" in r.get("doc_id", "").lower()]
    assert len(cwe_rows) >= 15, f"Expected >=15 CWE records, got {len(cwe_rows)}"


def test_vt_chunks_file_present_and_non_empty():
    p = os.path.join(ROOT, "corpus", "normalized", "vulnerability-taxonomy", "vuln_taxonomy_chunks.jsonl")
    assert os.path.exists(p), "vuln_taxonomy_chunks.jsonl must exist after Phase 6F ingest"
    rows = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    assert len(rows) >= 30, f"Expected >=30 taxonomy chunks, got {len(rows)}"
    for c in rows[:5]:
        assert "chunk_id" in c and "doc_id" in c and "text" in c


def test_vt_all_cwe_normalized_files_exist():
    cwe_dir = os.path.join(ROOT, "corpus", "normalized", "vulnerability-taxonomy", "cwe")
    expected = [
        "pd-vt-cwe--79-xss.md", "pd-vt-cwe--89-sqli.md", "pd-vt-cwe--352-csrf.md",
        "pd-vt-cwe--22-path-traversal.md", "pd-vt-cwe--78-cmdi.md", "pd-vt-cwe--918-ssrf.md",
        "pd-vt-cwe--200-info-exposure.md", "pd-vt-cwe--287-improper-auth.md",
        "pd-vt-cwe--798-hardcoded-creds.md", "pd-vt-cwe--522-protected-creds.md",
        "pd-vt-cwe--611-xxe.md", "pd-vt-cwe--614-cookie-no-secure.md",
        "pd-vt-cwe--1004-cookie-no-httponly.md", "pd-vt-cwe--1021-clickjacking.md",
        "pd-vt-cwe--693-protection-failure.md",
    ]
    missing = [f for f in expected if not os.path.exists(os.path.join(cwe_dir, f))]
    assert missing == [], f"Missing CWE normalized files: {missing}"


def test_vt_schema_has_official_taxonomy_doc():
    schema_path = os.path.join(ROOT, "corpus", "manifests", "manifest.schema.json")
    import json as _json
    schema = _json.load(open(schema_path, encoding="utf-8"))
    source_types = schema["properties"]["source_type"]["enum"]
    assert "official_taxonomy_doc" in source_types, \
        f"official_taxonomy_doc missing from schema enum: {source_types}"


if __name__ == "__main__":
    failures = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  [ ok ] {name}")
            except Exception as e:  # noqa: BLE001
                if e.__class__.__name__ in ("Skipped", "OutcomeException"):
                    print(f"  [skip] {name}")
                else:
                    failures.append(name)
                    print(f"  [FAIL] {name}: {e}")
    raise SystemExit(1 if failures else 0)
