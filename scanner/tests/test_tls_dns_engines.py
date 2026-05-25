# WebHound — scanner/tests/test_tls_dns_engines.py
# Tests for Phase 4: TLS and DNS scanner engines.
#
# All tests use constructed data objects — no live network, no DNS, no TLS connections.

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webhound.engines.tls_dns.dns_checker import DnsCheckerEngine, DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo, TlsCheckerEngine
from webhound.models.evidence import EvidenceType
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity

_ENGINE = TlsCheckerEngine()
_DNS_ENGINE = DnsCheckerEngine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _future(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _past(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def _valid_cert(domain: str = "example.com") -> TlsCertInfo:
    """A fully compliant TLS certificate — should produce no findings."""
    return TlsCertInfo(
        domain=domain,
        subject_cn=domain,
        sans=[domain, f"www.{domain}"],
        issuer_o="Let's Encrypt",
        issuer_cn="R3",
        not_before=_past(30),
        not_after=_future(90),
        protocol_version="TLSv1.3",
        is_expired=False,
        is_not_yet_valid=False,
        is_self_signed=False,
        hostname_mismatch=False,
    )


def _clean_dns(domain: str = "example.com") -> DnsRecords:
    """Fully configured DNS records — should produce no findings."""
    return DnsRecords(
        domain=domain,
        a=["93.184.216.34"],
        aaaa=["2606:2800:220:1:248:1893:25c8:1946"],
        mx=["10 mail.example.com."],
        txt=["v=spf1 include:_spf.example.com -all"],
        ns=["ns1.example.com.", "ns2.example.com."],
        dmarc_txt=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        # The engine also checks DKIM/CAA/DNSSEC/MTA-STS — a "fully configured"
        # domain has these too, otherwise those checks (correctly) fire.
        caa=['0 issue "letsencrypt.org"'],
        dnskey=["257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d"],
        mta_sts_txt=["v=STSv1; id=20240101000000Z"],
        dkim_selectors_seen=["google"],
    )


# ===========================================================================
# TestTlsCertInfo — dataclass properties
# ===========================================================================

class TestTlsCertInfo:
    def test_days_until_expiry_positive(self):
        cert = TlsCertInfo(domain="example.com", not_after=_future(60))
        days = cert.days_until_expiry
        assert days is not None
        assert 58 <= days <= 61

    def test_days_until_expiry_negative_when_expired(self):
        cert = TlsCertInfo(domain="example.com", not_after=_past(5))
        days = cert.days_until_expiry
        assert days is not None
        assert days < 0

    def test_days_until_expiry_none_when_no_date(self):
        cert = TlsCertInfo(domain="example.com")
        assert cert.days_until_expiry is None

    def test_days_until_expiry_zero_today(self):
        cert = TlsCertInfo(domain="example.com", not_after=_future(0))
        days = cert.days_until_expiry
        assert days is not None
        assert -1 <= days <= 1


# ===========================================================================
# TestTlsCheckerEngine — certificate analysis
# ===========================================================================

class TestTlsCheckerEngine:

    # --- Connection failure ---

    def test_connection_failed_produces_finding(self):
        cert = TlsCertInfo(domain="unreachable.example.com", connection_failed=True, error="Connection refused")
        findings = _ENGINE.analyze(cert)
        assert any("couldn't reach" in f.title.lower() for f in findings)

    def test_connection_failed_is_medium(self):
        cert = TlsCertInfo(domain="unreachable.example.com", connection_failed=True, error="timed out")
        findings = _ENGINE.analyze(cert)
        failed = [f for f in findings if "couldn't reach" in f.title.lower()]
        assert failed[0].severity == Severity.MEDIUM

    def test_no_connection_error_no_failure_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("couldn't reach" in f.title.lower() for f in findings)

    # --- Certificate expiry ---

    def test_expired_cert_is_critical(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired
        assert expired[0].severity == Severity.CRITICAL

    def test_expired_cert_category_is_tls(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired[0].category == FindingCategory.TLS

    def test_not_expired_cert_no_expiry_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("expired" in f.title.lower() for f in findings)

    def test_expired_cert_includes_date_when_provided(self):
        expiry = _past(3)
        cert = TlsCertInfo(domain="example.com", is_expired=True, not_after=expiry)
        findings = _ENGINE.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert str(expiry.date()) in expired[0].description

    # --- Not yet valid ---

    def test_not_yet_valid_cert_is_high(self):
        cert = TlsCertInfo(
            domain="example.com",
            is_not_yet_valid=True,
            not_before=_future(5),
        )
        findings = _ENGINE.analyze(cert)
        nv = [f for f in findings if "start date is in the future" in f.title.lower()]
        assert nv
        assert nv[0].severity == Severity.HIGH

    def test_valid_cert_no_not_yet_valid_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("start date is in the future" in f.title.lower() for f in findings)

    # --- Expiry warnings ---

    def test_expiring_in_25_days_is_medium(self):
        cert = TlsCertInfo(
            domain="example.com",
            not_after=_future(25),
            is_expired=False,
        )
        findings = _ENGINE.analyze(cert)
        warn = [f for f in findings if "expires in" in f.title.lower()]
        assert warn
        assert warn[0].severity == Severity.MEDIUM

    def test_expiring_in_10_days_is_high(self):
        cert = TlsCertInfo(
            domain="example.com",
            not_after=_future(10),
            is_expired=False,
        )
        findings = _ENGINE.analyze(cert)
        warn = [f for f in findings if "expires in" in f.title.lower()]
        assert warn
        assert warn[0].severity == Severity.HIGH

    def test_expiring_in_3_days_is_critical(self):
        cert = TlsCertInfo(
            domain="example.com",
            not_after=_future(3),
            is_expired=False,
        )
        findings = _ENGINE.analyze(cert)
        warn = [f for f in findings if "expires in" in f.title.lower()]
        assert warn
        assert warn[0].severity == Severity.CRITICAL

    def test_expiring_in_365_days_no_warning(self):
        cert = TlsCertInfo(
            domain="example.com",
            not_after=_future(365),
            is_expired=False,
        )
        findings = _ENGINE.analyze(cert)
        assert not any("expires in" in f.title.lower() for f in findings)

    def test_already_expired_no_expiry_warning(self):
        # Expired certs use _check_expired, not _check_expiry_warning
        cert = TlsCertInfo(domain="example.com", is_expired=True, not_after=_past(2))
        findings = _ENGINE.analyze(cert)
        assert not any("expires in" in f.title.lower() for f in findings)

    # --- Self-signed ---

    def test_self_signed_is_high(self):
        cert = TlsCertInfo(domain="example.com", is_self_signed=True)
        findings = _ENGINE.analyze(cert)
        ss = [f for f in findings if "isn't signed by a trusted authority" in f.title.lower()]
        assert ss
        assert ss[0].severity == Severity.HIGH

    def test_ca_issued_cert_no_self_signed_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("isn't signed by a trusted authority" in f.title.lower() for f in findings)

    # --- Hostname mismatch ---

    def test_hostname_mismatch_is_high(self):
        cert = TlsCertInfo(domain="example.com", hostname_mismatch=True)
        findings = _ENGINE.analyze(cert)
        mm = [f for f in findings if "isn't valid for this domain" in f.title.lower()]
        assert mm
        assert mm[0].severity == Severity.HIGH

    def test_matching_hostname_no_mismatch_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("isn't valid for this domain" in f.title.lower() for f in findings)

    # --- Weak protocol ---

    def test_tls_v1_0_is_high(self):
        cert = TlsCertInfo(domain="example.com", protocol_version="TLSv1")
        findings = _ENGINE.analyze(cert)
        wp = [f for f in findings if "obsolete tls version" in f.title.lower()]
        assert wp
        assert wp[0].severity == Severity.HIGH

    def test_tls_v1_1_is_high(self):
        cert = TlsCertInfo(domain="example.com", protocol_version="TLSv1.1")
        findings = _ENGINE.analyze(cert)
        wp = [f for f in findings if "obsolete tls version" in f.title.lower()]
        assert wp
        assert wp[0].severity == Severity.HIGH

    def test_tls_v1_2_no_weak_protocol_finding(self):
        cert = TlsCertInfo(domain="example.com", protocol_version="TLSv1.2")
        findings = _ENGINE.analyze(cert)
        assert not any("obsolete tls version" in f.title.lower() for f in findings)

    def test_tls_v1_3_no_weak_protocol_finding(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert not any("obsolete tls version" in f.title.lower() for f in findings)

    def test_no_protocol_version_no_weak_finding(self):
        cert = TlsCertInfo(domain="example.com")
        findings = _ENGINE.analyze(cert)
        assert not any("obsolete tls version" in f.title.lower() for f in findings)

    # --- HTTP → HTTPS redirect ---

    def test_http_no_redirect_to_https_is_medium(self):
        cert = TlsCertInfo(domain="example.com")
        findings = _ENGINE.analyze(
            cert,
            response_url="http://example.com/page",
            redirect_chain=["http://example.com/page"],
        )
        redir = [f for f in findings if "without redirecting to https" in f.title.lower()]
        assert redir
        assert redir[0].severity == Severity.MEDIUM

    def test_http_redirects_to_https_no_finding(self):
        cert = TlsCertInfo(domain="example.com")
        findings = _ENGINE.analyze(
            cert,
            response_url="https://example.com/page",
            redirect_chain=["http://example.com/page"],
        )
        assert not any("without redirecting to https" in f.title.lower() for f in findings)

    def test_no_redirect_chain_no_redirect_finding(self):
        cert = TlsCertInfo(domain="example.com")
        findings = _ENGINE.analyze(cert, response_url=None, redirect_chain=None)
        assert not any("without redirecting to https" in f.title.lower() for f in findings)

    # --- Fully valid cert produces no findings ---

    def test_valid_cert_produces_no_findings(self):
        cert = _valid_cert()
        findings = _ENGINE.analyze(cert)
        assert findings == []

    # --- Evidence and metadata ---

    def test_finding_has_tls_evidence(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        f = findings[0]
        assert f.evidence
        assert f.evidence[0].evidence_type == EvidenceType.TLS_CERTIFICATE

    def test_finding_has_owasp_alignment(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        f = findings[0]
        assert f.framework.owasp_top10

    def test_finding_has_remediation(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        assert findings[0].remediation

    def test_engine_name_is_set(self):
        cert = TlsCertInfo(domain="example.com", is_expired=True)
        findings = _ENGINE.analyze(cert)
        assert findings[0].scanner_engine == "tls_checker"


# ===========================================================================
# TestDnsRecords — dataclass properties
# ===========================================================================

class TestDnsRecords:
    def test_spf_records_filters_txt(self):
        records = DnsRecords(
            domain="example.com",
            txt=["v=spf1 include:_spf.example.com -all", "google-site-verification=abc"],
        )
        assert records.spf_records == ["v=spf1 include:_spf.example.com -all"]

    def test_spf_records_empty_when_none(self):
        records = DnsRecords(domain="example.com", txt=["some-other-txt"])
        assert records.spf_records == []

    def test_has_dmarc_true(self):
        records = DnsRecords(
            domain="example.com",
            dmarc_txt=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        )
        assert records.has_dmarc is True

    def test_has_dmarc_false_when_empty(self):
        records = DnsRecords(domain="example.com")
        assert records.has_dmarc is False

    def test_has_a_or_aaaa_true_with_a(self):
        records = DnsRecords(domain="example.com", a=["93.184.216.34"])
        assert records.has_a_or_aaaa is True

    def test_has_a_or_aaaa_true_with_aaaa(self):
        records = DnsRecords(domain="example.com", aaaa=["::1"])
        assert records.has_a_or_aaaa is True

    def test_has_a_or_aaaa_false_when_empty(self):
        records = DnsRecords(domain="example.com")
        assert records.has_a_or_aaaa is False

    def test_spf_strips_quotes(self):
        records = DnsRecords(
            domain="example.com",
            txt=['"v=spf1 -all"'],
        )
        assert records.spf_records == ["v=spf1 -all"]


# ===========================================================================
# TestDnsCheckerEngine — DNS record analysis
# ===========================================================================

class TestDnsCheckerEngine:

    # --- Resolution failure ---

    def test_resolution_failure_is_high(self):
        records = DnsRecords(
            domain="nonexistent.invalid",
            resolution_error="NXDOMAIN",
        )
        findings = _DNS_ENGINE.analyze(records)
        failed = [f for f in findings if "doesn't resolve" in f.title.lower()]
        assert failed
        assert failed[0].severity == Severity.HIGH

    def test_resolution_failure_category_is_dns(self):
        records = DnsRecords(domain="x.invalid", resolution_error="timeout")
        findings = _DNS_ENGINE.analyze(records)
        assert findings[0].category == FindingCategory.DNS

    def test_resolved_domain_no_failure_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("doesn't resolve" in f.title.lower() for f in findings)

    # --- SPF missing ---

    def test_missing_spf_is_medium(self):
        # MX present → the domain sends email → missing SPF is MEDIUM
        # (the engine downgrades to LOW for non-mail domains).
        records = DnsRecords(domain="example.com", a=["1.2.3.4"], mx=["10 mail.example.com."])
        findings = _DNS_ENGINE.analyze(records)
        spf = [f for f in findings if "no spf record" in f.title.lower()]
        assert spf
        assert spf[0].severity == Severity.MEDIUM

    def test_spf_present_no_missing_finding(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 -all"],
            dmarc_txt=["v=DMARC1; p=none"],
        )
        findings = _DNS_ENGINE.analyze(records)
        assert not any("no spf record" in f.title.lower() for f in findings)

    def test_resolution_failure_suppresses_spf_check(self):
        records = DnsRecords(domain="example.com", resolution_error="NXDOMAIN")
        findings = _DNS_ENGINE.analyze(records)
        assert not any("spf" in f.title.lower() for f in findings)

    # --- SPF risky patterns ---

    def test_spf_plus_all_is_high(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 include:_spf.example.com +all"],
        )
        findings = _DNS_ENGINE.analyze(records)
        risky = [f for f in findings if "allows anyone to send mail" in f.title.lower()]
        assert risky
        assert risky[0].severity == Severity.HIGH

    def test_spf_neutral_all_is_medium(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 ?all"],
        )
        findings = _DNS_ENGINE.analyze(records)
        neutral = [f for f in findings if "doesn't actually reject" in f.title.lower()]
        assert neutral
        assert neutral[0].severity == Severity.MEDIUM

    def test_spf_hard_fail_no_risky_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("allows anyone to send mail" in f.title.lower() or "doesn't actually reject" in f.title.lower() for f in findings)

    def test_spf_soft_fail_no_risky_finding(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 include:_spf.example.com ~all"],
            dmarc_txt=["v=DMARC1; p=none"],
        )
        findings = _DNS_ENGINE.analyze(records)
        assert not any("allows anyone to send mail" in f.title.lower() or "doesn't actually reject" in f.title.lower() for f in findings)

    # --- DMARC missing ---

    def test_missing_dmarc_is_medium(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 -all"],
        )
        findings = _DNS_ENGINE.analyze(records)
        dmarc = [f for f in findings if "no dmarc record" in f.title.lower()]
        assert dmarc
        assert dmarc[0].severity == Severity.MEDIUM

    def test_dmarc_present_no_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("no dmarc record" in f.title.lower() for f in findings)

    def test_dmarc_case_insensitive_detection(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 -all"],
            dmarc_txt=["v=dmarc1; p=none"],  # lowercase v=dmarc1
        )
        findings = _DNS_ENGINE.analyze(records)
        assert not any("no dmarc record" in f.title.lower() for f in findings)

    def test_resolution_failure_suppresses_dmarc_check(self):
        records = DnsRecords(domain="example.com", resolution_error="NXDOMAIN")
        findings = _DNS_ENGINE.analyze(records)
        assert not any("dmarc" in f.title.lower() for f in findings)

    # --- MX records ---

    def test_mx_missing_with_spf_is_low(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 -all"],
            dmarc_txt=["v=DMARC1; p=reject"],
        )
        findings = _DNS_ENGINE.analyze(records)
        mx = [f for f in findings if "no mx records" in f.title.lower()]
        assert mx
        assert mx[0].severity == Severity.LOW

    def test_mx_present_no_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("no mx records" in f.title.lower() for f in findings)

    def test_mx_missing_without_spf_no_finding(self):
        records = DnsRecords(domain="example.com", a=["1.2.3.4"])
        findings = _DNS_ENGINE.analyze(records)
        assert not any("no mx records" in f.title.lower() for f in findings)

    # --- NS redundancy ---

    def test_single_ns_is_low(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            txt=["v=spf1 -all"],
            ns=["ns1.example.com."],
            dmarc_txt=["v=DMARC1; p=none"],
        )
        findings = _DNS_ENGINE.analyze(records)
        ns = [f for f in findings if "single nameserver" in f.title.lower()]
        assert ns
        assert ns[0].severity == Severity.LOW

    def test_two_ns_no_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("single nameserver" in f.title.lower() for f in findings)

    def test_no_ns_records_no_false_positive(self):
        records = DnsRecords(domain="example.com", a=["1.2.3.4"])
        findings = _DNS_ENGINE.analyze(records)
        assert not any("single nameserver" in f.title.lower() for f in findings)

    # --- CNAME chain ---

    def test_long_cname_chain_is_info(self):
        # The engine flags chains of 3+ hops, at INFO severity.
        records = DnsRecords(
            domain="example.com",
            cname=["alias1.example.com.", "alias2.example.com.", "alias3.example.com."],
        )
        findings = _DNS_ENGINE.analyze(records)
        cname = [f for f in findings if "goes through many redirects" in f.title.lower()]
        assert cname
        assert cname[0].severity == Severity.INFO

    def test_single_cname_no_chain_finding(self):
        records = DnsRecords(
            domain="example.com",
            a=["1.2.3.4"],
            cname=["alias.example.com."],
        )
        findings = _DNS_ENGINE.analyze(records)
        assert not any("goes through many redirects" in f.title.lower() for f in findings)

    def test_no_cname_no_chain_finding(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert not any("goes through many redirects" in f.title.lower() for f in findings)

    # --- Evidence, metadata, framework ---

    def test_finding_has_dns_evidence(self):
        records = DnsRecords(domain="example.com", resolution_error="NXDOMAIN")
        findings = _DNS_ENGINE.analyze(records)
        assert findings[0].evidence
        assert findings[0].evidence[0].evidence_type == EvidenceType.DNS_RECORD

    def test_finding_has_owasp_alignment(self):
        records = DnsRecords(domain="example.com", a=["1.2.3.4"])
        findings = _DNS_ENGINE.analyze(records)
        spf = [f for f in findings if "spf" in f.title.lower()]
        assert spf[0].framework.owasp_top10

    def test_finding_has_remediation(self):
        records = DnsRecords(domain="example.com", a=["1.2.3.4"])
        findings = _DNS_ENGINE.analyze(records)
        assert all(f.remediation for f in findings)

    def test_engine_name_is_set(self):
        records = DnsRecords(domain="example.com", a=["1.2.3.4"])
        findings = _DNS_ENGINE.analyze(records)
        for f in findings:
            assert f.scanner_engine == "dns_checker"

    # --- Fully clean records produce no findings ---

    def test_fully_clean_records_no_findings(self):
        records = _clean_dns()
        findings = _DNS_ENGINE.analyze(records)
        assert findings == []
