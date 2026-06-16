"""Tests unitarios de reglas de detección de phishing (Iris).

Las reglas son funciones puras: reciben un dict de cabeceras y devuelven
un ``RuleResult`` con score/verdict. No requieren BD ni red.
"""

import pytest

from src.modules.iris.rules.spf import check_spf
from src.modules.iris.rules.suspicious_tld import check_suspicious_tld
from src.modules.iris.rules.url_in_subject import check_url_in_subject

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- SPF

def test_spf_pass_is_positive():
    result = check_spf({"authentication-results": "mx.google.com; spf=pass smtp.mailfrom=a@b.com"})
    assert result.verdict == "pass"
    assert result.score > 0


def test_spf_fail_is_strongly_negative():
    result = check_spf({"authentication-results": "spf=fail smtp.mailfrom=evil@b.com"})
    assert result.verdict == "fail"
    assert result.score <= -20


def test_spf_softfail_is_mildly_negative():
    result = check_spf({"authentication-results": "spf=softfail"})
    assert result.verdict == "softfail"
    assert -10 < result.score < 0


def test_spf_missing_is_neutral():
    result = check_spf({})
    assert result.verdict == "neutral"
    assert result.score == 0


def test_spf_reads_received_spf_header():
    result = check_spf({"received-spf": "pass (google.com: domain of a@b.com)"})
    assert result.verdict == "pass"


# ------------------------------------------------------------------ Suspicious TLD

def test_suspicious_tld_flags_freenom_domain():
    result = check_suspicious_tld({"from": "Support <help@paypa1.tk>"})
    assert result.verdict == "fail"
    assert result.score < 0
    assert result.details["count"] >= 1


def test_legitimate_tld_passes():
    result = check_suspicious_tld({"from": "billing@example.com"})
    assert result.verdict == "pass"
    assert result.score >= 0


def test_suspicious_tld_score_scales_with_count():
    one = check_suspicious_tld({"from": "a@evil.tk"})
    two = check_suspicious_tld({"from": "a@evil.tk", "reply-to": "b@bad.xyz"})
    assert two.score < one.score


# ------------------------------------------------------------------ URL in subject

def test_url_in_subject_is_flagged():
    result = check_url_in_subject({"subject": "Verify now at http://evil.example.com/login"})
    assert result.verdict == "fail"
    assert result.score < 0


def test_clean_subject_passes():
    result = check_url_in_subject({"subject": "Tu factura de mayo"})
    assert result.verdict == "pass"
    assert result.score >= 0


def test_empty_subject_is_neutral():
    result = check_url_in_subject({"subject": ""})
    assert result.verdict == "neutral"
    assert result.score == 0
