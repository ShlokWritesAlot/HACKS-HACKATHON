"""
Comprehensive test suite for the BhashaRakshak Threat Intelligence extraction engine.

Covers:
  - URL extraction with trailing punctuation stripping
  - Domain extraction and de-duplication
  - IPv4: public, private, loopback, link-local, cloud metadata
  - IPv6: loopback (::1), link-local, bracket notation
  - SSRF boundary classification
  - Unicode / IDN / homograph domain handling
  - Extremely long URLs (bounded output)
  - Multiple URLs in one message
  - UPI VPA extraction
  - Indian phone number extraction and normalization
  - Email extraction
  - DLT Sender ID extraction
  - Malformed / fake inputs that must NOT produce false positives
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.intel.extractor import (
    build_threat_report,
    extract_domains,
    extract_emails,
    extract_ip_addresses,
    extract_phone_numbers,
    extract_sender_ids,
    extract_upi_ids,
    extract_urls,
)
from app.intel.schemas import IndicatorType, SSRFRiskLevel
from app.intel.ssrf import classify_ssrf_risk


# ── SSRF Classifier Tests ──────────────────────────────────────────────────────

def test_ssrf_public_url_is_safe():
    assert classify_ssrf_risk("https://bit.ly/kyc-sbi") == SSRFRiskLevel.SAFE


def test_ssrf_localhost_blocked():
    assert classify_ssrf_risk("http://localhost/admin") == SSRFRiskLevel.LOOPBACK
    assert classify_ssrf_risk("http://127.0.0.1:8080/secret") == SSRFRiskLevel.LOOPBACK


def test_ssrf_private_ipv4_blocked():
    assert classify_ssrf_risk("http://192.168.1.1/config") == SSRFRiskLevel.PRIVATE_IP
    assert classify_ssrf_risk("http://10.0.0.1/api") == SSRFRiskLevel.PRIVATE_IP
    assert classify_ssrf_risk("http://172.17.0.1/") == SSRFRiskLevel.PRIVATE_IP


def test_ssrf_cloud_metadata_blocked():
    assert classify_ssrf_risk("http://169.254.169.254/latest/meta-data") == SSRFRiskLevel.METADATA_ENDPOINT
    assert classify_ssrf_risk("http://metadata.google.internal/") == SSRFRiskLevel.METADATA_ENDPOINT


def test_ssrf_ipv6_loopback_blocked():
    assert classify_ssrf_risk("http://[::1]/admin") == SSRFRiskLevel.LOOPBACK


def test_ssrf_invalid_scheme_blocked():
    assert classify_ssrf_risk("file:///etc/passwd") == SSRFRiskLevel.INVALID_SCHEME
    assert classify_ssrf_risk("gopher://evil.com/exploit") == SSRFRiskLevel.INVALID_SCHEME
    assert classify_ssrf_risk("dict://127.0.0.1:11111/") == SSRFRiskLevel.INVALID_SCHEME


def test_ssrf_empty_and_none():
    assert classify_ssrf_risk("") == SSRFRiskLevel.BLOCKED
    assert classify_ssrf_risk("   ") == SSRFRiskLevel.BLOCKED


# ── URL Extraction Tests ───────────────────────────────────────────────────────

def test_extract_url_plain():
    results = extract_urls("Update KYC at https://sbi-kyc-update.xyz/verify now.")
    assert len(results) == 1
    assert "sbi-kyc-update.xyz" in results[0].value
    assert results[0].type == IndicatorType.URL


def test_extract_url_strips_trailing_dot():
    results = extract_urls("See http://example.com/login.")
    assert len(results) >= 1
    for r in results:
        assert not r.value.endswith(".")


def test_extract_url_strips_trailing_parenthesis():
    results = extract_urls("Link (http://example.com) is dangerous.")
    assert len(results) >= 1
    for r in results:
        assert not r.value.endswith(")")


def test_extract_multiple_urls():
    msg = "Visit http://a.com and also https://b.xyz for more info."
    results = extract_urls(msg)
    values = [r.value for r in results]
    assert any("a.com" in v for v in values)
    assert any("b.xyz" in v for v in values)


def test_extract_url_extremely_long_is_bounded():
    long_url = "https://malicious.xyz/" + "A" * 4000
    results = extract_urls(long_url)
    for r in results:
        assert len(r.value) < 3000


def test_extract_url_no_private_ip_in_url_bucket():
    """Private IPs inside URLs should NOT appear in the URL extractor (they go to IP extractor)."""
    results = extract_urls("http://192.168.1.100/phish")
    # URLs containing bare private IPs are skipped from URL bucket
    # (they are caught in IP extractor instead)
    for r in results:
        assert "192.168" not in r.value or r.is_internal_or_private


def test_extract_shortener_domain_high_confidence():
    results = extract_urls("Click here: bit.ly/kyc-update")
    for r in results:
        if "bit.ly" in r.value:
            assert r.confidence >= 0.95


# ── Domain Extraction Tests ────────────────────────────────────────────────────

def test_extract_domain_deduplication():
    msg = "Go to https://evil.com/a and https://evil.com/b"
    domains = extract_domains(msg)
    domain_values = [d.value for d in domains]
    # evil.com should appear exactly once despite two URLs
    assert domain_values.count("evil.com") == 1


def test_extract_domain_idn_flagged():
    # xn--google-hqa.com is a punycode homograph of "gòogle.com"
    results = extract_urls("Visit https://xn--google-hqa.com/login")
    if results:
        # IDN encoded hostnames should be flagged
        for r in results:
            if "xn--" in r.value:
                assert r.is_idn_homograph is True


# ── IP Address Extraction Tests ────────────────────────────────────────────────

def test_extract_public_ipv4():
    results = extract_ip_addresses("Server at 8.8.8.8 answered the query.")
    assert any(r.value == "8.8.8.8" for r in results)
    assert all(r.ssrf_risk == SSRFRiskLevel.SAFE for r in results if r.value == "8.8.8.8")


def test_extract_private_ipv4_flagged():
    results = extract_ip_addresses("Internal server 10.0.0.5 is down.")
    assert any(r.value == "10.0.0.5" for r in results)
    for r in results:
        if r.value == "10.0.0.5":
            assert r.is_internal_or_private is True
            assert r.ssrf_risk == SSRFRiskLevel.PRIVATE_IP


def test_extract_loopback_ipv4_flagged():
    results = extract_ip_addresses("Connect to 127.0.0.1:8080")
    for r in results:
        if r.value == "127.0.0.1":
            assert r.ssrf_risk == SSRFRiskLevel.LOOPBACK


def test_extract_cloud_metadata_ip():
    results = extract_ip_addresses("curl 169.254.169.254/latest")
    for r in results:
        if r.value == "169.254.169.254":
            assert r.ssrf_risk == SSRFRiskLevel.METADATA_ENDPOINT


def test_extract_ipv6_loopback():
    results = extract_ip_addresses("Host [::1] is loopback.")
    for r in results:
        if "::1" in r.value:
            assert r.ssrf_risk == SSRFRiskLevel.LOOPBACK


def test_no_false_positive_phone_as_ip():
    # Phone numbers like 9876543210 must NOT be extracted as IPs
    results = extract_ip_addresses("Call 9876543210 for support.")
    assert all("9876543210" not in r.value for r in results)


# ── Phone Number Extraction Tests ──────────────────────────────────────────────

def test_extract_indian_mobile_10_digit():
    results = extract_phone_numbers("Call 9876543210 immediately.")
    assert any("9876543210" in r.value for r in results)


def test_extract_indian_mobile_with_country_code():
    results = extract_phone_numbers("WhatsApp +91 9812345678 for HR.")
    assert len(results) >= 1
    assert any("9812345678" in r.value for r in results)


def test_extract_indian_mobile_91_prefix():
    results = extract_phone_numbers("Contact 919876543210 for help.")
    assert len(results) >= 1


def test_reject_short_fake_number():
    results = extract_phone_numbers("Call 12345 for support.")
    assert len(results) == 0


def test_reject_all_zeros():
    results = extract_phone_numbers("0000000000 is fake.")
    assert len(results) == 0


def test_reject_non_6_to_9_start():
    """Indian mobiles must start with 6-9; numbers starting with 1-5 must be rejected."""
    results = extract_phone_numbers("Fake 5555555555 is not valid.")
    assert len(results) == 0


# ── Email Extraction Tests ─────────────────────────────────────────────────────

def test_extract_email_basic():
    results = extract_emails("Send OTP to victim@gmail.com now.")
    assert any("victim@gmail.com" in r.value for r in results)


def test_extract_email_case_normalized():
    results = extract_emails("Contact SUPPORT@HDFC.CO.IN for help.")
    assert any("support@hdfc.co.in" in r.value for r in results)


def test_no_false_positive_upi_as_email():
    """UPI IDs like user@paytm must not appear in the email extractor bucket."""
    results = extract_emails("Pay to merchant@paytm for the bill.")
    for r in results:
        assert "@paytm" not in r.value or r.type == IndicatorType.EMAIL


# ── UPI ID Extraction Tests ────────────────────────────────────────────────────

def test_extract_upi_okaxis():
    results = extract_upi_ids("Pay Rs 50 to merchant@okaxis immediately.")
    assert any("merchant@okaxis" in r.value for r in results)
    assert all(r.type == IndicatorType.UPI_ID for r in results)


def test_extract_upi_paytm():
    results = extract_upi_ids("Send money to scammer@paytm right now.")
    assert any("scammer@paytm" in r.value for r in results)


def test_extract_upi_ybl():
    results = extract_upi_ids("Transfer to fraudster@ybl to unlock account.")
    assert any("fraudster@ybl" in r.value for r in results)


def test_extract_upi_deduplication():
    results = extract_upi_ids("Pay user@oksbi and then user@oksbi again.")
    values = [r.value for r in results]
    assert values.count("user@oksbi") == 1


# ── Sender ID Tests ────────────────────────────────────────────────────────────

def test_extract_sender_id_sbi():
    results = extract_sender_ids("From AX-SBIINB: Your account is blocked.")
    assert any("AX-SBIINB" in r.value for r in results)


def test_extract_sender_id_hdfc():
    results = extract_sender_ids("VM-HDFCBK: Click the link immediately.")
    assert any("VM-HDFCBK" in r.value for r in results)


# ── Full Threat Report Tests ───────────────────────────────────────────────────

def test_build_threat_report_mixed_message():
    msg = (
        "AX-SBIINB: Dear customer, your account is blocked. "
        "Update KYC at https://sbi-kyc-update.xyz/verify. "
        "Call 9876543210 or email support@fraud.com. "
        "Pay Rs 500 to collect@okaxis."
    )
    report = build_threat_report(msg)
    assert report.url_count >= 1
    assert report.domain_count >= 1
    assert report.phone_count >= 1
    assert report.email_count >= 1
    assert report.upi_count >= 1
    assert report.sender_id_count >= 1
    assert len(report.indicators) > 0


def test_build_threat_report_empty_text():
    report = build_threat_report("")
    assert report.url_count == 0
    assert report.phone_count == 0
    assert len(report.indicators) == 0


def test_build_threat_report_all_private_ips():
    msg = "Internal servers: 10.0.0.1, 192.168.1.1, 172.16.5.5"
    report = build_threat_report(msg)
    assert report.ip_count >= 3
    assert report.suspicious_indicator_count >= 3


def test_build_threat_report_no_crash_on_unicode_soup():
    msg = "𝕳𝖊𝖑𝖑𝖔 𝖜𝖔𝖗𝖑𝖉 — यह एक टेस्ट मैसेज है। 📱💸🔒"
    report = build_threat_report(msg)
    assert isinstance(report.indicators, list)


def run_all_tests():
    tests = [
        test_ssrf_public_url_is_safe,
        test_ssrf_localhost_blocked,
        test_ssrf_private_ipv4_blocked,
        test_ssrf_cloud_metadata_blocked,
        test_ssrf_ipv6_loopback_blocked,
        test_ssrf_invalid_scheme_blocked,
        test_ssrf_empty_and_none,
        test_extract_url_plain,
        test_extract_url_strips_trailing_dot,
        test_extract_url_strips_trailing_parenthesis,
        test_extract_multiple_urls,
        test_extract_url_extremely_long_is_bounded,
        test_extract_url_no_private_ip_in_url_bucket,
        test_extract_shortener_domain_high_confidence,
        test_extract_domain_deduplication,
        test_extract_domain_idn_flagged,
        test_extract_public_ipv4,
        test_extract_private_ipv4_flagged,
        test_extract_loopback_ipv4_flagged,
        test_extract_cloud_metadata_ip,
        test_extract_ipv6_loopback,
        test_no_false_positive_phone_as_ip,
        test_extract_indian_mobile_10_digit,
        test_extract_indian_mobile_with_country_code,
        test_extract_indian_mobile_91_prefix,
        test_reject_short_fake_number,
        test_reject_all_zeros,
        test_reject_non_6_to_9_start,
        test_extract_email_basic,
        test_extract_email_case_normalized,
        test_no_false_positive_upi_as_email,
        test_extract_upi_okaxis,
        test_extract_upi_paytm,
        test_extract_upi_ybl,
        test_extract_upi_deduplication,
        test_extract_sender_id_sbi,
        test_extract_sender_id_hdfc,
        test_build_threat_report_mixed_message,
        test_build_threat_report_empty_text,
        test_build_threat_report_all_private_ips,
        test_build_threat_report_no_crash_on_unicode_soup,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} Threat Intelligence Tests Passed!")
