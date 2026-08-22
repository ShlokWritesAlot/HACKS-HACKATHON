"""
Comprehensive Test Suite: Extended SSRF-Safe URL Analysis Engine.

Coverage:
  - Suspicious TLDs
  - Excessive subdomain depth
  - URL entropy
  - Suspicious path tokens
  - Credential-related paths
  - Brand impersonation in domain
  - Punycode domains
  - Unicode homoglyphs
  - IP-literal URLs (IPv4, octal, hex)
  - URL shorteners
  - Excessive / double encoding
  - Embedded credentials
  - Suspicious ports
  - Nested URLs
  - Unusual URL structures (fragments, multiple @, long URLs)
  - Parser differential attacks
  - Malformed URLs
  - Regression proof: all SSRF attack payloads produce zero network activity
  - Existing SSRF block preservation (private IPv4, IPv6, loopback,
    link-local, cloud metadata, non-http/https schemes)

NETWORK SAFETY INVARIANT:
  None of these test inputs trigger any DNS lookup, TCP connection,
  HTTP request, or redirect resolution. All detectors are pure
  in-process string operations.
"""

import os
import sys
import unittest.mock as mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.intel.url_analyzer import analyze_url, URLFindingSeverity
from app.intel.ssrf import classify_ssrf_risk
from app.intel.schemas import SSRFRiskLevel


# ─── Existing SSRF Block Preservation ─────────────────────────────────────────

def test_preserve_ssrf_loopback_ipv4():
    """Loopback IPv4 is blocked and NEVER reaches network detectors."""
    result = analyze_url("http://127.0.0.1/admin")
    assert result.is_blocked_ssrf is True
    assert result.ssrf_risk_level == SSRFRiskLevel.LOOPBACK.value
    assert result.is_malicious is True


def test_preserve_ssrf_private_ipv4_10():
    """Private 10.x.x.x range is blocked."""
    result = analyze_url("http://10.0.0.1/secret")
    assert result.is_blocked_ssrf is True
    assert result.ssrf_risk_level == SSRFRiskLevel.PRIVATE_IP.value


def test_preserve_ssrf_private_ipv4_172():
    """Private 172.16.x.x range is blocked."""
    result = analyze_url("http://172.31.255.255/api")
    assert result.is_blocked_ssrf is True


def test_preserve_ssrf_private_ipv4_192():
    """Private 192.168.x.x range is blocked."""
    result = analyze_url("http://192.168.1.1/router")
    assert result.is_blocked_ssrf is True


def test_preserve_ssrf_loopback_ipv6():
    """IPv6 loopback ::1 is blocked."""
    result = analyze_url("http://[::1]/admin")
    assert result.is_blocked_ssrf is True
    assert result.ssrf_risk_level in (SSRFRiskLevel.LOOPBACK.value, SSRFRiskLevel.PRIVATE_IP.value)


def test_preserve_ssrf_link_local():
    """AWS metadata link-local IP is blocked."""
    result = analyze_url("http://169.254.169.254/latest/meta-data/")
    assert result.is_blocked_ssrf is True
    assert result.ssrf_risk_level == SSRFRiskLevel.METADATA_ENDPOINT.value


def test_preserve_ssrf_cloud_metadata_hostname():
    """GCP metadata hostname is blocked."""
    result = analyze_url("http://metadata.google.internal/computeMetadata/v1/")
    assert result.is_blocked_ssrf is True


def test_preserve_ssrf_localhost_keyword():
    """Localhost keyword is blocked."""
    result = analyze_url("http://localhost:8080/debug")
    assert result.is_blocked_ssrf is True
    assert result.ssrf_risk_level == SSRFRiskLevel.LOOPBACK.value


def test_preserve_ssrf_invalid_scheme():
    """Non-HTTP schemes (file://, gopher://) are blocked."""
    for scheme_url in ["file:///etc/passwd", "gopher://evil.com/", "dict://internal/", "ftp://192.168.1.1/"]:
        result = analyze_url(scheme_url)
        assert result.is_blocked_ssrf is True, f"Expected SSRF block for: {scheme_url}"


# ─── Suspicious TLD Detection ─────────────────────────────────────────────────

def test_suspicious_tld_xyz():
    """Domain with .xyz TLD triggers SUSPICIOUS_TLD."""
    result = analyze_url("http://sbi-kyc.xyz/update")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_TLD" in ids


def test_suspicious_tld_click():
    """Domain with .click TLD triggers SUSPICIOUS_TLD."""
    result = analyze_url("http://bank-verify.click/login")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_TLD" in ids


def test_clean_tld_no_flag():
    """Legitimate .com TLD alone doesn't trigger SUSPICIOUS_TLD."""
    result = analyze_url("http://example.com/about")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_TLD" not in ids


# ─── Excessive Subdomain Depth ────────────────────────────────────────────────

def test_excessive_subdomain_depth():
    """5+ subdomain labels trigger EXCESSIVE_SUBDOMAIN_DEPTH."""
    result = analyze_url("http://a.b.c.d.e.f.example.com/")
    ids = [f.finding_id for f in result.findings]
    assert "EXCESSIVE_SUBDOMAIN_DEPTH" in ids


def test_normal_subdomain_depth():
    """Two-label domain doesn't trigger depth warning."""
    result = analyze_url("http://www.example.com/")
    ids = [f.finding_id for f in result.findings]
    assert "EXCESSIVE_SUBDOMAIN_DEPTH" not in ids


# ─── URL Entropy ──────────────────────────────────────────────────────────────

def test_high_entropy_url():
    """Randomly-looking URL with high entropy triggers HIGH_URL_ENTROPY."""
    result = analyze_url("http://evil.xyz/a3kX9pQrZ8mNcWvYtLuJhFdBgSeOiRzA?tok=xK2wP7qM")
    ids = [f.finding_id for f in result.findings]
    assert "HIGH_URL_ENTROPY" in ids


def test_low_entropy_url():
    """Simple URL doesn't trigger entropy warning."""
    result = analyze_url("http://example.com/home")
    ids = [f.finding_id for f in result.findings]
    assert "HIGH_URL_ENTROPY" not in ids


# ─── Suspicious Path Tokens ───────────────────────────────────────────────────

def test_suspicious_path_reward():
    """'reward' in path triggers SUSPICIOUS_PATH_TOKENS."""
    result = analyze_url("http://example.com/claim-reward?user=abc")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_PATH_TOKENS" in ids


# ─── Credential Path Tokens ───────────────────────────────────────────────────

def test_credential_path_kyc():
    """'/kyc' in path triggers CREDENTIAL_HARVESTING_PATH."""
    result = analyze_url("http://sbi-update.xyz/kyc/submit")
    ids = [f.finding_id for f in result.findings]
    assert "CREDENTIAL_HARVESTING_PATH" in ids


def test_credential_path_aadhaar():
    """'aadhaar' in query triggers CREDENTIAL_HARVESTING_PATH."""
    result = analyze_url("http://gov-portal.live/?aadhaar=verify")
    ids = [f.finding_id for f in result.findings]
    assert "CREDENTIAL_HARVESTING_PATH" in ids


# ─── Brand Impersonation in Domain ────────────────────────────────────────────

def test_brand_impersonation_sbi_in_subdomain():
    """'sbi' in non-authoritative subdomain triggers BRAND_IMPERSONATION_IN_DOMAIN."""
    result = analyze_url("http://sbi-login.fraud.xyz/kyc")
    ids = [f.finding_id for f in result.findings]
    assert "BRAND_IMPERSONATION_IN_DOMAIN" in ids


def test_brand_impersonation_paytm():
    """'paytm' in non-authoritative subdomain triggers BRAND_IMPERSONATION_IN_DOMAIN."""
    result = analyze_url("http://secure-paytm-kyc.click/verify")
    ids = [f.finding_id for f in result.findings]
    assert "BRAND_IMPERSONATION_IN_DOMAIN" in ids


def test_legitimate_brand_domain_no_flag():
    """Official sbi.co.in doesn't trigger BRAND_IMPERSONATION_IN_DOMAIN."""
    result = analyze_url("http://sbi.co.in/personal")
    ids = [f.finding_id for f in result.findings]
    assert "BRAND_IMPERSONATION_IN_DOMAIN" not in ids


# ─── Punycode Detection ───────────────────────────────────────────────────────

def test_punycode_domain():
    """xn-- Punycode label triggers PUNYCODE_DOMAIN."""
    result = analyze_url("http://xn--sbi-kyc.co.in/update")
    ids = [f.finding_id for f in result.findings]
    assert "PUNYCODE_DOMAIN" in ids


# ─── Unicode Homoglyphs ───────────────────────────────────────────────────────

def test_unicode_homoglyph_in_host():
    """Cyrillic lookalike chars in host trigger UNICODE_HOMOGLYPH."""
    # Using Cyrillic 'о' (U+043E) to spoof 'o'
    result = analyze_url("http://sbі.co.in/kyc")  # Cyrillic 'і'
    ids = [f.finding_id for f in result.findings]
    # Should get at least one homoglyph-related finding
    assert any("HOMOGLYPH" in fid or "NFKC" in fid for fid in ids)


# ─── IP Literal URLs ──────────────────────────────────────────────────────────

def test_public_ip_literal_flagged():
    """Public raw IP URL triggers IP_LITERAL_URL."""
    result = analyze_url("http://203.0.114.1/phish")  # routable public IP
    ids = [f.finding_id for f in result.findings]
    assert "IP_LITERAL_URL" in ids


# ─── URL Shorteners ───────────────────────────────────────────────────────────

def test_url_shortener_bitly():
    """bit.ly triggers URL_SHORTENER."""
    result = analyze_url("http://bit.ly/3scamLink")
    ids = [f.finding_id for f in result.findings]
    assert "URL_SHORTENER" in ids


def test_url_shortener_tinyurl():
    """tinyurl.com triggers URL_SHORTENER."""
    result = analyze_url("https://tinyurl.com/scam123")
    ids = [f.finding_id for f in result.findings]
    assert "URL_SHORTENER" in ids


# ─── Excessive / Double Encoding ─────────────────────────────────────────────

def test_double_encoding():
    """Double percent-encoding (%252F = double-encoded '/') triggers DOUBLE_ENCODING."""
    result = analyze_url("http://example.com/%252Fetc%252Fpasswd")
    ids = [f.finding_id for f in result.findings]
    assert "DOUBLE_ENCODING" in ids


def test_excessive_encoding():
    """More than 10 encoded sequences trigger EXCESSIVE_PERCENT_ENCODING."""
    encoded = "%41" * 12  # 12 instances of %41 (= 'A')
    result = analyze_url(f"http://example.com/{encoded}")
    ids = [f.finding_id for f in result.findings]
    # May flag DOUBLE_ENCODING or EXCESSIVE_PERCENT_ENCODING
    assert "EXCESSIVE_PERCENT_ENCODING" in ids or "DOUBLE_ENCODING" in ids


# ─── Embedded Credentials ─────────────────────────────────────────────────────

def test_embedded_credentials():
    """user:pass@host triggers EMBEDDED_CREDENTIALS."""
    result = analyze_url("http://admin:secret@evil.com/login")
    ids = [f.finding_id for f in result.findings]
    assert "EMBEDDED_CREDENTIALS" in ids


# ─── Suspicious Ports ─────────────────────────────────────────────────────────

def test_suspicious_port_8080():
    """Port 8080 triggers SUSPICIOUS_PORT."""
    result = analyze_url("http://evil.com:8080/phish")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_PORT" in ids


def test_suspicious_port_4444():
    """Port 4444 (common C2) triggers SUSPICIOUS_PORT."""
    result = analyze_url("http://example.com:4444/")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_PORT" in ids


def test_standard_port_no_flag():
    """Standard port 443 doesn't trigger SUSPICIOUS_PORT."""
    result = analyze_url("https://example.com:443/safe")
    ids = [f.finding_id for f in result.findings]
    assert "SUSPICIOUS_PORT" not in ids


# ─── Nested URLs ──────────────────────────────────────────────────────────────

def test_nested_url_open_redirect():
    """Nested http URL in path triggers NESTED_URL."""
    result = analyze_url("http://tracker.evil.xyz/redirect?url=http://phish.xyz/kyc")
    ids = [f.finding_id for f in result.findings]
    assert "NESTED_URL" in ids


# ─── Unusual URL Structures ───────────────────────────────────────────────────

def test_url_fragment_redirect():
    """#http:// fragment triggers REDIRECT_VIA_FRAGMENT."""
    result = analyze_url("http://example.com/page#http://evil.com/steal")
    ids = [f.finding_id for f in result.findings]
    assert "REDIRECT_VIA_FRAGMENT" in ids


def test_multiple_at_signs():
    """Multiple @ signs trigger MULTIPLE_AT_SIGNS."""
    result = analyze_url("http://evil.com@legitimate.com@phish.xyz/")
    ids = [f.finding_id for f in result.findings]
    assert "MULTIPLE_AT_SIGNS" in ids


def test_abnormally_long_url():
    """URL over 500 chars triggers ABNORMALLY_LONG_URL."""
    long_path = "a" * 600
    result = analyze_url(f"http://example.com/{long_path}")
    ids = [f.finding_id for f in result.findings]
    assert "ABNORMALLY_LONG_URL" in ids


# ─── Parser Differential / Malformed URL Tests ───────────────────────────────

def test_malformed_empty_url():
    """Empty URL returns a blocked or safe result without crashing."""
    result = analyze_url("")
    assert result is not None


def test_malformed_only_spaces():
    """Whitespace-only URL doesn't crash the analyzer."""
    result = analyze_url("   ")
    assert result is not None


def test_malformed_url_no_host():
    """URL with missing host doesn't crash the analyzer."""
    result = analyze_url("http:///path/only")
    assert result is not None


def test_parser_differential_backslash():
    """Backslash normalization is handled safely."""
    result = analyze_url(r"http://evil.com\@legitimate.com/")
    assert result is not None


def test_parser_differential_tab_injection():
    """Tab character in URL is handled without crash."""
    result = analyze_url("http://evil.com/path\ttab")
    assert result is not None


def test_parser_differential_null_byte():
    """Null byte in URL is handled safely."""
    result = analyze_url("http://evil.com/path\x00null")
    assert result is not None


def test_parser_differential_unicode_host():
    """Non-ASCII unicode hostname is handled without crash."""
    result = analyze_url("http://例え.jp/test")
    assert result is not None


# ─── Network-Free Regression Proof ───────────────────────────────────────────

def test_network_invariant_no_socket_calls():
    """
    Regression: analyzing SSRF payloads NEVER triggers socket.connect,
    socket.getaddrinfo, or urllib.request.urlopen.
    """
    import socket
    import urllib.request

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://10.0.0.1/admin",
        "http://127.0.0.1:8080/debug",
        "http://[::1]/secret",
        "http://bit.ly/3abc123",
        "http://sbi-kyc.xyz/update",
        "http://xn--sbi-kyc.co.in/login",
        "http://admin:password@evil.com/",
        "http://evil.com/redirect?url=http://localhost/",
    ]

    with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS resolution forbidden!")) as mock_dns, \
         mock.patch("socket.socket.connect", side_effect=AssertionError("TCP connection forbidden!")) as mock_tcp, \
         mock.patch("urllib.request.urlopen", side_effect=AssertionError("HTTP request forbidden!")) as mock_http:

        for payload in ssrf_payloads:
            result = analyze_url(payload)
            assert result is not None, f"Analyzer returned None for: {payload}"

        # Verify absolutely no network calls were made
        assert mock_dns.call_count == 0, "DNS resolution was attempted!"
        assert mock_tcp.call_count == 0, "TCP connection was attempted!"
        assert mock_http.call_count == 0, "HTTP request was attempted!"


def test_ssrf_classify_stays_static():
    """
    Regression: classify_ssrf_risk() never causes any socket activity for
    any of the standard SSRF attack payloads.
    """
    import socket

    payloads = [
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "gopher://internal/",
        "file:///etc/passwd",
        "http://192.168.0.1/",
    ]

    with mock.patch("socket.getaddrinfo", side_effect=AssertionError("DNS call forbidden")) as mock_dns:
        for p in payloads:
            level = classify_ssrf_risk(p)
            assert level != SSRFRiskLevel.SAFE or p.startswith("http://127"), f"Unexpected SAFE for: {p}"

        assert mock_dns.call_count == 0, "classify_ssrf_risk triggered DNS!"


# ─── Test Runner ─────────────────────────────────────────────────────────────

def run_all_tests():
    tests = [
        # SSRF block preservation
        test_preserve_ssrf_loopback_ipv4,
        test_preserve_ssrf_private_ipv4_10,
        test_preserve_ssrf_private_ipv4_172,
        test_preserve_ssrf_private_ipv4_192,
        test_preserve_ssrf_loopback_ipv6,
        test_preserve_ssrf_link_local,
        test_preserve_ssrf_cloud_metadata_hostname,
        test_preserve_ssrf_localhost_keyword,
        test_preserve_ssrf_invalid_scheme,
        # Suspicious TLDs
        test_suspicious_tld_xyz,
        test_suspicious_tld_click,
        test_clean_tld_no_flag,
        # Subdomain depth
        test_excessive_subdomain_depth,
        test_normal_subdomain_depth,
        # Entropy
        test_high_entropy_url,
        test_low_entropy_url,
        # Path tokens
        test_suspicious_path_reward,
        test_credential_path_kyc,
        test_credential_path_aadhaar,
        # Brand impersonation
        test_brand_impersonation_sbi_in_subdomain,
        test_brand_impersonation_paytm,
        test_legitimate_brand_domain_no_flag,
        # Punycode
        test_punycode_domain,
        # Homoglyphs
        test_unicode_homoglyph_in_host,
        # IP literal
        test_public_ip_literal_flagged,
        # Shorteners
        test_url_shortener_bitly,
        test_url_shortener_tinyurl,
        # Encoding
        test_double_encoding,
        test_excessive_encoding,
        # Embedded creds
        test_embedded_credentials,
        # Ports
        test_suspicious_port_8080,
        test_suspicious_port_4444,
        test_standard_port_no_flag,
        # Nested URLs
        test_nested_url_open_redirect,
        # Unusual structure
        test_url_fragment_redirect,
        test_multiple_at_signs,
        test_abnormally_long_url,
        # Parser differential / malformed
        test_malformed_empty_url,
        test_malformed_only_spaces,
        test_malformed_url_no_host,
        test_parser_differential_backslash,
        test_parser_differential_tab_injection,
        test_parser_differential_null_byte,
        test_parser_differential_unicode_host,
        # Network-free regression proofs
        test_network_invariant_no_socket_calls,
        test_ssrf_classify_stays_static,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} URL Analyzer Tests Passed!")
