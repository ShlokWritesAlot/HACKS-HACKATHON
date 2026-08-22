"""
Indicator-of-Compromise (IOC) extractor for BhashaRakshak.

Extracts from untrusted SMS text:
  - URLs (with trailing punctuation stripping and scheme normalization)
  - Domains (from URLs and bare hostnames)
  - IP addresses (IPv4 and IPv6)
  - Phone numbers (Indian +91 / international)
  - Email addresses
  - UPI / VPA payment identifiers
  - Alphanumeric DLT Sender IDs

SECURITY CONTRACT:
  - This module NEVER fetches, resolves, or executes any extracted URL.
  - All regex patterns are bounded to prevent ReDoS.
  - Input is length-capped before processing.
  - Punycode/IDN decoding is performed for homograph detection but
    the domain is NOT resolved.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import unicodedata
from typing import List
from urllib.parse import urlparse

from app.intel.schemas import ExtractedIndicator, IndicatorType, SSRFRiskLevel, ThreatReport
from app.intel.ssrf import classify_ssrf_risk

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

MAX_INPUT_LENGTH = 5000  # Never process more characters than the API limit

# ── Compiled Regex Patterns ───────────────────────────────────────────────────

# URL: matches http/https/ftp URLs and bare short-domain patterns (bit.ly, t.co etc.)
# Uses possessive-like construction with atomic groups via character classes to avoid ReDoS.
_URL_RE = re.compile(
    r"(?:"
    r"https?://[^\s\x00-\x1f\x7f\"'<>()\[\]{}]{1,2000}"
    r"|"
    r"(?:www\.|[a-zA-Z0-9-]{2,63}\.(?:com|net|org|in|co\.in|io|live|xyz|top|link|click|info|biz|cc|tk|ml|ga|cf|gq))"
    r"[^\s\x00-\x1f\x7f\"'<>()\[\]{}]{0,500}"
    r")",
    re.IGNORECASE,
)

# IPv4 address (bounded, no CIDR)
_IPV4_RE = re.compile(
    r"\b"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
    r"\b"
)

# IPv6: basic bracket-enclosed form
_IPV6_RE = re.compile(r"\[([0-9a-fA-F:]{3,39})\]")

# Email
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,20}\b"
)

# UPI VPA: <handle>@<psp>
_UPI_PSPS = (
    "upi|paytm|okhdfcbank|okaxis|oksbi|ybl|apl|ibl|axl|hdfcbank|"
    "icici|sbi|kotak|aubank|indus|rbl|idfc|federal|barodapay|boi|"
    "centralbank|dbs|equitas|esaf|fincare|hsbc|jkb|kvb|mehb|"
    "nsdl|okbizaxis|pingpay|postpaid|pockets|rajgovhdfcbank|"
    "timecosmos|yapl|superyes|fbl"
)
_UPI_RE = re.compile(
    rf"\b[a-zA-Z0-9.\-_]{{3,64}}@(?:{_UPI_PSPS})\b",
    re.IGNORECASE,
)

# Indian mobile: 10 digits starting with 6-9, optionally prefixed +91/91/0
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+91[-.\s]?|91[-.\s]?|0[-.\s]?)?(?!0{10})([6-9]\d{9})"
    r"(?!\d)"
)

# DLT Alphanumeric Sender IDs: e.g. AX-SBIINB, VM-HDFCBK, TM-AIRTEL
_SENDER_ID_RE = re.compile(
    r"\b(?:AX|VM|TM|IM|TF|MF|LM|PM|SA|BP|BK|DM|DC|SC|SF|SD|SU|TP|UC)"
    r"-[A-Z0-9]{3,11}\b",
    re.IGNORECASE,
)

# High-risk / dynamic-DNS / known-malicious TLD patterns for confidence boost
_HIGH_RISK_TLDS = frozenset({
    "xyz", "top", "click", "link", "live", "tk", "ml", "ga", "cf", "gq",
    "cc", "buzz", "fun", "site", "online", "work", "bid", "win",
})

_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "cutt.ly",
    "rb.gy", "short.io", "is.gd", "buff.ly", "su.pr",
})


# ── Internal helpers ───────────────────────────────────────────────────────────

def _strip_trailing_punctuation(url: str) -> str:
    """
    Remove common punctuation characters appended after a URL in natural text.
    E.g.: http://example.com/login.  →  http://example.com/login
          (http://example.com)       →  http://example.com
    """
    # Remove matching trailing bracket/paren if no corresponding opener
    stripped = url.rstrip(".,;:!?\"'")
    for left, right in (("(", ")"), ("[", "]"), ("{", "}")):
        if stripped.endswith(right) and left not in stripped:
            stripped = stripped[:-1]
    return stripped


def _decode_idn(host: str) -> tuple[str, bool]:
    """
    Attempt to decode an IDN (Internationalized Domain Name) from punycode.
    Returns (decoded_hostname, is_non_ascii).
    """
    try:
        decoded = host.encode("ascii").decode("ascii")
        # Pure ASCII — check for IDNA encoded segments
        if "xn--" in decoded.lower():
            decoded = host.encode("ascii").decode("idna")
            return decoded, True
        return decoded, False
    except (UnicodeError, UnicodeDecodeError):
        # Already contains non-ASCII characters → potential homograph
        return host, True


def _extract_host(url: str) -> str | None:
    """Extract hostname from URL string, handling bare domains gracefully."""
    to_parse = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url) else "http://" + url
    try:
        parsed = urlparse(to_parse)
        return parsed.hostname or None
    except Exception:
        return None


def _domain_confidence(host: str) -> float:
    """Compute extraction confidence for a domain/URL based on known-risky signals."""
    host_lower = host.lower()
    tld = host_lower.rsplit(".", 1)[-1] if "." in host_lower else ""
    if host_lower in _SHORTENER_DOMAINS:
        return 0.97
    if tld in _HIGH_RISK_TLDS:
        return 0.92
    return 0.88


# ── Public extraction functions ────────────────────────────────────────────────

def extract_urls(text: str) -> List[ExtractedIndicator]:
    """Extract and classify URLs from text. NEVER fetches them."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    for match in _URL_RE.finditer(text[:MAX_INPUT_LENGTH]):
        raw = _strip_trailing_punctuation(match.group(0))
        if not raw or raw in seen:
            continue
        seen.add(raw)

        host = _extract_host(raw)
        if not host:
            continue

        # Reject pure IPs from the URL bucket — handled separately
        try:
            ipaddress.ip_address(host.strip("[]"))
            continue
        except ValueError:
            pass

        ssrf_risk = classify_ssrf_risk(raw)
        is_internal = ssrf_risk not in (SSRFRiskLevel.SAFE,)
        _, is_idn = _decode_idn(host)
        conf = _domain_confidence(host)

        indicators.append(ExtractedIndicator(
            type=IndicatorType.URL,
            value=raw,
            source="message",
            confidence=conf,
            ssrf_risk=ssrf_risk,
            is_internal_or_private=is_internal,
            is_idn_homograph=is_idn,
            metadata={"host": host},
        ))

    return indicators


def extract_domains(text: str) -> List[ExtractedIndicator]:
    """
    Extract the unique domain (host) component from all URLs found in text.
    Provides a de-duplicated flat domain list alongside the URL list.
    """
    seen_hosts: set[str] = set()
    indicators: List[ExtractedIndicator] = []

    for url_ind in extract_urls(text):
        host = url_ind.metadata.get("host", "")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        decoded, is_idn = _decode_idn(host)

        indicators.append(ExtractedIndicator(
            type=IndicatorType.DOMAIN,
            value=host,
            source="message",
            confidence=url_ind.confidence,
            ssrf_risk=url_ind.ssrf_risk,
            is_internal_or_private=url_ind.is_internal_or_private,
            is_idn_homograph=is_idn,
            metadata={"decoded": decoded} if is_idn else {},
        ))

    return indicators


def extract_ip_addresses(text: str) -> List[ExtractedIndicator]:
    """Extract IPv4 and IPv6 literals, classify SSRF risk."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    # IPv4
    for m in _IPV4_RE.finditer(text[:MAX_INPUT_LENGTH]):
        val = m.group(0)
        if val in seen:
            continue
        seen.add(val)
        ssrf = classify_ssrf_risk(val)
        indicators.append(ExtractedIndicator(
            type=IndicatorType.IP_ADDRESS,
            value=val,
            source="message",
            confidence=0.99,
            ssrf_risk=ssrf,
            is_internal_or_private=ssrf != SSRFRiskLevel.SAFE,
        ))

    # IPv6 bracket notation
    for m in _IPV6_RE.finditer(text[:MAX_INPUT_LENGTH]):
        val = m.group(1)
        bracketed = f"[{val}]"
        if bracketed in seen:
            continue
        seen.add(bracketed)
        ssrf = classify_ssrf_risk(bracketed)
        indicators.append(ExtractedIndicator(
            type=IndicatorType.IP_ADDRESS,
            value=val,
            source="message",
            confidence=0.99,
            ssrf_risk=ssrf,
            is_internal_or_private=ssrf != SSRFRiskLevel.SAFE,
        ))

    return indicators


def extract_phone_numbers(text: str) -> List[ExtractedIndicator]:
    """Extract Indian and international phone numbers."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    for m in _PHONE_RE.finditer(text[:MAX_INPUT_LENGTH]):
        digits = re.sub(r"\D", "", m.group(0))
        # Normalize to 10-digit Indian mobile
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]

        # Minimum 10 digits for Indian numbers
        if len(digits) < 10 or digits in seen:
            continue
        seen.add(digits)

        indicators.append(ExtractedIndicator(
            type=IndicatorType.PHONE_NUMBER,
            value=f"+91{digits}" if len(digits) == 10 else digits,
            source="message",
            confidence=0.91,
        ))

    return indicators


def extract_emails(text: str) -> List[ExtractedIndicator]:
    """Extract email addresses."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    for m in _EMAIL_RE.finditer(text[:MAX_INPUT_LENGTH]):
        val = m.group(0).lower()
        if val in seen:
            continue
        seen.add(val)
        indicators.append(ExtractedIndicator(
            type=IndicatorType.EMAIL,
            value=val,
            source="message",
            confidence=0.95,
        ))

    return indicators


def extract_upi_ids(text: str) -> List[ExtractedIndicator]:
    """Extract UPI Virtual Payment Addresses (VPAs)."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    for m in _UPI_RE.finditer(text[:MAX_INPUT_LENGTH]):
        val = m.group(0).lower()
        if val in seen:
            continue
        seen.add(val)
        indicators.append(ExtractedIndicator(
            type=IndicatorType.UPI_ID,
            value=val,
            source="message",
            confidence=0.97,
        ))

    return indicators


def extract_sender_ids(text: str) -> List[ExtractedIndicator]:
    """Extract Indian DLT alphanumeric sender IDs."""
    indicators: List[ExtractedIndicator] = []
    seen: set[str] = set()

    for m in _SENDER_ID_RE.finditer(text[:MAX_INPUT_LENGTH]):
        val = m.group(0).upper()
        if val in seen:
            continue
        seen.add(val)
        indicators.append(ExtractedIndicator(
            type=IndicatorType.SENDER_ID,
            value=val,
            source="message",
            confidence=0.89,
        ))

    return indicators


def build_threat_report(text: str) -> ThreatReport:
    """
    Run all extractors and compile a full ThreatReport for the given SMS text.

    This is the single entry point for the rest of the system.
    """
    urls = extract_urls(text)
    domains = extract_domains(text)
    ips = extract_ip_addresses(text)
    phones = extract_phone_numbers(text)
    emails = extract_emails(text)
    upis = extract_upi_ids(text)
    senders = extract_sender_ids(text)

    all_indicators = urls + domains + ips + phones + emails + upis + senders

    suspicious_count = sum(
        1 for ind in all_indicators
        if ind.is_internal_or_private or ind.is_idn_homograph
        or ind.ssrf_risk not in (SSRFRiskLevel.SAFE,)
    )

    return ThreatReport(
        indicators=all_indicators,
        url_count=len(urls),
        domain_count=len(domains),
        phone_count=len(phones),
        email_count=len(emails),
        upi_count=len(upis),
        sender_id_count=len(senders),
        ip_count=len(ips),
        suspicious_indicator_count=suspicious_count,
    )
