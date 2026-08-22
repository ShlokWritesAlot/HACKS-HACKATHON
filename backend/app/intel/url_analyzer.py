"""
Extended SSRF-Safe URL Analysis Engine for BhashaRakshak.

SECURITY CONTRACT:
  - This module is a PURE STATIC ANALYZER.
  - It NEVER performs DNS resolution, TCP connections, HTTP requests,
    or redirect following.
  - It NEVER contacts or resolves the supplied domain.
  - All analysis is performed on the textual representation of the URL only.
  - All existing SSRF blocks (localhost, loopback, private IPv4/IPv6,
    link-local, cloud metadata, non-http/https schemes) are preserved
    and delegated to the existing ssrf.py module.
"""

from __future__ import annotations

import enum
import ipaddress
import math
import re
import unicodedata
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.intel.ssrf import classify_ssrf_risk
from app.intel.schemas import SSRFRiskLevel


# ── Finding Severity Enum ──────────────────────────────────────────────────────

class URLFindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Structured Finding ─────────────────────────────────────────────────────────

class URLFinding(BaseModel):
    """A single structured finding from the URL analyzer."""
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Machine-readable identifier.")
    severity: URLFindingSeverity
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str
    detail: Optional[str] = Field(None, description="Sanitized technical detail.")


# ── URL Analysis Result ────────────────────────────────────────────────────────

class URLAnalysisResult(BaseModel):
    """Aggregate result from analyzing a single URL."""
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="The original (sanitized) URL string analyzed.")
    is_blocked_ssrf: bool = Field(False, description="True if the SSRF engine blocked this URL.")
    ssrf_risk_level: str = Field("safe", description="SSRFRiskLevel value.")
    is_malicious: bool = Field(False, description="True if the URL is assessed as malicious/suspicious.")
    overall_confidence: float = Field(0.0, ge=0.0, le=1.0)
    findings: List[URLFinding] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── Constants ─────────────────────────────────────────────────────────────────

# Suspicious TLDs common in scams
_SUSPICIOUS_TLDS = frozenset({
    "xyz", "click", "top", "live", "site", "icu", "online", "store", "fun",
    "gq", "ml", "cf", "tk", "ga", "info", "biz", "cc", "pw", "link",
    "work", "world", "land", "global", "digital", "life", "space", "ws",
})

# Known URL shortener domains
_URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "rebrand.ly", "rb.gy", "tiny.cc",
    "shorte.st", "clk.sh", "cur.lv", "cutt.ly", "urlshortx.com",
    "shorturl.at", "s.id",
})

# Credential / auth / KYC path tokens that indicate phishing
_CREDENTIAL_PATH_TOKENS = frozenset({
    "kyc", "verify", "verification", "login", "signin", "auth",
    "account", "password", "passwd", "credentials", "otp", "token",
    "update", "confirm", "secure", "validate", "activate", "unlock",
    "aadhaar", "pan", "passport",
})

# Suspicious path tokens
_SUSPICIOUS_PATH_TOKENS = frozenset({
    "phish", "scam", "spam", "click", "redirect", "track", "survey",
    "reward", "prize", "winner", "claim", "offer", "promo", "coupon",
    "free", "gift", "bonus", "earn", "income", "refund", "cashback",
})

# Non-standard suspicious ports
_SUSPICIOUS_PORTS = frozenset({
    8080, 8443, 8888, 9090, 9999, 3000, 3001, 4000, 4443,
    1337, 31337, 2222, 4444, 5555, 6666, 7777,
})

# Brands commonly impersonated — cross-check with impersonation registry terms
_BRAND_TOKENS = [
    "sbi", "hdfc", "icici", "axis", "paytm", "income-tax", "incometax",
    "jio", "airtel", "bsnl", "fedex", "indiapost", "irdai", "sebi",
    "rbi", "npci", "upi",
]

# Characters that are confusable homoglyphs (quick static check)
_HOMOGLYPH_PATTERN = re.compile(
    r"[àáâãäåæçèéêëìíîïðñòóôõöùúûü"
    r"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖÙÚÛÜ"
    r"\u0430\u0435\u043e\u0440\u0441\u0445"   # Cyrillic а,е,о,р,с,х
    r"\u04BB\u0456\u0458\u04CF]",              # More Cyrillic lookalikes
    re.UNICODE,
)

# Re-used across analysis
_ENCODING_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")
_NESTED_URL_RE = re.compile(r"https?://[^\s]*https?://", re.IGNORECASE)
_EMBEDDED_CRED_RE = re.compile(r"https?://[^@\s]+:[^@\s]+@", re.IGNORECASE)
_IP_LITERAL_RE = re.compile(
    r"https?://\[?(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\."
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\]?",
    re.IGNORECASE,
)


# ── Entropy Calculation ────────────────────────────────────────────────────────

def _compute_entropy(s: str) -> float:
    """Shannon entropy of a string. Bounded to avoid division by zero."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── Main Analyzer Class ────────────────────────────────────────────────────────

class URLAnalyzer:
    """
    Pure static URL analysis engine.

    Extends the existing SSRF guard (ssrf.py) with 15+ structural
    analysis detectors. Zero network activity is performed.
    """

    def analyze(self, raw_url: str) -> URLAnalysisResult:
        """
        Analyze a URL string purely from its textual representation.

        Args:
            raw_url: An untrusted URL string extracted from SMS or user input.

        Returns:
            URLAnalysisResult with structured findings and overall assessment.
        """
        # Sanitize input length to prevent ReDoS / memory exhaustion
        url = (raw_url or "").strip()[:4096]

        # ── Step 0: SSRF Check (MUST always run first) ─────────────────────────
        ssrf_level = classify_ssrf_risk(url)
        is_blocked = ssrf_level != SSRFRiskLevel.SAFE

        findings: List[URLFinding] = []
        metadata: Dict[str, Any] = {}

        if is_blocked:
            findings.append(URLFinding(
                finding_id="SSRF_BLOCKED",
                severity=URLFindingSeverity.CRITICAL,
                confidence=1.0,
                description=f"URL blocked by SSRF guard: {ssrf_level.value}",
                detail=None,  # Do not expose internal URL structure
            ))
            return URLAnalysisResult(
                url=url,
                is_blocked_ssrf=True,
                ssrf_risk_level=ssrf_level.value,
                is_malicious=True,
                overall_confidence=1.0,
                findings=findings,
                metadata=metadata,
            )

        # ── Parse URL statically ───────────────────────────────────────────────
        parse_input = url
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
            parse_input = "http://" + url

        try:
            parsed = urllib.parse.urlparse(parse_input)
        except Exception:
            findings.append(URLFinding(
                finding_id="MALFORMED_URL",
                severity=URLFindingSeverity.HIGH,
                confidence=0.98,
                description="URL is malformed and cannot be safely parsed.",
            ))
            return URLAnalysisResult(
                url=url,
                is_blocked_ssrf=False,
                ssrf_risk_level=ssrf_level.value,
                is_malicious=True,
                overall_confidence=0.98,
                findings=findings,
            )

        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        metadata["host"] = host
        metadata["scheme"] = scheme
        metadata["path_length"] = len(path)

        # Run all static detectors
        self._detect_suspicious_tld(host, findings)
        self._detect_excessive_subdomain_depth(host, findings)
        self._detect_url_entropy(host, path, query, findings, metadata)
        self._detect_suspicious_path_tokens(path, query, findings)
        self._detect_credential_path_tokens(path, query, findings)
        self._detect_brand_impersonation_in_domain(host, path, findings)
        self._detect_punycode(host, findings)
        self._detect_homoglyphs(host, findings)
        self._detect_ip_literal_url(url, host, findings)
        self._detect_url_shortener(host, findings)
        self._detect_excessive_encoding(url, findings)
        self._detect_embedded_credentials(url, findings)
        self._detect_suspicious_port(port, findings)
        self._detect_nested_urls(url, findings)
        self._detect_unusual_url_structure(parsed, url, host, path, findings)

        # ── Aggregate verdict ─────────────────────────────────────────────────
        if not findings:
            return URLAnalysisResult(
                url=url,
                is_blocked_ssrf=False,
                ssrf_risk_level=ssrf_level.value,
                is_malicious=False,
                overall_confidence=0.90,
                findings=[],
                metadata=metadata,
            )

        max_conf = max(f.confidence for f in findings)
        has_high = any(f.severity in (URLFindingSeverity.HIGH, URLFindingSeverity.CRITICAL) for f in findings)
        is_malicious = has_high or len(findings) >= 3

        return URLAnalysisResult(
            url=url,
            is_blocked_ssrf=False,
            ssrf_risk_level=ssrf_level.value,
            is_malicious=is_malicious,
            overall_confidence=max_conf if is_malicious else 0.90,
            findings=findings,
            metadata=metadata,
        )

    # ── Individual Detectors ───────────────────────────────────────────────────

    def _detect_suspicious_tld(self, host: str, findings: List[URLFinding]):
        parts = host.split(".")
        tld = parts[-1] if parts else ""
        if tld in _SUSPICIOUS_TLDS:
            findings.append(URLFinding(
                finding_id="SUSPICIOUS_TLD",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.85,
                description=f"Domain uses a high-risk TLD commonly associated with scam infrastructure.",
                detail=f".{tld}",
            ))

    def _detect_excessive_subdomain_depth(self, host: str, findings: List[URLFinding]):
        # Strip trailing dot if any
        parts = [p for p in host.rstrip(".").split(".") if p]
        depth = len(parts)
        if depth >= 5:
            findings.append(URLFinding(
                finding_id="EXCESSIVE_SUBDOMAIN_DEPTH",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.80,
                description=f"Domain has excessive subdomain depth ({depth} labels), often used to mimic legitimate brands.",
                detail=None,
            ))

    def _detect_url_entropy(self, host: str, path: str, query: str, findings: List[URLFinding], metadata: Dict):
        full = host + path + query
        entropy = _compute_entropy(full)
        metadata["url_entropy"] = round(entropy, 3)
        if entropy > 4.0:
            findings.append(URLFinding(
                finding_id="HIGH_URL_ENTROPY",
                severity=URLFindingSeverity.LOW,
                confidence=0.75,
                description=f"URL has abnormally high character entropy ({entropy:.2f} bits), consistent with generated/obfuscated phishing links.",
            ))

    def _detect_suspicious_path_tokens(self, path: str, query: str, findings: List[URLFinding]):
        combined = (path + " " + query).lower()
        matched = [t for t in _SUSPICIOUS_PATH_TOKENS if t in combined]
        if matched:
            findings.append(URLFinding(
                finding_id="SUSPICIOUS_PATH_TOKENS",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.82,
                description="URL path/query contains tokens commonly associated with phishing campaigns.",
                detail=", ".join(sorted(matched)[:5]),
            ))

    def _detect_credential_path_tokens(self, path: str, query: str, findings: List[URLFinding]):
        combined = (path + " " + query).lower()
        matched = [t for t in _CREDENTIAL_PATH_TOKENS if t in combined]
        if matched:
            findings.append(URLFinding(
                finding_id="CREDENTIAL_HARVESTING_PATH",
                severity=URLFindingSeverity.HIGH,
                confidence=0.88,
                description="URL path/query contains credential or KYC-harvesting tokens.",
                detail=", ".join(sorted(matched)[:5]),
            ))

    def _detect_brand_impersonation_in_domain(self, host: str, path: str, findings: List[URLFinding]):
        combined = host + path
        for brand in _BRAND_TOKENS:
            if brand not in combined:
                continue
            # Check if brand IS the primary registrable domain (e.g. sbi.co.in, paytm.com)
            parts = [p for p in host.split(".") if p]
            # Registrable domain check: brand occupies leftmost label or the SLD
            # before ccTLD combos like .co.in / .org.in
            is_legitimate_registrant = False
            for i, part in enumerate(parts):
                if part == brand:
                    # If it's first label with only 1–2 remaining labels → legitimate
                    # e.g. sbi.co.in → parts[0]='sbi', remaining=['co','in'] (2 labels)
                    remaining = len(parts) - i - 1
                    if remaining <= 2:
                        is_legitimate_registrant = True
                        break
            if is_legitimate_registrant:
                continue
            findings.append(URLFinding(
                finding_id="BRAND_IMPERSONATION_IN_DOMAIN",
                severity=URLFindingSeverity.HIGH,
                confidence=0.90,
                description=f"URL contains a brand name token in a non-authoritative domain context.",
                detail=brand,
            ))
            break  # Report once per URL

    def _detect_punycode(self, host: str, findings: List[URLFinding]):
        labels = host.split(".")
        for label in labels:
            if label.startswith("xn--"):
                findings.append(URLFinding(
                    finding_id="PUNYCODE_DOMAIN",
                    severity=URLFindingSeverity.HIGH,
                    confidence=0.92,
                    description="Domain contains Punycode-encoded label (xn--), commonly used for IDN homograph spoofing.",
                    detail=label[:32],
                ))
                break

    def _detect_homoglyphs(self, host: str, findings: List[URLFinding]):
        if _HOMOGLYPH_PATTERN.search(host):
            findings.append(URLFinding(
                finding_id="UNICODE_HOMOGLYPH",
                severity=URLFindingSeverity.HIGH,
                confidence=0.93,
                description="Domain contains Unicode lookalike characters (homoglyphs) that may impersonate legitimate domains.",
            ))
        # Additional NFKC normalization check
        try:
            normalized = unicodedata.normalize("NFKC", host)
            if normalized != host and normalized.isascii():
                findings.append(URLFinding(
                    finding_id="UNICODE_NFKC_NORMALIZATION",
                    severity=URLFindingSeverity.MEDIUM,
                    confidence=0.85,
                    description="Domain normalizes to a different ASCII value under NFKC — possible confusable Unicode abuse.",
                ))
        except Exception:
            pass

    def _detect_ip_literal_url(self, url: str, host: str, findings: List[URLFinding]):
        if _IP_LITERAL_RE.match(url):
            findings.append(URLFinding(
                finding_id="IP_LITERAL_URL",
                severity=URLFindingSeverity.HIGH,
                confidence=0.94,
                description="URL uses a raw IP address instead of a domain name — common in phishing and C2 infrastructure.",
            ))
            return
        # Also handle octal / hex IP encoding
        if re.match(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$", host, re.IGNORECASE):
            findings.append(URLFinding(
                finding_id="ENCODED_IP_LITERAL",
                severity=URLFindingSeverity.CRITICAL,
                confidence=0.97,
                description="URL host appears to be an integer, octal, or hex-encoded IP address — SSRF bypass attempt.",
            ))

    def _detect_url_shortener(self, host: str, findings: List[URLFinding]):
        if host in _URL_SHORTENERS:
            findings.append(URLFinding(
                finding_id="URL_SHORTENER",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.85,
                description=f"URL uses a known shortening service that obscures the true destination.",
                detail=host,
            ))

    def _detect_excessive_encoding(self, url: str, findings: List[URLFinding]):
        # Double encoding (%25xx)
        if _DOUBLE_ENCODING_RE.search(url):
            findings.append(URLFinding(
                finding_id="DOUBLE_ENCODING",
                severity=URLFindingSeverity.HIGH,
                confidence=0.93,
                description="URL uses double percent-encoding (%25xx), a common WAF/filter bypass technique.",
            ))
            return
        # Count percent-encoded sequences
        encoded_count = len(_ENCODING_PERCENT_RE.findall(url))
        if encoded_count > 10:
            findings.append(URLFinding(
                finding_id="EXCESSIVE_PERCENT_ENCODING",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.80,
                description=f"URL contains {encoded_count} percent-encoded sequences, which may be used to obfuscate malicious content.",
            ))

    def _detect_embedded_credentials(self, url: str, findings: List[URLFinding]):
        if _EMBEDDED_CRED_RE.match(url):
            findings.append(URLFinding(
                finding_id="EMBEDDED_CREDENTIALS",
                severity=URLFindingSeverity.HIGH,
                confidence=0.96,
                description="URL contains embedded credentials in the userinfo component (user:password@host).",
            ))

    def _detect_suspicious_port(self, port: Optional[int], findings: List[URLFinding]):
        if port is None:
            return
        if port in _SUSPICIOUS_PORTS:
            findings.append(URLFinding(
                finding_id="SUSPICIOUS_PORT",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.82,
                description=f"URL specifies a non-standard port ({port}) commonly used for evasion or proxy tunneling.",
                detail=str(port),
            ))

    def _detect_nested_urls(self, url: str, findings: List[URLFinding]):
        if _NESTED_URL_RE.search(url):
            findings.append(URLFinding(
                finding_id="NESTED_URL",
                severity=URLFindingSeverity.HIGH,
                confidence=0.92,
                description="URL contains a nested URL within its path or query, indicating open redirect or URL injection abuse.",
            ))

    def _detect_unusual_url_structure(
        self,
        parsed: urllib.parse.ParseResult,
        url: str,
        host: str,
        path: str,
        findings: List[URLFinding],
    ):
        # Abnormally long URL (beyond what legitimate services use)
        if len(url) > 500:
            findings.append(URLFinding(
                finding_id="ABNORMALLY_LONG_URL",
                severity=URLFindingSeverity.LOW,
                confidence=0.72,
                description=f"URL length is {len(url)} characters, abnormally long for a consumer-facing link.",
            ))
        # Fragment used as redirect (#http://...)
        fragment = parsed.fragment or ""
        if fragment.startswith("http://") or fragment.startswith("https://"):
            findings.append(URLFinding(
                finding_id="REDIRECT_VIA_FRAGMENT",
                severity=URLFindingSeverity.HIGH,
                confidence=0.90,
                description="URL uses a URL-scheme fragment (#http://...) for open redirect abuse.",
            ))
        # Unusual auth component without password (userinfo present)
        if parsed.username and not parsed.password:
            findings.append(URLFinding(
                finding_id="UNUSUAL_USERINFO",
                severity=URLFindingSeverity.MEDIUM,
                confidence=0.78,
                description="URL contains a userinfo component without a password, which is unusual and suspicious.",
            ))
        # Multiple @ signs (attempt to confuse parsers)
        if url.count("@") > 1:
            findings.append(URLFinding(
                finding_id="MULTIPLE_AT_SIGNS",
                severity=URLFindingSeverity.HIGH,
                confidence=0.95,
                description="URL contains multiple '@' characters, a common parser differential attack technique.",
            ))


# ── Module-level singleton ─────────────────────────────────────────────────────

_analyzer = URLAnalyzer()


def analyze_url(raw_url: str) -> URLAnalysisResult:
    """
    Analyze a URL string using pure static analysis.
    NEVER performs DNS resolution, TCP connections, or HTTP requests.

    Args:
        raw_url: Untrusted URL string from SMS or user input.

    Returns:
        URLAnalysisResult with findings and overall malicious assessment.
    """
    return _analyzer.analyze(raw_url)
