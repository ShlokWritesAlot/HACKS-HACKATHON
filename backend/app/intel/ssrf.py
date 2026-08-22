"""
SSRF (Server-Side Request Forgery) boundary validator for BhashaRakshak.

PURPOSE:
    This module is the CRITICAL security boundary between untrusted SMS content
    and any future network-level URL enrichment. It classifies extracted URLs and
    IP addresses before they can be passed to any outbound HTTP client.

SECURITY CONTRACT:
    - This module NEVER fetches, resolves, or executes any URL.
    - It performs STATIC classification of the URL/IP string only.
    - All checks are purely in-process string and address math operations.

BLOCKED CATEGORIES:
    - Private IPv4 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Loopback: 127.0.0.0/8, ::1
    - Link-local: 169.254.0.0/16 (AWS/GCP metadata), fe80::/10
    - Unique local IPv6: fc00::/7
    - Cloud metadata: 169.254.169.254, metadata.google.internal
    - Non-HTTP/HTTPS schemes: file://, gopher://, dict://, ftp://, etc.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.intel.schemas import SSRFRiskLevel

# Allowed schemes for enrichment (if ever implemented)
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata hostnames that must never be accessed
_METADATA_HOSTNAMES = frozenset({
    "169.254.169.254",          # AWS / Azure / GCP instance metadata
    "metadata.google.internal",
    "metadata.goog",
    "metadata.internal",
    "instance-data",
    "link-local.internal",
})

# Private / reserved IPv4 networks
_PRIVATE_IPV4_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback
    ipaddress.IPv4Network("0.0.0.0/8"),        # this-network
    ipaddress.IPv4Network("100.64.0.0/10"),    # shared address space
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("240.0.0.0/4"),      # reserved
    ipaddress.IPv4Network("255.255.255.255/32"),
]

# Private / reserved IPv6 networks
_PRIVATE_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::1/128"),          # loopback
    ipaddress.IPv6Network("fc00::/7"),         # unique local
    ipaddress.IPv6Network("fe80::/10"),        # link-local
    ipaddress.IPv6Network("::/128"),           # unspecified
    ipaddress.IPv6Network("::ffff:0:0/96"),    # IPv4-mapped
    ipaddress.IPv6Network("100::/64"),         # discard
    ipaddress.IPv6Network("2001:db8::/32"),    # documentation
]


def _is_private_ipv4(host: str) -> bool:
    """Check if host string is a private or reserved IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(host)
        return any(addr in net for net in _PRIVATE_IPV4_NETWORKS)
    except ValueError:
        return False


def _is_private_ipv6(host: str) -> bool:
    """Check if host string is a private or reserved IPv6 address."""
    # Strip bracket notation from IPv6 literals: [::1] -> ::1
    cleaned = host.strip("[]")
    try:
        addr = ipaddress.IPv6Address(cleaned)
        return any(addr in net for net in _PRIVATE_IPV6_NETWORKS)
    except ValueError:
        return False


def classify_ssrf_risk(raw_url: str) -> SSRFRiskLevel:
    """
    Statically classify the SSRF risk of a URL or IP address string.

    This function is PURELY STATIC — it never resolves DNS or fetches anything.

    Args:
        raw_url: A URL string extracted from untrusted SMS content.

    Returns:
        SSRFRiskLevel classification.
    """
    if not raw_url or not isinstance(raw_url, str):
        return SSRFRiskLevel.BLOCKED

    # Strip leading/trailing whitespace
    url = raw_url.strip()
    if not url:
        return SSRFRiskLevel.BLOCKED

    # Add scheme for bare domains / IP parsing
    parsed_input = url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        parsed_input = "http://" + url

    try:
        parsed = urlparse(parsed_input)
    except Exception:
        return SSRFRiskLevel.BLOCKED

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    host = parsed.hostname or ""

    # 1. Scheme validation
    if scheme not in _ALLOWED_SCHEMES:
        return SSRFRiskLevel.INVALID_SCHEME

    # 2. Metadata endpoint check (hostname-based, pre-IP resolution)
    if host.lower() in _METADATA_HOSTNAMES:
        return SSRFRiskLevel.METADATA_ENDPOINT

    # 3. IPv4 private check
    if _is_private_ipv4(host):
        if host.startswith("127."):
            return SSRFRiskLevel.LOOPBACK
        if host.startswith("169.254."):
            return SSRFRiskLevel.METADATA_ENDPOINT
        return SSRFRiskLevel.PRIVATE_IP

    # 4. IPv6 private check
    if _is_private_ipv6(host):
        if host.strip("[]") in ("::1", "0:0:0:0:0:0:0:1"):
            return SSRFRiskLevel.LOOPBACK
        return SSRFRiskLevel.PRIVATE_IP

    # 5. Localhost keyword match (belt-and-suspenders)
    if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        return SSRFRiskLevel.LOOPBACK

    return SSRFRiskLevel.SAFE


def is_safe_for_enrichment(raw_url: str) -> bool:
    """
    Returns True only if a URL has been cleared by all SSRF checks.
    This is the gate a hypothetical enrichment adapter MUST call before
    making any outbound request.
    """
    return classify_ssrf_risk(raw_url) == SSRFRiskLevel.SAFE
