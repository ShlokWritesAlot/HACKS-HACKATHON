"""
Threat Intelligence Indicator schemas for BhashaRakshak.

Defines the canonical representation of extracted indicators (IOCs):
URLs, domains, phone numbers, emails, UPI IDs, sender IDs, IP addresses.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    PHONE_NUMBER = "phone_number"
    EMAIL = "email"
    UPI_ID = "upi_id"
    SENDER_ID = "sender_id"
    IP_ADDRESS = "ip_address"


class SSRFRiskLevel(str, enum.Enum):
    """Whether an extracted URL/IP refers to a potentially dangerous internal resource."""
    SAFE = "safe"
    PRIVATE_IP = "private_ip"
    LOOPBACK = "loopback"
    METADATA_ENDPOINT = "metadata_endpoint"
    INVALID_SCHEME = "invalid_scheme"
    BLOCKED = "blocked"


class ExtractedIndicator(BaseModel):
    """Single extracted indicator of compromise from an SMS message."""
    model_config = ConfigDict(extra="forbid")

    type: IndicatorType
    value: str = Field(..., description="The raw, normalized indicator value.")
    source: str = Field(default="message", description="Source of extraction (always 'message' in Phase 1).")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Extraction confidence score (0.0–1.0).")

    # SSRF / Security flags
    ssrf_risk: SSRFRiskLevel = Field(default=SSRFRiskLevel.SAFE)
    is_internal_or_private: bool = Field(default=False)
    is_idn_homograph: bool = Field(default=False, description="True if domain uses non-ASCII lookalike characters.")

    # Optional metadata for future enrichment
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EnrichmentVerdict(BaseModel):
    """Result from a threat intelligence provider enrichment lookup."""
    model_config = ConfigDict(extra="forbid")

    provider: str
    indicator_value: str
    is_known_malicious: bool = False
    threat_category: Optional[str] = None
    reputation_score: Optional[float] = None
    raw: Dict[str, Any] = Field(default_factory=dict)


class ThreatReport(BaseModel):
    """Full threat intelligence report for a single SMS message."""
    model_config = ConfigDict(extra="forbid")

    indicators: List[ExtractedIndicator] = Field(default_factory=list)
    enrichments: List[EnrichmentVerdict] = Field(default_factory=list)

    # Summary counts
    url_count: int = 0
    domain_count: int = 0
    phone_count: int = 0
    email_count: int = 0
    upi_count: int = 0
    sender_id_count: int = 0
    ip_count: int = 0
    suspicious_indicator_count: int = 0
