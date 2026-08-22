"""
Pydantic schemas for Campaign Clustering API.

SECURITY: Raw message text is never exposed in campaign responses.
Only hashed identifiers, statistics, and scrubbed metadata are returned.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CampaignStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class ClusterRequest(BaseModel):
    """Request to cluster a single message into the campaign graph."""
    model_config = ConfigDict(extra="forbid")

    # Message content for embedding (not stored or logged)
    message: str = Field(..., min_length=1, max_length=5000)
    normalized_text: Optional[str] = Field(default=None, max_length=5000)

    # Pre-computed metadata from analysis pipeline
    scam_family: str = Field(default="UNKNOWN", max_length=50)
    language: str = Field(default="en", max_length=20)
    risk_score: int = Field(default=0, ge=0, le=100)

    # Structural indicators
    domains: List[str] = Field(default_factory=list, max_length=20)
    sender_ids: List[str] = Field(default_factory=list, max_length=10)
    phone_numbers: List[str] = Field(default_factory=list, max_length=10)
    upi_ids: List[str] = Field(default_factory=list, max_length=10)

    # Deduplication
    content_hash: Optional[str] = Field(default=None, max_length=64)
    analysis_id: Optional[str] = Field(default=None, max_length=64)


class ClusterResult(BaseModel):
    """Result of a single message's campaign cluster assignment."""
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    is_new_campaign: bool
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    campaign_confidence: float = Field(..., ge=0.0, le=1.0)
    association_confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    dna_hash: Optional[str] = Field(default=None, description="Scam DNA fingerprint hash ('dna_<hash16>')")
    member_count: int
    scam_family: str


class CampaignMember(BaseModel):
    """A single campaign member record. Raw text is NEVER included."""
    model_config = ConfigDict(extra="forbid")

    member_id: str
    content_hash: str
    analysis_id: Optional[str] = None
    scam_family: str
    language: str
    risk_score: int
    similarity_to_centroid: float
    joined_at: datetime


class CampaignSummary(BaseModel):
    """High-level campaign summary for list views."""
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    scam_family: str
    status: CampaignStatus
    member_count: int
    campaign_confidence: float
    dominant_language: str
    top_domains: List[str]
    first_seen: datetime
    last_seen: datetime


class CampaignDetail(BaseModel):
    """Full campaign detail including statistics. No raw message text."""
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    scam_family: str
    status: CampaignStatus
    member_count: int
    campaign_confidence: float
    dominant_language: str
    language_distribution: Dict[str, int]
    top_domains: List[str]
    sender_ids: List[str]
    avg_risk_score: float
    first_seen: datetime
    last_seen: datetime
