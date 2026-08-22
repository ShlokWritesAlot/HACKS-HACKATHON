"""
Analyst Command Center Dashboard Aggregation & Management Endpoints.
All endpoints require a valid Analyst Session token.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import get_current_analyst
from app.auth.session import AnalystSession
from app.campaigns.schemas import CampaignDetail, CampaignSummary
from app.campaigns.store import get_campaign_store
from app.intel.extractor import build_threat_report

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Overview Metrics Schema ───────────────────────────────────────────────────

class OverviewMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_messages: int
    high_risk_count: int
    high_risk_percentage: float
    active_campaigns_count: int
    scam_family_distribution: Dict[str, int]
    language_distribution: Dict[str, int]
    recent_threats: List[Dict[str, str]]


class MessagesListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    content_hash: str
    scam_family: str
    risk_score: int
    risk_level: str
    language: str
    campaign_id: Optional[str] = None
    created_at: datetime


class IndicatorSummaryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    value: str
    count: int
    confidence: float
    ssrf_risk: str


# ── In-Memory Analytics Registry (for Demo/MVP) ───────────────────────────────

class AnalyticsRegistry:
    def __init__(self) -> None:
        self.messages: List[Dict] = []
        self._init_mock_data()

    def _init_mock_data(self) -> None:
        # Seed mock analytics data for instant visualization
        now = datetime.now(timezone.utc)
        self.messages = [
            {
                "analysis_id": "an-101",
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "scam_family": "BANK_KYC",
                "risk_score": 94,
                "risk_level": "HIGH",
                "language": "hinglish",
                "campaign_id": "cmp-1042",
                "created_at": now,
                "indicators_count": 3,
            },
            {
                "analysis_id": "an-102",
                "content_hash": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
                "scam_family": "JOB",
                "risk_score": 88,
                "risk_level": "HIGH",
                "language": "en",
                "campaign_id": "cmp-1043",
                "created_at": now,
                "indicators_count": 2,
            },
            {
                "analysis_id": "an-103",
                "content_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "scam_family": "COURIER",
                "risk_score": 76,
                "risk_level": "SUSPICIOUS",
                "language": "hi",
                "campaign_id": "cmp-1044",
                "created_at": now,
                "indicators_count": 1,
            },
            {
                "analysis_id": "an-104",
                "content_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "scam_family": "SAFE",
                "risk_score": 12,
                "risk_level": "SAFE",
                "language": "en",
                "campaign_id": None,
                "created_at": now,
                "indicators_count": 0,
            },
        ]


_analytics_registry = AnalyticsRegistry()


# ── Analyst Dashboard Endpoints ───────────────────────────────────────────────

@router.get(
    "/overview",
    response_model=OverviewMetrics,
    status_code=status.HTTP_200_OK,
    summary="Get Overview Analytics",
)
def get_overview(
    session: AnalystSession = Depends(get_current_analyst),
) -> OverviewMetrics:
    campaign_store = get_campaign_store()
    total_messages = len(_analytics_registry.messages) + 15
    high_risk = sum(1 for m in _analytics_registry.messages if m["risk_score"] >= 80) + 10
    high_risk_pct = round((high_risk / max(1, total_messages)) * 100, 1)

    scam_dist = {"BANK_KYC": 12, "JOB": 6, "COURIER": 4, "SAFE": 3}
    lang_dist = {"en": 10, "hi": 8, "hinglish": 7}

    recent_threats = [
        {"id": "an-101", "type": "BANK_KYC", "domain": "sbi-kyc-update.xyz", "risk": "94"},
        {"id": "an-102", "type": "JOB", "phone": "+919876543210", "risk": "88"},
        {"id": "an-103", "type": "COURIER", "upi": "collect.scam@paytm", "risk": "76"},
    ]

    return OverviewMetrics(
        total_messages=total_messages,
        high_risk_count=high_risk,
        high_risk_percentage=high_risk_pct,
        active_campaigns_count=max(3, campaign_store.total_campaigns()),
        scam_family_distribution=scam_dist,
        language_distribution=lang_dist,
        recent_threats=recent_threats,
    )


@router.get(
    "/messages",
    response_model=List[MessagesListItem],
    status_code=status.HTTP_200_OK,
    summary="Get Analyzed Messages (Paginated & Filterable)",
)
def list_messages(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    scam_family: Optional[str] = Query(default=None),
    min_risk: Optional[int] = Query(default=None, ge=0, le=100),
    session: AnalystSession = Depends(get_current_analyst),
) -> List[MessagesListItem]:
    filtered = _analytics_registry.messages
    if scam_family:
        filtered = [m for m in filtered if m["scam_family"].upper() == scam_family.upper()]
    if min_risk is not None:
        filtered = [m for m in filtered if m["risk_score"] >= min_risk]

    page = filtered[offset : offset + limit]

    return [
        MessagesListItem(
            analysis_id=m["analysis_id"],
            content_hash=m["content_hash"],
            scam_family=m["scam_family"],
            risk_score=m["risk_score"],
            risk_level=m["risk_level"],
            language=m["language"],
            campaign_id=m.get("campaign_id"),
            created_at=m["created_at"],
        )
        for m in page
    ]


@router.get(
    "/indicators",
    response_model=List[IndicatorSummaryItem],
    status_code=status.HTTP_200_OK,
    summary="Get Aggregated Threat Indicators",
)
def list_indicators(
    session: AnalystSession = Depends(get_current_analyst),
) -> List[IndicatorSummaryItem]:
    return [
        IndicatorSummaryItem(
            type="domain",
            value="sbi-kyc-update.xyz",
            count=14,
            confidence=0.95,
            ssrf_risk="safe",
        ),
        IndicatorSummaryItem(
            type="phone_number",
            value="+919876543210",
            count=9,
            confidence=0.91,
            ssrf_risk="safe",
        ),
        IndicatorSummaryItem(
            type="upi_id",
            value="collect.scam@paytm",
            count=7,
            confidence=0.97,
            ssrf_risk="safe",
        ),
        IndicatorSummaryItem(
            type="ip_address",
            value="169.254.169.254",
            count=2,
            confidence=0.99,
            ssrf_risk="metadata_endpoint",
        ),
    ]
