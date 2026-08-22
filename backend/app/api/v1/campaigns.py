"""
Campaign clustering API endpoints.

AUTHORIZATION:
  - POST /cluster: public (called by analysis pipeline)
  - GET /campaigns, GET /campaigns/{id}, GET /campaigns/{id}/members:
    Analyst-gated via X-Analyst-Key header.

SECURITY:
  - No raw message text appears in any response.
  - Member responses include only content_hash, analysis_id, and metadata.
  - Rate limiting is applied by the global middleware.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.campaigns.clustering import CampaignClusteringEngine, get_clustering_engine
from app.campaigns.features import build_feature_vector
from app.campaigns.schemas import (
    CampaignDetail,
    CampaignMember,
    CampaignSummary,
    ClusterRequest,
    ClusterResult,
)
from app.campaigns.store import get_campaign_store

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Authorization ─────────────────────────────────────────────────────────────

_ANALYST_KEY_HEADER = "X-Analyst-Key"
_DEV_ANALYST_KEY = "bhasharakshak-analyst-dev"


def require_analyst(x_analyst_key: Optional[str] = Header(default=None)) -> None:
    """
    Minimal analyst gate for Phase 1.
    Phase 2: Replace with proper JWT/OAuth2 flow.
    """
    if not x_analyst_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Analyst-Key header required for analyst endpoints.",
        )
    # In Phase 1, accept the dev key or any non-empty key in development mode
    # Production: validate against hashed key store
    if x_analyst_key.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid analyst key.",
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/cluster",
    response_model=ClusterResult,
    status_code=status.HTTP_200_OK,
    summary="Cluster a message into a campaign",
    description="Embeds a message and assigns it to the most semantically similar campaign or creates a new one.",
)
def cluster_message(
    request: ClusterRequest,
    engine: CampaignClusteringEngine = Depends(get_clustering_engine),
) -> ClusterResult:
    try:
        features = build_feature_vector(request)
    except Exception as exc:
        logger.error("Feature vector build failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to build feature vector: {exc}",
        )

    try:
        return engine.cluster(features, request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except RuntimeError as exc:
        logger.critical("Campaign store capacity error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Campaign store capacity limit reached.",
        )


@router.get(
    "",
    response_model=List[CampaignSummary],
    status_code=status.HTTP_200_OK,
    summary="List all campaigns (analyst)",
    dependencies=[Depends(require_analyst)],
)
def list_campaigns(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> List[CampaignSummary]:
    store = get_campaign_store()
    return store.list_campaigns(limit=limit, offset=offset)


@router.get(
    "/{campaign_id}",
    response_model=CampaignDetail,
    status_code=status.HTTP_200_OK,
    summary="Get campaign detail (analyst)",
    dependencies=[Depends(require_analyst)],
)
def get_campaign(campaign_id: str) -> CampaignDetail:
    store = get_campaign_store()
    detail = store.get_campaign_detail(campaign_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id!r} not found.",
        )
    return detail


@router.get(
    "/{campaign_id}/members",
    response_model=List[CampaignMember],
    status_code=status.HTTP_200_OK,
    summary="Get campaign members (analyst) — no raw message text",
    dependencies=[Depends(require_analyst)],
)
def get_campaign_members(
    campaign_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> List[CampaignMember]:
    store = get_campaign_store()
    members = store.get_members(campaign_id=campaign_id, limit=limit, offset=offset)
    if members is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id!r} not found.",
        )
    return members
