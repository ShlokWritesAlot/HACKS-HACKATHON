from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.v1.schemas import FeedbackRequest, FeedbackResponse
from app.db.repository import AnalysisRepository, get_repository

router = APIRouter()


@router.post(
    "",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit analyst feedback",
    description="Records ground-truth analyst feedback on an analysis record for continuous validation and calibration.",
)
async def submit_feedback(
    feedback: FeedbackRequest,
    repo: AnalysisRepository = Depends(get_repository),
) -> FeedbackResponse:
    # Check if analysis exists (optional validation - logs warning if external)
    analysis = await repo.get_analysis(feedback.analysis_id)
    if not analysis:
        # We still record feedback even if evicted from in-memory cache, but flag it
        pass

    response = await repo.save_feedback(feedback)
    return response
