from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from app.api.v1.schemas import AnalyzeResponse, FeedbackRequest, FeedbackResponse


class AnalysisRepository:
    """
    Thread-safe repository managing analysis persistence and retrieval.
    Includes in-memory cache fallback for high performance and offline resilience.
    """

    def __init__(self):
        self._analyses: Dict[str, AnalyzeResponse] = {}
        self._feedback: Dict[str, FeedbackResponse] = {}
        self._lock = asyncio.Lock()

    async def save_analysis(self, analysis: AnalyzeResponse) -> None:
        async with self._lock:
            self._analyses[analysis.analysis_id] = analysis

    async def get_analysis(self, analysis_id: str) -> Optional[AnalyzeResponse]:
        async with self._lock:
            return self._analyses.get(analysis_id)

    async def save_feedback(self, feedback_req: FeedbackRequest) -> FeedbackResponse:
        async with self._lock:
            resp = FeedbackResponse(analysis_id=feedback_req.analysis_id)
            self._feedback[resp.feedback_id] = resp
            return resp

    async def list_feedback_for_analysis(self, analysis_id: str) -> List[FeedbackResponse]:
        async with self._lock:
            return [f for f in self._feedback.values() if f.analysis_id == analysis_id]


# Singleton instance
_repo_instance = AnalysisRepository()


def get_repository() -> AnalysisRepository:
    return _repo_instance
