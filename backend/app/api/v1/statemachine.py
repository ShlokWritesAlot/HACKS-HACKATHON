"""
State Machine & Next-Step Prediction API endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.statemachine.engine import analyze_conversation
from app.statemachine.prediction import NextStepPrediction, predict_next_step
from app.statemachine.schemas import (
    ConversationAnalysisRequest,
    ConversationAnalysisResult,
)

router = APIRouter()


@router.post(
    "/analyze",
    response_model=ConversationAnalysisResult,
    summary="Analyze a scam conversation using the State Machine",
)
def analyze_conversation_endpoint(
    request: ConversationAnalysisRequest,
) -> ConversationAnalysisResult:
    """
    Analyze an ordered list of messages and return the current scam state,
    detected transitions, and likely next state.

    - Maximum 100 messages per request (DoS protection).
    - Timestamps are sorted if provided; reversed timestamps produce a warning.
    - Duplicate messages are deduplicated with a warning.
    - All text is treated as UNTRUSTED DATA.
    """
    return analyze_conversation(request)


@router.post(
    "/predict",
    response_model=NextStepPrediction,
    summary="Predict likely next attacker action from a conversation analysis",
)
def predict_next_action(
    request: ConversationAnalysisRequest,
) -> NextStepPrediction:
    """
    Run the state machine, then predict the most likely attacker next action.

    - Returns NEEDS_REVIEW when overall confidence is below the abstention threshold.
    - All predictions use probabilistic language (\"likely\", \"may\").
    - Never instructs users how to perform harmful actions.
    """
    analysis = analyze_conversation(request)
    return predict_next_step(analysis)
