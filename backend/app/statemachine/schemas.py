"""
Scam Conversation State Machine — Schemas.

Defines states, transitions, and structured output types.
All probabilistic language is explicit: "likely next step" not "will do".
"""

from __future__ import annotations

import enum
import html
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── States ─────────────────────────────────────────────────────────────────────

class ScamState(str, enum.Enum):
    """
    Ordered stages of a scam conversation lifecycle.
    Not every scam traverses every stage.
    """
    CONTACT          = "CONTACT"
    TRUST_BUILDING   = "TRUST_BUILDING"
    AUTHORITY_CLAIM  = "AUTHORITY_CLAIM"
    FEAR_OR_URGENCY  = "FEAR_OR_URGENCY"
    CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    PAYMENT_REQUEST  = "PAYMENT_REQUEST"
    REMOTE_ACCESS    = "REMOTE_ACCESS"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    EXIT             = "EXIT"
    UNKNOWN          = "UNKNOWN"


# Canonical ordering index (for progression detection)
STATE_ORDER: Dict[ScamState, int] = {
    ScamState.CONTACT:            0,
    ScamState.TRUST_BUILDING:     1,
    ScamState.AUTHORITY_CLAIM:    2,
    ScamState.FEAR_OR_URGENCY:    3,
    ScamState.CREDENTIAL_REQUEST: 4,
    ScamState.PAYMENT_REQUEST:    5,
    ScamState.REMOTE_ACCESS:      6,
    ScamState.ACCOUNT_TAKEOVER:   7,
    ScamState.EXIT:               8,
    ScamState.UNKNOWN:            -1,
}


# ── Input Schemas ──────────────────────────────────────────────────────────────

class ConversationMessage(BaseModel):
    """A single message in a potentially multi-message conversation."""
    model_config = ConfigDict(extra="forbid")

    message_id: Optional[str] = Field(None, max_length=64)
    text: str = Field(..., min_length=1, max_length=5000)
    sender_id: Optional[str] = Field(None, max_length=50)
    timestamp: Optional[datetime] = None
    is_from_scammer: Optional[bool] = Field(
        None,
        description="If known: True = scammer side, False = victim side. None = unknown.",
    )

    @field_validator("text", mode="before")
    @classmethod
    def sanitize_text(cls, v: str) -> str:
        return html.escape(str(v).strip())


class ConversationAnalysisRequest(BaseModel):
    """
    Request to analyze a conversation (single or multiple messages).
    Messages are ordered by timestamp when provided; otherwise by list order.
    """
    model_config = ConfigDict(extra="forbid")

    conversation_id: Optional[str] = Field(None, max_length=64)
    messages: List[ConversationMessage] = Field(
        ...,
        min_length=1,
        max_length=100,  # DoS cap: max 100 messages per analysis
        description="Ordered list of messages. Maximum 100 per request.",
    )


# ── Output Schemas ─────────────────────────────────────────────────────────────

class StateEvidence(BaseModel):
    """A piece of evidence supporting a detected state or transition."""
    model_config = ConfigDict(extra="forbid")

    signal: str = Field(..., description="Name of the signal or detector.")
    description: str = Field(..., description="Human-readable explanation.")
    confidence_contribution: float = Field(..., ge=0.0, le=1.0)


class DetectedTransition(BaseModel):
    """A detected state transition between two consecutive messages."""
    model_config = ConfigDict(extra="forbid")

    from_state: ScamState
    to_state: ScamState
    confidence: float = Field(..., ge=0.0, le=1.0)
    trigger_signal: str = Field(..., description="Primary signal that triggered the transition.")


class MessageStateResult(BaseModel):
    """State analysis result for a single message."""
    model_config = ConfigDict(extra="forbid")

    message_index: int
    message_id: Optional[str] = None
    assigned_state: ScamState
    state_confidence: float = Field(..., ge=0.0, le=1.0)
    supporting_evidence: List[StateEvidence] = Field(default_factory=list)
    signal_scores: Dict[str, float] = Field(default_factory=dict)


class ConversationAnalysisResult(BaseModel):
    """
    Full state-machine analysis of an ordered message conversation.
    Probabilistic language is used throughout (likelihood, not certainty).
    """
    model_config = ConfigDict(extra="forbid")

    conversation_id: Optional[str] = None
    message_count: int
    current_state: ScamState
    previous_states: List[ScamState] = Field(default_factory=list)
    overall_confidence: float = Field(..., ge=0.0, le=1.0)
    detected_transitions: List[DetectedTransition] = Field(default_factory=list)
    likely_next_state: Optional[ScamState] = Field(
        None,
        description="Probabilistic estimate only — not a certainty.",
    )
    likely_next_state_reasoning: str = Field(
        default="",
        description="Explanation using probabilistic language (e.g. 'Likely next step').",
    )
    per_message_results: List[MessageStateResult] = Field(default_factory=list)
    is_scam_progression_detected: bool = Field(
        False,
        description="True if 2+ consecutive scam states are detected.",
    )
    scam_advancement_score: float = Field(
        0.0, ge=0.0, le=1.0,
        description="0.0 = no progression, 1.0 = full scam funnel completed.",
    )
    warnings: List[str] = Field(default_factory=list)
