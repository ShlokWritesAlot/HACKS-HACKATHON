from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.evidence.schemas import StructuredEvidenceItem
from app.xray.schemas import ManipulationFingerprint, RiskLevelEnum


class AnalyzeRequest(BaseModel):
    """Input payload for a single SMS message analysis."""
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The suspicious SMS text to analyze (1 to 5000 characters).",
        examples=["URGENT: Your SBI account has been blocked. Click bit.ly/unblock-sbi now."],
    )
    sender_id: Optional[str] = Field(
        None,
        max_length=50,
        description="Optional sender identifier / shortcode (e.g. 'AX-SBIINB').",
    )


class AnalyzeResponse(BaseModel):
    """Structured response containing all Scam X-Ray analysis dimensions."""
    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the persisted analysis record.",
    )
    risk_score: int = Field(..., ge=0, le=100, description="Composite risk score from 0 (safe) to 100 (critical).")
    risk_level: str = Field(..., description="Categorical risk tier: SAFE, LOW, MEDIUM, HIGH, CRITICAL.")
    scam_family: str = Field(..., description="Identified scam archetype or SAFE.")
    language: str = Field(..., description="Detected language code (e.g. 'en', 'hi', 'hinglish').")
    original_text: str = Field(..., description="Original raw SMS message.")
    normalized_text: str = Field(..., description="Cleaned, de-obfuscated text.")
    decoded_meaning: str = Field(..., description="Plain-language breakdown of attacker intent.")
    manipulation_fingerprint: ManipulationFingerprint = Field(..., description="Normalized psychological manipulation vector.")
    obfuscation_fingerprint: List[str] = Field(default_factory=list, description="List of detected obfuscation techniques.")
    evidence: List[str] = Field(default_factory=list, description="Verifiable facts and extracted elements observed directly in text.")
    structured_evidence: List[StructuredEvidenceItem] = Field(default_factory=list, description="Structured explainable evidence items with category, detector, confidence, and severity contribution.")
    uncertainty: float = Field(default=0.05, ge=0.0, le=1.0, description="Epistemic uncertainty score (1.0 - confidence).")
    safe_action: str = Field(..., description="Protective action recommended to the recipient.")
    model_version: str = Field(default="v1.0.0-xray", description="Version of the model/engine used for analysis.")

    # Enriched Subsystem Intelligence Payloads
    extracted_iocs: List[dict] = Field(default_factory=list, description="Extracted threat indicators (URLs, domains, IPs, phone, email, UPI, sender IDs).")
    brand_impersonation: Optional[dict] = Field(default=None, description="Brand and government impersonation telemetry.")
    conversation_state: Optional[dict] = Field(default=None, description="Scam state machine progression & next-step predictions.")
    scam_dna: Optional[dict] = Field(default=None, description="16-dimensional Scam DNA campaign fingerprint.")


class BatchAnalyzeRequest(BaseModel):
    """Input payload for batch SMS analysis."""
    model_config = ConfigDict(extra="forbid")

    messages: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of SMS messages to analyze (1 to 50 items per batch).",
    )


class BatchAnalyzeResponse(BaseModel):
    """Batch analysis results envelope."""
    model_config = ConfigDict(extra="forbid")

    results: List[AnalyzeResponse] = Field(..., description="List of individual analysis results.")
    total_processed: int = Field(..., description="Total count of successfully analyzed messages.")


class FeedbackRequest(BaseModel):
    """Analyst / User feedback submission schema."""
    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(..., description="UUID of the analysis record being reviewed.")
    is_correct: bool = Field(..., description="True if classification was accurate; False if False Positive/Negative.")
    comment: Optional[str] = Field(None, max_length=1000, description="Optional analyst notes or correction details.")
    analyst_id: Optional[str] = Field(None, max_length=100, description="Optional identifier of the reviewing analyst.")


class FeedbackResponse(BaseModel):
    """Feedback submission acknowledgment."""
    model_config = ConfigDict(extra="forbid")

    feedback_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str
    status: str = "recorded"
    recorded_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
