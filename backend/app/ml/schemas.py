from __future__ import annotations

import enum

from pydantic import BaseModel, Field

from app.core.text.schemas import TextAnalysisResult


class ScamCategory(str, enum.Enum):
    """The 11 target classes for the ML classification system."""

    SAFE = "SAFE"
    BANK_KYC = "BANK_KYC"
    UPI_PAYMENT = "UPI_PAYMENT"
    COURIER = "COURIER"
    TELECOM = "TELECOM"
    GOVERNMENT = "GOVERNMENT"
    JOB = "JOB"
    LOTTERY = "LOTTERY"
    LOAN_INVESTMENT = "LOAN_INVESTMENT"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    OTHER_SCAM = "OTHER_SCAM"


class InferenceRequest(BaseModel):
    """Payload for requesting an ML analysis."""

    text: str = Field(..., description="The raw SMS text to analyze.")
    phone_number: str | None = Field(None, description="Optional sender ID for correlation.")


class InferenceResponse(BaseModel):
    """The final ML response combining text normalization and model output."""

    # Normalization metadata
    text_analysis: TextAnalysisResult = Field(..., description="Details of text normalization")
    
    # ML Outputs
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Normalized risk score (0=safe, 1=malicious)")
    risk_level: str = Field(..., description="SAFE, SUSPICIOUS, or MALICIOUS based on threshold")
    scam_family: ScamCategory | None = Field(None, description="Specific scam category if not SAFE")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence in the prediction")
    
    model_version: str = Field(..., description="Pinned model artifact version")
    is_low_confidence: bool = Field(False, description="True if the prediction fell below the confidence threshold")
