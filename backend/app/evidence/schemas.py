"""
Structured Evidence Schemas for Explainable Threat Evidence Engine.

SECURITY INVARIANTS:
  - All textual descriptions, source spans, and normalized values MUST be sanitized
    against HTML/JS injection before serialization.
  - Evidence items are strict Pydantic models with extra="forbid".
"""

from __future__ import annotations

import enum
import html
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ml.schemas import ScamCategory


class RiskLevelEnum(str, enum.Enum):
    """Categorical risk tier."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceCategoryEnum(str, enum.Enum):
    """The 10 core threat evidence categories."""

    OTP_REQUEST = "OTP_REQUEST"
    URGENCY_LANGUAGE = "URGENCY_LANGUAGE"
    BANK_IMPERSONATION = "BANK_IMPERSONATION"
    SUSPICIOUS_DOMAIN = "SUSPICIOUS_DOMAIN"
    UPI_REQUEST = "UPI_REQUEST"
    REMOTE_ACCESS = "REMOTE_ACCESS"
    ACCOUNT_BLOCK_THREAT = "ACCOUNT_BLOCK_THREAT"
    CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    HOMOGLYPH_DOMAIN = "HOMOGLYPH_DOMAIN"
    OBFUSCATION_DETECTED = "OBFUSCATION_DETECTED"


class StructuredEvidenceItem(BaseModel):
    """
    Normalized, explainable evidence item.
    Represents a specific, verifiable threat signal observed by a detector.
    """
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., description="Unique evidence item identifier (e.g. 'ev_a1b2c3d4').")
    category: EvidenceCategoryEnum = Field(..., description="Standardized evidence category.")
    detector: str = Field(..., description="Identifier of the specific detector module (e.g. 'regex_bank_impersonation').")
    description: str = Field(..., description="Plain language explanation of the observed signal.")
    severity_contribution: float = Field(..., ge=0.0, le=100.0, description="Contribution to the overall risk score (0 to 100).")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector confidence score (0.0 to 1.0).")
    source_span: Optional[str] = Field(None, description="Sanitized raw text snippet where signal was detected.")
    normalized_value: Optional[str] = Field(None, description="Extracted clean value (e.g. domain, phone, UPI VPA).")
    is_deterministic: bool = Field(..., description="True if derived from rule/pattern/intel; False if ML model derived.")

    @field_validator("description", "source_span", "normalized_value", mode="before")
    @classmethod
    def sanitize_text_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Escape HTML entities to prevent XSS payloads in UI rendering
        return html.escape(str(v).strip())


class ExplainableEvidenceReport(BaseModel):
    """
    Aggregated evidence report explaining the final risk assessment.
    """
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(..., ge=0, le=100, description="Final composite risk score (0 to 100).")
    risk_tier: RiskLevelEnum = Field(..., description="Categorical risk tier (SAFE, LOW, MEDIUM, HIGH, CRITICAL).")
    scam_category: ScamCategory = Field(..., description="Primary identified scam archetype.")
    structured_evidence: List[StructuredEvidenceItem] = Field(
        default_factory=list,
        description="Structured list of verified evidence items explaining the score.",
    )
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Weighted confidence score across all detectors.")
    uncertainty: float = Field(..., ge=0.0, le=1.0, description="Epistemic uncertainty measure (1.0 - overall_confidence).")
