from __future__ import annotations

import enum
import re
from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.evidence.schemas import StructuredEvidenceItem
from app.ml.schemas import ScamCategory


class RiskLevelEnum(str, enum.Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ManipulationFingerprint(BaseModel):
    """Normalized manipulation vector across 7 key psychological pressure dimensions."""
    model_config = ConfigDict(extra="forbid")

    fear: float = Field(default=0.0, ge=0.0, le=1.0, description="Threat of account suspension, legal action, or arrest")
    urgency: float = Field(default=0.0, ge=0.0, le=1.0, description="Time pressure (e.g. within 24 hours, immediate, expiring)")
    authority_impersonation: float = Field(default=0.0, ge=0.0, le=1.0, description="Pretending to be bank, police, courier, telecom, or government")
    financial_request: float = Field(default=0.0, ge=0.0, le=1.0, description="Direct/indirect request for money, fee, fine, or deposit")
    credential_request: float = Field(default=0.0, ge=0.0, le=1.0, description="Request for OTP, password, PIN, CVV, or personal documents")
    suspicious_link: float = Field(default=0.0, ge=0.0, le=1.0, description="Presence of obfuscated, shortened, or unverified URLs/APKs")
    call_to_action_pressure: float = Field(default=0.0, ge=0.0, le=1.0, description="Forced direct action (click, call, forward, download)")


class SafeActionRecommendation(str, enum.Enum):
    DO_NOT_CLICK = "DO_NOT_CLICK"
    OPEN_OFFICIAL_APP_OR_SITE = "Open the organization's official app/site manually. Do not click any link."
    DO_NOT_SHARE_OTP = "Never share OTP, PIN, or banking passwords with anyone."
    VERIFY_WITH_OFFICIAL_SUPPORT = "Contact customer support through their verified official website or mobile app only."
    DELETE_AND_BLOCK = "Delete the message and block the sender."
    SAFE_NO_ACTION = "Message appears legitimate. No protective action required."


class ScamXRayResponse(BaseModel):
    """Structured Scam X-Ray output schema."""
    model_config = ConfigDict(extra="forbid")

    original_text: str = Field(..., description="Original raw suspicious SMS")
    cleaned_text: str = Field(..., description="Normalized and de-obfuscated SMS text")
    decoded_meaning: str = Field(..., description="Plain-language breakdown of what the message is attempting to achieve")
    scam_family: ScamCategory = Field(..., description="Identified scam archetype or SAFE")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score between 0 (safe) and 100 (critical scam)")
    risk_level: RiskLevelEnum = Field(..., description="Categorical risk tier: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    manipulation: ManipulationFingerprint = Field(..., description="Psychological manipulation fingerprint")
    obfuscation: List[str] = Field(default_factory=list, description="List of detected obfuscation techniques applied in the message")
    evidence: List[str] = Field(default_factory=list, description="Verifiable facts and extracted elements observed directly in text")
    structured_evidence: List[StructuredEvidenceItem] = Field(default_factory=list, description="Structured explainable evidence items with category, detector, confidence, and severity contribution.")
    uncertainty: float = Field(default=0.05, ge=0.0, le=1.0, description="Epistemic uncertainty score (1.0 - confidence).")
    recommended_action: str = Field(
        default=SafeActionRecommendation.OPEN_OFFICIAL_APP_OR_SITE.value,
        description="Actionable safety guidance for the recipient"
    )

    @field_validator("recommended_action")
    @classmethod
    def validate_safe_action(cls, v: str) -> str:
        # AI Safety check: Ensure the recommendation NEVER advises calling a phone number
        phone_call_pattern = re.compile(r"(call|dial|ring|contact)\s+(the\s+)?(number|sender|\+?\d+)", re.IGNORECASE)
        if phone_call_pattern.search(v) and "official" not in v.lower():
            raise ValueError("Unsafe recommendation: Must never recommend calling unverified numbers from SMS.")
        return v
