"""
Brand & Government Impersonation Detection Schemas.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LegitimateReferenceInformation(BaseModel):
    """Verified reference details for an organization."""
    model_config = ConfigDict(extra="forbid")

    canonical_name: str = Field(..., description="Official canonical name.")
    category: str = Field(..., description="Industry category.")
    legitimate_domains: List[str] = Field(..., description="Verified official domain names.")
    verified_sender_ids: List[str] = Field(..., description="Official verified DLT sender ID headers.")
    official_support_url: str = Field(..., description="Verified official support website.")


class BrandImpersonationResult(BaseModel):
    """Structured brand/government impersonation analysis report."""
    model_config = ConfigDict(extra="forbid")

    claimed_brand: Optional[str] = Field(None, description="Canonical name of claimed organization if detected.")
    impersonation_detected: bool = Field(..., description="True if malicious brand impersonation was detected.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score (0.0 to 1.0).")
    supporting_evidence: List[str] = Field(default_factory=list, description="Forensic evidence items explaining the decision.")
    legitimate_reference_information: Optional[LegitimateReferenceInformation] = Field(
        None, description="Verified official reference guidance if brand claim was detected."
    )

    @field_validator("supporting_evidence", mode="before")
    @classmethod
    def sanitize_evidence(cls, v: List[str]) -> List[str]:
        if not v:
            return []
        return [html.escape(str(item).strip()) for item in v]
