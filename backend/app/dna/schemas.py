"""
Scam DNA & Campaign Fingerprint Schemas for BhashaRakshak.

PRIVACY INVARIANT:
  Raw SMS text is NEVER stored in ScamDNAFingerprint or included in dna_hash.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.ml.schemas import ScamCategory


class ScamDNAFingerprint(BaseModel):
    """
    16-Dimensional Structured Scam DNA Fingerprint.
    Represents a stable structural signature of a scam campaign independent of exact text.
    """
    model_config = ConfigDict(extra="forbid")

    version: str = Field(default="1.0.0-dna", description="Fingerprint schema version.")
    dna_hash: str = Field(..., description="Deterministic SHA-256 hash of normalized structural features ('dna_<hash16>').")
    scam_archetype: ScamCategory = Field(..., description="Target scam category archetype.")
    pressure_profile: Dict[str, float] = Field(
        ...,
        description="7-dimensional psychological pressure vector (fear, urgency, authority, etc.).",
    )
    language: str = Field(..., description="Detected language code (e.g. 'en', 'hi', 'hinglish').")
    script: str = Field(..., description="Detected script type (e.g. 'latin', 'devanagari', 'mixed').")
    linguistic_structure: Dict[str, Any] = Field(
        ...,
        description="Linguistic metrics (word_count, sentence_count, has_imperatives).",
    )
    impersonated_organization: str = Field(..., description="Target brand or authority impersonated (e.g. 'SBI', 'NONE').")
    url_characteristics: Dict[str, Any] = Field(
        ...,
        description="URL features (has_url, url_count, tlds, has_homoglyph, is_shortener).",
    )
    phone_indicators: Dict[str, Any] = Field(
        ...,
        description="Phone number features (has_phone, phone_count, country_codes).",
    )
    upi_characteristics: Dict[str, Any] = Field(
        ...,
        description="UPI payment features (has_vpa, vpa_count, psp_handles).",
    )
    sender_id: Optional[str] = Field(None, description="Normalized DLT Sender ID header if present.")
    monetary_request_characteristics: Dict[str, Any] = Field(
        ...,
        description="Monetary request indicators (has_amount, currency_symbols).",
    )
    obfuscation_techniques: List[str] = Field(
        default_factory=list,
        description="Sorted list of detected obfuscation techniques.",
    )
    message_structure: str = Field(
        ...,
        description="Abstract structural template pattern (e.g. 'HEADER+IMPERSONATION+URGENCY+LINK').",
    )
    extracted_entities: List[str] = Field(
        default_factory=list,
        description="Sorted list of extracted IOC hashes/values for entity matching.",
    )
    semantic_embedding: List[float] = Field(
        ...,
        description="384-dimensional dense semantic embedding vector.",
    )
    temporal_characteristics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Temporal metadata (time_window_hour, creation_bucket).",
    )
