"""
Composite message feature vector for campaign clustering.

Assembles semantic embedding + structural metadata into the full
representation used for similarity comparison and campaign grouping.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np

from app.campaigns.embedder import EMBEDDING_DIM, embed_text, validate_embedding
from app.campaigns.schemas import ClusterRequest

# Scam family one-hot encoding (must match ScamFamily enum order)
_SCAM_FAMILIES = [
    "SAFE", "BANK_KYC", "UPI_PAYMENT", "COURIER", "TELECOM",
    "GOVERNMENT", "JOB", "LOTTERY", "LOAN_INVESTMENT",
    "REMOTE_ACCESS", "OTHER_SCAM", "UNKNOWN",
]

_LANGUAGE_WEIGHTS = {
    "hi": 1.0, "hinglish": 1.0, "en": 1.0, "unknown": 0.5,
}


@dataclass
class MessageFeatureVector:
    """
    Full composite feature vector for a single message.

    embedding: 384-d semantic vector from sentence-transformers
    scam_family: string label
    language: ISO-like language tag
    url_count, phone_count, upi_count: structural indicator counts
    domains: extracted domain list
    sender_ids: extracted DLT sender ID list
    content_hash: SHA-256 of original text for deduplication
    """

    embedding: np.ndarray
    scam_family: str
    language: str
    risk_score: int
    url_count: int = 0
    phone_count: int = 0
    upi_count: int = 0
    domains: List[str] = field(default_factory=list)
    sender_ids: List[str] = field(default_factory=list)
    content_hash: str = ""
    analysis_id: Optional[str] = None

    def is_valid(self) -> bool:
        return validate_embedding(self.embedding)


def build_feature_vector(request: ClusterRequest) -> MessageFeatureVector:
    """
    Build a MessageFeatureVector from a ClusterRequest.

    Uses the normalized_text if available (preferred — already de-obfuscated),
    otherwise falls back to the raw message text for embedding.
    """
    embed_input = request.normalized_text or request.message
    embedding = embed_text(embed_input)

    # Content hash for deduplication (hash of the raw message, not logged)
    content_hash = request.content_hash
    if not content_hash:
        content_hash = hashlib.sha256(
            request.message.encode("utf-8", errors="replace")
        ).hexdigest()

    return MessageFeatureVector(
        embedding=embedding,
        scam_family=request.scam_family,
        language=request.language,
        risk_score=request.risk_score,
        url_count=len(request.domains),
        phone_count=len(request.phone_numbers),
        upi_count=len(request.upi_ids),
        domains=list(request.domains)[:20],
        sender_ids=list(request.sender_ids)[:10],
        content_hash=content_hash,
        analysis_id=request.analysis_id,
    )
