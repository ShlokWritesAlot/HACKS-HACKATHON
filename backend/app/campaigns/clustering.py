"""
Campaign clustering engine for BhashaRakshak.

Orchestrates: feature extraction → similarity search → create/join campaign.

Thread safety: uses the store's internal RLock for all mutations.
"""

from __future__ import annotations

import logging

from app.campaigns.features import MessageFeatureVector
from app.campaigns.schemas import ClusterRequest, ClusterResult
from app.campaigns.store import InMemoryCampaignStore, get_campaign_store

logger = logging.getLogger(__name__)


from app.campaigns.features import MessageFeatureVector
from app.campaigns.schemas import ClusterRequest, ClusterResult
from app.campaigns.store import InMemoryCampaignStore, get_campaign_store
from app.dna.builder import ScamDNABuilder
from app.dna.similarity import ScamDNASimilarityEngine
from app.ml.schemas import ScamCategory

logger = logging.getLogger(__name__)


class CampaignClusteringEngine:
    """
    Assigns a message to the best matching campaign using multi-factor Scam DNA similarity,
    or creates a new campaign if no fingerprint match exceeds threshold.
    """

    def __init__(self, store: InMemoryCampaignStore | None = None):
        self._store = store or get_campaign_store()
        self._dna_builder = ScamDNABuilder()
        self._dna_similarity_engine = ScamDNASimilarityEngine()

    def cluster(self, features: MessageFeatureVector, request: ClusterRequest) -> ClusterResult:
        """
        Cluster a message feature vector and return the campaign assignment.
        """
        if not features.is_valid():
            raise ValueError("Invalid feature vector: embedding failed validation.")

        # Map scam family string to enum
        try:
            scam_archetype = ScamCategory(features.scam_family)
        except ValueError:
            scam_archetype = ScamCategory.OTHER_SCAM

        # Extract IOC entities list
        extracted_iocs = []
        for d in features.domains:
            extracted_iocs.append({"value": d, "type": "domain"})
        for u in request.upi_ids:
            extracted_iocs.append({"value": u, "type": "upi"})
        for p in request.phone_numbers:
            extracted_iocs.append({"value": p, "type": "phone"})

        # Build Scam DNA Fingerprint
        dna_fingerprint = self._dna_builder.build_dna(
            raw_text=request.message,
            cleaned_text=request.normalized_text or request.message,
            scam_archetype=scam_archetype,
            manipulation_dict={
                "fear": 0.8 if features.risk_score >= 80 else 0.4,
                "urgency": 0.8 if features.risk_score >= 70 else 0.3,
                "authority_impersonation": 0.8 if len(features.sender_ids) > 0 else 0.2,
                "financial_request": 0.8 if request.upi_ids else 0.2,
                "credential_request": 0.7 if "KYC" in features.scam_family else 0.2,
                "suspicious_link": 0.9 if features.domains else 0.1,
                "call_to_action_pressure": 0.7,
            },
            obfuscations=[],
            extracted_iocs=extracted_iocs,
            sender_id=features.sender_ids[0] if features.sender_ids else None,
            embedding=features.embedding,
        )

        # 1. Exact duplicate check
        existing_campaign_id = self._store.is_duplicate(features.content_hash)
        if existing_campaign_id:
            rec = self._store.get_campaign(existing_campaign_id)
            if rec:
                logger.debug("Duplicate message hash, returning existing campaign %s", existing_campaign_id[:8])
                return ClusterResult(
                    campaign_id=existing_campaign_id,
                    is_new_campaign=False,
                    similarity_score=1.0,
                    campaign_confidence=rec.campaign_confidence,
                    association_confidence=1.0,
                    dna_hash=dna_fingerprint.dna_hash,
                    member_count=rec.member_count,
                    scam_family=rec.scam_family,
                )

        # 2. Scam DNA multi-factor similarity search
        match = self._store.find_similar_campaign(
            embedding=features.embedding,
            scam_family=features.scam_family,
        )

        if match:
            campaign_id, similarity = match
            rec = self._store.add_member(
                campaign_id=campaign_id,
                embedding=features.embedding,
                language=features.language,
                domains=features.domains,
                sender_ids=features.sender_ids,
                risk_score=features.risk_score,
                content_hash=features.content_hash,
                analysis_id=features.analysis_id,
                similarity=similarity,
            )
            logger.info(
                "Message joined campaign %s (sim=%.3f, members=%d)",
                campaign_id[:8], similarity, rec.member_count,
            )
            return ClusterResult(
                campaign_id=campaign_id,
                is_new_campaign=False,
                similarity_score=round(similarity, 4),
                campaign_confidence=rec.campaign_confidence,
                association_confidence=round(similarity * 0.95, 2),
                dna_hash=dna_fingerprint.dna_hash,
                member_count=rec.member_count,
                scam_family=rec.scam_family,
            )

        # 3. No match — create new campaign
        rec = self._store.create_campaign(
            embedding=features.embedding,
            scam_family=features.scam_family,
            language=features.language,
            domains=features.domains,
            sender_ids=features.sender_ids,
            risk_score=features.risk_score,
            content_hash=features.content_hash,
            analysis_id=features.analysis_id,
        )

        return ClusterResult(
            campaign_id=rec.campaign_id,
            is_new_campaign=True,
            similarity_score=1.0,
            campaign_confidence=1.0,
            association_confidence=1.0,
            dna_hash=dna_fingerprint.dna_hash,
            member_count=1,
            scam_family=features.scam_family,
        )


# ── Singleton ──────────────────────────────────────────────────────────────────

_engine_instance: CampaignClusteringEngine | None = None


def get_clustering_engine() -> CampaignClusteringEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CampaignClusteringEngine()
    return _engine_instance
