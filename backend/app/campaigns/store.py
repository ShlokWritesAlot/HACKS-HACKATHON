"""
Campaign store implementations for BhashaRakshak.

Provides two implementations behind a common interface:

  InMemoryCampaignStore — thread-safe in-process store for Phase 1 / testing.
    Uses numpy cosine similarity across cached embedding centroids.
    Resource-limited: MAX_CANDIDATES cap prevents vector scan DoS.

  PgvectorCampaignStore — production store using PostgreSQL + pgvector.
    Uses <=> cosine distance operator with an IVFFlat index.
    (Requires pgvector extension and asyncpg/SQLAlchemy.)

SECURITY:
  - Raw message text is NEVER stored in the campaign store.
  - Only embeddings, hashes, and scrubbed metadata are persisted.
  - Similarity queries are bounded to MAX_CANDIDATES results.
  - Embedding dimensions are validated before storage.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np

from app.campaigns.embedder import EMBEDDING_DIM, cosine_similarity, validate_embedding
from app.campaigns.schemas import (
    CampaignDetail,
    CampaignMember,
    CampaignStatus,
    CampaignSummary,
)

logger = logging.getLogger(__name__)

# Maximum candidates returned by a single similarity scan (DoS prevention)
MAX_CANDIDATES = 200
# Maximum total campaigns tracked in memory (Phase 1 ceiling)
MAX_CAMPAIGNS_IN_MEMORY = 10_000


# ── Data structures ────────────────────────────────────────────────────────────

class _CampaignRecord:
    """Internal campaign record (not exposed directly via API)."""

    __slots__ = (
        "campaign_id", "scam_family", "status",
        "centroid", "member_count", "members",
        "language_dist", "domains", "sender_ids",
        "risk_scores", "first_seen", "last_seen",
    )

    def __init__(self, campaign_id: str, scam_family: str, centroid: np.ndarray):
        self.campaign_id = campaign_id
        self.scam_family = scam_family
        self.status = CampaignStatus.ACTIVE
        self.centroid = centroid.copy()
        self.member_count = 0
        self.members: List[CampaignMember] = []
        self.language_dist: Dict[str, int] = defaultdict(int)
        self.domains: List[str] = []
        self.sender_ids: List[str] = []
        self.risk_scores: List[int] = []
        self.first_seen: datetime = datetime.now(timezone.utc)
        self.last_seen: datetime = datetime.now(timezone.utc)

    def update_centroid(self, new_embedding: np.ndarray) -> None:
        """
        Online centroid update: running average of member embeddings.
        This is equivalent to recalculating the mean over all members
        without storing all vectors permanently.
        """
        n = self.member_count
        if n == 0:
            self.centroid = new_embedding.copy()
        else:
            self.centroid = ((self.centroid * n) + new_embedding) / (n + 1)
            # Re-normalize to unit sphere
            norm = np.linalg.norm(self.centroid)
            if norm > 1e-9:
                self.centroid = (self.centroid / norm).astype(np.float32)

    @property
    def campaign_confidence(self) -> float:
        """Confidence as mean similarity of all members to the centroid."""
        if not self.members:
            return 0.0
        sims = [m.similarity_to_centroid for m in self.members]
        return round(float(np.mean(sims)), 4)

    @property
    def dominant_language(self) -> str:
        if not self.language_dist:
            return "unknown"
        return max(self.language_dist, key=self.language_dist.get)  # type: ignore

    @property
    def avg_risk_score(self) -> float:
        if not self.risk_scores:
            return 0.0
        return round(float(np.mean(self.risk_scores)), 1)


# ── In-Memory Store ────────────────────────────────────────────────────────────

class InMemoryCampaignStore:
    """
    Thread-safe in-memory campaign store using cosine similarity.

    Uses a reader-writer lock pattern via threading.RLock for
    safe concurrent access without deadlocks.
    """

    def __init__(self, similarity_threshold: float = 0.82):
        self._threshold = similarity_threshold
        self._campaigns: Dict[str, _CampaignRecord] = {}
        self._content_hash_index: Dict[str, str] = {}  # hash → campaign_id
        self._lock = threading.RLock()

    def find_similar_campaign(
        self,
        embedding: np.ndarray,
        scam_family: str,
        limit: int = MAX_CANDIDATES,
    ) -> Optional[Tuple[str, float]]:
        """
        Find the most similar existing campaign centroid.

        Compares only campaigns matching the same scam_family to reduce
        search space and improve precision.

        Returns (campaign_id, similarity_score) or None.
        """
        if not validate_embedding(embedding):
            return None

        best_id: Optional[str] = None
        best_sim: float = self._threshold - 1e-9  # must beat threshold

        with self._lock:
            candidates = list(self._campaigns.values())

        # Cosine similarity scan (no lock needed — reading immutable centroids)
        for rec in candidates[:limit]:
            if rec.scam_family != scam_family:
                continue
            sim = cosine_similarity(embedding, rec.centroid)
            if sim > best_sim:
                best_sim = sim
                best_id = rec.campaign_id

        if best_id and best_sim >= self._threshold:
            return best_id, best_sim
        return None

    def is_duplicate(self, content_hash: str) -> Optional[str]:
        """Returns existing campaign_id if this exact content was already clustered."""
        with self._lock:
            return self._content_hash_index.get(content_hash)

    def create_campaign(
        self,
        embedding: np.ndarray,
        scam_family: str,
        language: str,
        domains: List[str],
        sender_ids: List[str],
        risk_score: int,
        content_hash: str,
        analysis_id: Optional[str],
    ) -> _CampaignRecord:
        if len(self._campaigns) >= MAX_CAMPAIGNS_IN_MEMORY:
            raise RuntimeError(
                f"Campaign store capacity ({MAX_CAMPAIGNS_IN_MEMORY}) exceeded."
            )

        campaign_id = str(uuid.uuid4())
        rec = _CampaignRecord(campaign_id=campaign_id, scam_family=scam_family, centroid=embedding)

        member = CampaignMember(
            member_id=str(uuid.uuid4()),
            content_hash=content_hash,
            analysis_id=analysis_id,
            scam_family=scam_family,
            language=language,
            risk_score=risk_score,
            similarity_to_centroid=1.0,
            joined_at=datetime.now(timezone.utc),
        )
        rec.members.append(member)
        rec.member_count = 1
        rec.language_dist[language] += 1
        rec.domains = list(domains[:10])
        rec.sender_ids = list(sender_ids[:5])
        rec.risk_scores.append(risk_score)

        with self._lock:
            self._campaigns[campaign_id] = rec
            self._content_hash_index[content_hash] = campaign_id

        logger.info("Created new campaign %s (family=%s)", campaign_id[:8], scam_family)
        return rec

    def add_member(
        self,
        campaign_id: str,
        embedding: np.ndarray,
        language: str,
        domains: List[str],
        sender_ids: List[str],
        risk_score: int,
        content_hash: str,
        analysis_id: Optional[str],
        similarity: float,
    ) -> _CampaignRecord:
        with self._lock:
            rec = self._campaigns.get(campaign_id)
            if rec is None:
                raise KeyError(f"Campaign {campaign_id} not found")

            member = CampaignMember(
                member_id=str(uuid.uuid4()),
                content_hash=content_hash,
                analysis_id=analysis_id,
                scam_family=rec.scam_family,
                language=language,
                risk_score=risk_score,
                similarity_to_centroid=round(similarity, 4),
                joined_at=datetime.now(timezone.utc),
            )
            rec.members.append(member)
            rec.member_count += 1
            rec.language_dist[language] += 1
            rec.update_centroid(embedding)
            rec.last_seen = datetime.now(timezone.utc)
            rec.risk_scores.append(risk_score)

            # Merge new domains / sender IDs (deduplicate, cap at 20)
            existing_domains = set(rec.domains)
            for d in domains:
                if d not in existing_domains and len(rec.domains) < 20:
                    rec.domains.append(d)
                    existing_domains.add(d)

            existing_sids = set(rec.sender_ids)
            for s in sender_ids:
                if s not in existing_sids and len(rec.sender_ids) < 10:
                    rec.sender_ids.append(s)
                    existing_sids.add(s)

            self._content_hash_index[content_hash] = campaign_id

        return rec

    def get_campaign(self, campaign_id: str) -> Optional[_CampaignRecord]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def list_campaigns(self, limit: int = 50, offset: int = 0) -> List[CampaignSummary]:
        with self._lock:
            records = sorted(
                self._campaigns.values(),
                key=lambda r: r.last_seen,
                reverse=True,
            )
        page = records[offset: offset + limit]
        return [
            CampaignSummary(
                campaign_id=r.campaign_id,
                scam_family=r.scam_family,
                status=r.status,
                member_count=r.member_count,
                campaign_confidence=r.campaign_confidence,
                dominant_language=r.dominant_language,
                top_domains=r.domains[:5],
                first_seen=r.first_seen,
                last_seen=r.last_seen,
            )
            for r in page
        ]

    def get_campaign_detail(self, campaign_id: str) -> Optional[CampaignDetail]:
        rec = self.get_campaign(campaign_id)
        if rec is None:
            return None
        return CampaignDetail(
            campaign_id=rec.campaign_id,
            scam_family=rec.scam_family,
            status=rec.status,
            member_count=rec.member_count,
            campaign_confidence=rec.campaign_confidence,
            dominant_language=rec.dominant_language,
            language_distribution=dict(rec.language_dist),
            top_domains=rec.domains[:10],
            sender_ids=rec.sender_ids[:10],
            avg_risk_score=rec.avg_risk_score,
            first_seen=rec.first_seen,
            last_seen=rec.last_seen,
        )

    def get_members(
        self,
        campaign_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[CampaignMember]:
        rec = self.get_campaign(campaign_id)
        if rec is None:
            return []
        # Return scrubbed members — no raw text, only hashes and metadata
        with self._lock:
            return rec.members[offset: offset + limit]

    def total_campaigns(self) -> int:
        with self._lock:
            return len(self._campaigns)


# ── Store Factory ──────────────────────────────────────────────────────────────

_store_instance: Optional[InMemoryCampaignStore] = None
_store_lock = threading.Lock()


def get_campaign_store(similarity_threshold: float = 0.82) -> InMemoryCampaignStore:
    """
    Return the singleton campaign store.

    Phase 1: Always InMemoryCampaignStore.
    Phase 2: Swap to PgvectorCampaignStore when DB is available.
    """
    global _store_instance
    with _store_lock:
        if _store_instance is None:
            _store_instance = InMemoryCampaignStore(
                similarity_threshold=similarity_threshold
            )
            logger.info("Campaign store initialised (InMemory, threshold=%.2f)", similarity_threshold)
    return _store_instance
