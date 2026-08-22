"""
Session Token Management & Authentication logic for BhashaRakshak Analysts.

SECURITY INVARIANTS:
  - Tokens are generated using secrets.token_urlsafe(32).
  - Tokens are stored as SHA-256 hashes in memory (never raw tokens).
  - Verification uses hmac.compare_digest for constant-time comparisons.
  - Expired sessions are automatically purged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# Default session duration: 8 hours
SESSION_DURATION = timedelta(hours=8)
_ANALYST_SECRET_KEY = "bhasharakshak-analyst-secret-key"


class AnalystSession(BaseModel):
    """Analyst Session metadata stored in server memory."""
    model_config = ConfigDict(extra="forbid")

    session_id: str
    analyst_id: str
    role: str = "analyst"
    created_at: datetime
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


class SessionStore:
    """Thread-safe in-memory session store."""

    def __init__(self) -> None:
        self._sessions: Dict[str, AnalystSession] = {}  # token_hash -> AnalystSession
        self._lock = threading.RLock()

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, analyst_id: str = "analyst-01", role: str = "analyst") -> tuple[str, AnalystSession]:
        raw_token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(raw_token)
        session_id = secrets.token_hex(8)

        now = datetime.now(timezone.utc)
        expires_at = now + SESSION_DURATION

        session = AnalystSession(
            session_id=session_id,
            analyst_id=analyst_id,
            role=role,
            created_at=now,
            expires_at=expires_at,
        )

        with self._lock:
            self._purge_expired_locked()
            self._sessions[token_hash] = session

        logger.info("Created analyst session %s for %s", session_id, analyst_id)
        return raw_token, session

    def verify_token(self, raw_token: str) -> Optional[AnalystSession]:
        if not raw_token or not raw_token.strip():
            return None

        token_hash = self._hash_token(raw_token.strip())

        with self._lock:
            session = self._sessions.get(token_hash)
            if session is None:
                return None

            if session.is_expired():
                del self._sessions[token_hash]
                logger.info("Session %s expired and purged", session.session_id)
                return None

            return session

    def invalidate_token(self, raw_token: str) -> bool:
        token_hash = self._hash_token(raw_token)
        with self._lock:
            if token_hash in self._sessions:
                del self._sessions[token_hash]
                return True
        return False

    def _purge_expired_locked(self) -> None:
        now = datetime.now(timezone.utc)
        expired_keys = [
            h for h, sess in self._sessions.items() if now > sess.expires_at
        ]
        for h in expired_keys:
            del self._sessions[h]


# Global session store singleton
_session_store = SessionStore()


def get_session_store() -> SessionStore:
    return _session_store


def verify_analyst_key(provided_key: str) -> bool:
    """Constant-time validation of secret key."""
    if not provided_key:
        return False
    return hmac.compare_digest(provided_key.strip(), _ANALYST_SECRET_KEY)
