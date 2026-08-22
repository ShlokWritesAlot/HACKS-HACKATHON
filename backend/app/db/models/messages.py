from __future__ import annotations

import enum

from sqlalchemy import DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class MessageSource(str, enum.Enum):
    """Origin of the message."""

    USER_SUBMISSION = "user_submission"
    HONEYPOT = "honeypot"
    API_BULK = "api_bulk"


class Message(Base, UUIDMixin, TimestampMixin):
    """
    Core SMS/Message record.
    
    Privacy & Data Retention:
    - `raw_text` and `sender_id` can be set to NULL after the retention
      period expires, retaining only the UUID and metadata for analytics.
    """

    __tablename__ = "messages"

    # Privacy: Nullable for eventual data retention cleanup
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender_id: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # ML/Normalized fields
    normalized_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_language: Mapped[str | None] = mapped_column(String(10), index=True, nullable=True)

    # Metadata
    source: Mapped[MessageSource] = mapped_column(Enum(MessageSource, name="message_source_enum"), nullable=False, default=MessageSource.USER_SUBMISSION)
    
    # Hash of raw_text for rapid exact-duplicate detection.
    # Uses SHA-256 hex digest (64 chars).
    content_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    
    # Relationships
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        "Analysis",
        back_populates="message",
        cascade="all, delete-orphan",
        uselist=False,
    )
    campaign_memberships: Mapped[list["CampaignMember"]] = relationship(  # type: ignore[name-defined]
        "CampaignMember",
        back_populates="message",
        cascade="all, delete-orphan",
    )
