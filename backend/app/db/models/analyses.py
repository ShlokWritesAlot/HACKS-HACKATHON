from __future__ import annotations

import enum

from sqlalchemy import ARRAY, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import ENUM as pg_enum

from app.db.base import Base, TimestampMixin, UUIDMixin


class RiskLevel(str, enum.Enum):
    """Normalized risk level."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Analysis(Base, UUIDMixin, TimestampMixin):
    """
    ML Analysis results for a specific message.
    """

    __tablename__ = "analyses"

    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    scam_family_id: Mapped[str | None] = mapped_column(ForeignKey("scam_families.id", ondelete="SET NULL"), index=True, nullable=True)

    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[RiskLevel] = mapped_column(pg_enum(RiskLevel, name="risk_level_enum", create_type=False), nullable=False, default=RiskLevel.SAFE)
    
    decoded_meaning: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Use Postgres ARRAY instead of JSON for structured lists of strings
    manipulation_signals: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    obfuscation_signals: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    message: Mapped["Message"] = relationship(  # type: ignore[name-defined]
        "Message",
        back_populates="analysis",
    )
    scam_family: Mapped["ScamFamily"] = relationship(  # type: ignore[name-defined]
        "ScamFamily",
        back_populates="analyses",
    )
    feedbacks: Mapped[list["Feedback"]] = relationship(  # type: ignore[name-defined]
        "Feedback",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
