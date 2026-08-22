from __future__ import annotations

import enum

from sqlalchemy import Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class IndicatorType(str, enum.Enum):
    """Types of extracted Indicators of Compromise (IoCs)."""

    PHONE_NUMBER = "phone_number"
    URL = "url"
    DOMAIN = "domain"
    UPI_ID = "upi_id"
    BANK_ACCOUNT = "bank_account"


class ScamFamily(Base, UUIDMixin, TimestampMixin):
    """
    High-level categorization of scams.
    e.g., 'KYC Phishing', 'Job Fraud', 'Sextortion'
    """

    __tablename__ = "scam_families"

    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    analyses: Mapped[list["Analysis"]] = relationship(  # type: ignore[name-defined]
        "Analysis",
        back_populates="scam_family",
    )
    campaigns: Mapped[list["Campaign"]] = relationship(  # type: ignore[name-defined]
        "Campaign",
        back_populates="scam_family",
    )


class Indicator(Base, UUIDMixin, TimestampMixin):
    """
    Extracted Indicators of Compromise from messages.
    Normalized values ensure deduplication.
    """

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uix_indicator_type_value"),
    )

    type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType, name="indicator_type_enum"), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    
    # Optional metadata (e.g., extracted country code for phone)
    context: Mapped[str | None] = mapped_column(String(255), nullable=True)
