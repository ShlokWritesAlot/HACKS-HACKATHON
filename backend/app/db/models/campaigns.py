from __future__ import annotations

from sqlalchemy import Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Campaign(Base, UUIDMixin, TimestampMixin):
    """
    A clustered attack group / campaign.
    """

    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    scam_family_id: Mapped[str | None] = mapped_column(ForeignKey("scam_families.id", ondelete="SET NULL"), index=True, nullable=True)
    
    # Aggregate stats
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Relationships
    scam_family: Mapped["ScamFamily"] = relationship(  # type: ignore[name-defined]
        "ScamFamily",
        back_populates="campaigns",
    )
    memberships: Mapped[list["CampaignMember"]] = relationship(
        "CampaignMember",
        back_populates="campaign",
        cascade="all, delete-orphan",
    )


class CampaignMember(Base, UUIDMixin, TimestampMixin):
    """
    Association table linking Messages to Campaigns.
    """

    __tablename__ = "campaign_members"
    __table_args__ = (
        UniqueConstraint("campaign_id", "message_id", name="uix_campaign_message"),
    )

    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True, nullable=False)
    message_id: Mapped[str] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True, nullable=False)
    
    # Relationships
    campaign: Mapped["Campaign"] = relationship(
        "Campaign",
        back_populates="memberships",
    )
    message: Mapped["Message"] = relationship(  # type: ignore[name-defined]
        "Message",
        back_populates="campaign_memberships",
    )
