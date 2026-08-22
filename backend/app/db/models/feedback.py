from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Feedback(Base, UUIDMixin, TimestampMixin):
    """
    Feedback provided by a User/Analyst on a specific Analysis.
    """

    __tablename__ = "feedback"
    __table_args__ = (
        UniqueConstraint("analysis_id", "user_id", name="uix_analysis_user_feedback"),
    )

    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    
    # Is the analysis considered correct? (True = True Positive, False = False Positive)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    
    # Optional comment/reasoning
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    analysis: Mapped["Analysis"] = relationship(  # type: ignore[name-defined]
        "Analysis",
        back_populates="feedbacks",
    )
    user: Mapped["User"] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="feedbacks",
    )
