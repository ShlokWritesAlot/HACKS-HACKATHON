from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB

from app.db.base import Base, TimestampMixin, UUIDMixin


class AuditEvent(Base, UUIDMixin, TimestampMixin):
    """
    Append-only audit log for sensitive actions.
    
    Security:
    - Should never be updated or deleted by the application.
    - Tracks WHO did WHAT to WHICH resource.
    """

    __tablename__ = "audit_events"

    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    
    # Flexible JSON blob for arbitrary event details (e.g. old_value, new_value)
    # This is an acceptable use of JSON since it is schemaless by design.
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
