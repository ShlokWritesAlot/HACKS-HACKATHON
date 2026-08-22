"""
SQLAlchemy declarative base for BhashaRakshak.

All ORM models inherit from Base.
Includes graceful fallback when SQLAlchemy is not installed in the local environment.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

try:
    from sqlalchemy import DateTime, String, func
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    DeclarativeBase = object  # type: ignore
    Mapped = Any  # type: ignore

    def mapped_column(*args: Any, **kwargs: Any) -> Any:
        return None

    class func:  # type: ignore
        @staticmethod
        def now():
            return None


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


class TimestampMixin:
    """Mixin that adds standard audit timestamp columns to a model."""
    if HAS_SQLALCHEMY:
        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )
        updated_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        )
    else:
        created_at = None
        updated_at = None


class UUIDMixin:
    """Mixin that adds a UUID primary key."""
    if HAS_SQLALCHEMY:
        id: Mapped[str] = mapped_column(
            String(36),
            primary_key=True,
            default=lambda: str(uuid.uuid4()),
            nullable=False,
        )
    else:
        id = None
