"""
SQLAlchemy async session factory for BhashaRakshak.

Uses asyncpg driver with connection pooling.
Includes graceful fallback when running in lightweight environments without SQLAlchemy installed.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from app.config import Settings

logger = logging.getLogger(__name__)

# Module-level engine and session factory
_engine: Any = None
_session_factory: Any = None

try:
    from sqlalchemy.ext.asyncio import (
        AsyncEngine,
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    AsyncEngine = Any  # type: ignore
    AsyncSession = Any  # type: ignore


def create_engine(settings: Settings) -> Any:
    if not HAS_SQLALCHEMY:
        logger.warning("SQLAlchemy not available. Running in standalone mock DB mode.")
        return None

    logger.info("Creating database engine", extra={"environment": settings.environment})
    return create_async_engine(
        settings.database_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_timeout=30,
        echo=settings.log_level == "DEBUG" and not settings.is_production,
    )


def create_session_factory(engine: Any) -> Any:
    if not HAS_SQLALCHEMY or engine is None:
        return None

    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


async def init_db(settings: Settings) -> None:
    global _engine, _session_factory  # noqa: PLW0603
    _engine = create_engine(settings)
    if _engine is not None:
        _session_factory = create_session_factory(_engine)
        logger.info("Database engine initialised")
    else:
        logger.info("Mock database mode initialised")


async def close_db() -> None:
    global _engine  # noqa: PLW0603
    if _engine is not None and hasattr(_engine, "dispose"):
        await _engine.dispose()
        _engine = None
        logger.info("Database engine disposed")


async def get_db_session() -> AsyncGenerator[Any, None]:
    if not HAS_SQLALCHEMY or _session_factory is None:
        # Mock session for offline testing
        class MockSession:
            async def execute(self, query: Any) -> None:
                pass
            async def rollback(self) -> None:
                pass
            async def close(self) -> None:
                pass

        yield MockSession()
        return

    async with _session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
