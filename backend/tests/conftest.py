"""
Pytest configuration and shared fixtures for BhashaRakshak backend tests.

Fixtures:
    settings: Test settings with safe defaults (no real DB/secrets needed).
    app: Configured FastAPI test application.
    client: AsyncClient for making HTTP requests in tests.
    mock_db_session: In-memory mock session for DB-dependent endpoints.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ── Environment setup (must happen before app import) ─────────────────────────
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars-long!!")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000")

# ── App imports (after env setup) ─────────────────────────────────────────────
from app.config import Settings, get_settings
from app.db.session import get_db_session


@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.DefaultEventLoopPolicy:
    """Use the default event loop policy."""
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture
def test_settings() -> Settings:
    """Return test settings singleton."""
    return get_settings()


@pytest.fixture
def mock_db_session() -> AsyncMock:
    """
    Return a mock async database session.

    Simulates a healthy DB by default.
    Override in specific tests to simulate failures.
    """
    session = AsyncMock()
    # execute() returns a mock result with a scalar() method
    mock_result = MagicMock()
    mock_result.scalar.return_value = 1
    session.execute = AsyncMock(return_value=mock_result)
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def app_with_mock_db(mock_db_session: AsyncMock) -> Any:
    """
    Create a test FastAPI app with the DB session overridden.

    Uses dependency_overrides to inject the mock session.
    No real database connection is needed.
    """
    from app.main import create_app
    from app.config import get_settings as _get_settings
    from app.db.session import get_db_session as _get_db_session

    test_app = create_app()

    async def override_db() -> AsyncGenerator[AsyncMock, None]:
        yield mock_db_session

    test_app.dependency_overrides[_get_db_session] = override_db
    return test_app


@pytest_asyncio.fixture
async def client(app_with_mock_db: Any) -> AsyncGenerator[AsyncClient, None]:
    """
    Return an AsyncClient wired to the test application.

    The app lifespan (startup/shutdown) is NOT run in tests —
    dependencies are overridden instead.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app_with_mock_db),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def client_db_down() -> AsyncGenerator[AsyncClient, None]:
    """
    Return a client where the DB session raises an exception.

    Used to test degraded health states.
    """
    from app.main import create_app
    from app.db.session import get_db_session as _get_db_session

    test_app = create_app()

    async def failing_db() -> AsyncGenerator[None, None]:
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=ConnectionError("DB unreachable"))
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        yield session

    test_app.dependency_overrides[_get_db_session] = failing_db

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        yield ac
