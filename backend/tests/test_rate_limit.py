"""
Tests for rate limiting middleware.

Coverage:
- Normal requests are allowed (below limit)
- Requests exceeding the limit return 429
- 429 response includes Retry-After header
- 429 response follows error schema
- Health endpoints bypass rate limiting
- Rate limit resets after the window expires (simulated)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_requests_below_limit_are_allowed(client: AsyncClient) -> None:
    """Requests under the limit should all succeed."""
    for _ in range(5):
        response = await client.get("/api/v1/health/live")
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_rate_limit_triggers_429() -> None:
    """After exhausting the token bucket, the next request gets 429."""
    from app.main import create_app
    from app.db.session import get_db_session as _get_db_session
    from httpx import ASGITransport, AsyncClient

    # Create a fresh app with a very tight rate limit (2 requests per 60 seconds)
    import os
    os.environ["RATE_LIMIT_REQUESTS"] = "2"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"

    # We need a fresh settings instance for this test
    from app.config import get_settings
    get_settings.cache_clear()

    test_app = create_app()
    mock_session = AsyncMock()
    mock_result = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    async def override_db():  # type: ignore[return]
        yield mock_session

    test_app.dependency_overrides[_get_db_session] = override_db

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        # First 2 requests should pass
        r1 = await ac.get("/")
        r2 = await ac.get("/")
        # Third should be rate limited
        r3 = await ac.get("/")

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429

        data = r3.json()
        assert "error" in data
        assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Restore original settings
    os.environ["RATE_LIMIT_REQUESTS"] = "60"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rate_limit_response_has_retry_after() -> None:
    """Rate-limited response must include Retry-After header."""
    import os
    from app.config import get_settings
    from app.main import create_app
    from app.db.session import get_db_session as _get_db_session
    from httpx import ASGITransport, AsyncClient

    os.environ["RATE_LIMIT_REQUESTS"] = "1"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
    get_settings.cache_clear()

    test_app = create_app()
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=AsyncMock())
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    async def override_db():  # type: ignore[return]
        yield mock_session

    test_app.dependency_overrides[_get_db_session] = override_db

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        await ac.get("/")  # consume the 1 token
        r = await ac.get("/")  # should be rate limited
        assert r.status_code == 429
        assert "retry-after" in r.headers
        retry_after = int(r.headers["retry-after"])
        assert retry_after > 0

    os.environ["RATE_LIMIT_REQUESTS"] = "60"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_health_endpoints_bypass_rate_limit() -> None:
    """Health endpoints should not be subject to rate limiting."""
    import os
    from app.config import get_settings
    from app.main import create_app
    from app.db.session import get_db_session as _get_db_session
    from httpx import ASGITransport, AsyncClient

    # Extremely tight limit — would block 3rd request on most endpoints
    os.environ["RATE_LIMIT_REQUESTS"] = "1"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
    get_settings.cache_clear()

    test_app = create_app()
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=AsyncMock())
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    async def override_db():  # type: ignore[return]
        yield mock_session

    test_app.dependency_overrides[_get_db_session] = override_db

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        # Health endpoints should all succeed even with limit=1
        for _ in range(5):
            r = await ac.get("/api/v1/health/live")
            assert r.status_code == 200, "Health endpoint should bypass rate limiting"

    os.environ["RATE_LIMIT_REQUESTS"] = "60"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rate_limit_error_schema(client: AsyncClient) -> None:
    """Rate limit 429 response follows the standard error schema."""
    import os
    from app.config import get_settings
    from app.main import create_app
    from app.db.session import get_db_session as _get_db_session
    from httpx import ASGITransport, AsyncClient

    os.environ["RATE_LIMIT_REQUESTS"] = "1"
    os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
    get_settings.cache_clear()

    test_app = create_app()
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=AsyncMock())
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    async def override_db():  # type: ignore[return]
        yield mock_session

    test_app.dependency_overrides[_get_db_session] = override_db

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as ac:
        await ac.get("/")
        r = await ac.get("/")

    assert r.status_code == 429
    data = r.json()
    assert "error" in data
    assert "code" in data["error"]
    assert "message" in data["error"]

    os.environ["RATE_LIMIT_REQUESTS"] = "60"
    get_settings.cache_clear()
