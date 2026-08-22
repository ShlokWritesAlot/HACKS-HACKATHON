"""
Tests for health check endpoints.

Coverage:
- GET /api/v1/health → 200 with full response schema
- GET /api/v1/health/live → 200 always
- GET /api/v1/health/ready → 200 when DB healthy
- GET /api/v1/health/ready → 503 when DB is down
- Response always includes X-Request-ID header
- Response never exposes sensitive info (DB URL, secrets)
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient) -> None:
    """Full health check returns 200 with correct schema."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "environment" in data
    assert "uptime_seconds" in data
    assert "database" in data
    assert data["environment"] == "development"


@pytest.mark.asyncio
async def test_health_response_has_request_id_header(client: AsyncClient) -> None:
    """Every response must include X-Request-ID header."""
    response = await client.get("/api/v1/health")
    assert "x-request-id" in response.headers
    request_id = response.headers["x-request-id"]
    assert len(request_id) == 36  # UUID4 string length


@pytest.mark.asyncio
async def test_health_database_healthy(client: AsyncClient) -> None:
    """Health check reports database as healthy when DB is reachable."""
    response = await client.get("/api/v1/health")
    data = response.json()
    assert data["database"]["status"] == "healthy"
    assert "latency_ms" in data["database"]


@pytest.mark.asyncio
async def test_liveness_always_200(client: AsyncClient) -> None:
    """Liveness probe always returns 200."""
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"


@pytest.mark.asyncio
async def test_liveness_has_request_id(client: AsyncClient) -> None:
    """Liveness probe includes X-Request-ID."""
    response = await client.get("/api/v1/health/live")
    assert "x-request-id" in response.headers


@pytest.mark.asyncio
async def test_readiness_200_when_db_healthy(client: AsyncClient) -> None:
    """Readiness probe returns 200 when database is healthy."""
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_readiness_503_when_db_down(client_db_down: AsyncClient) -> None:
    """Readiness probe returns 503 when database is unreachable."""
    response = await client_db_down.get("/api/v1/health/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unhealthy"
    assert data["database"]["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_health_does_not_expose_secrets(client: AsyncClient) -> None:
    """Health response must never contain sensitive values."""
    response = await client.get("/api/v1/health")
    body = response.text.lower()

    # These strings must never appear in any response
    forbidden_strings = [
        "secret_key",
        "database_url",
        "postgresql+asyncpg",
        "password",
        "test-secret-key",
    ]
    for forbidden in forbidden_strings:
        assert forbidden not in body, f"Found forbidden string in health response: {forbidden!r}"


@pytest.mark.asyncio
async def test_health_degraded_when_db_down(client_db_down: AsyncClient) -> None:
    """Full health endpoint returns degraded status when DB is down."""
    response = await client_db_down.get("/api/v1/health")
    assert response.status_code == 200  # Health endpoint itself still responds
    data = response.json()
    assert data["status"] == "degraded"
    assert data["database"]["status"] == "unhealthy"
    # Error message must be safe — no internal exception details
    db_error = data["database"].get("error", "")
    assert "postgresql" not in db_error.lower()
    assert "password" not in db_error.lower()


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient) -> None:
    """Security headers must be present on health endpoint responses."""
    response = await client.get("/api/v1/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "referrer-policy" in response.headers


@pytest.mark.asyncio
async def test_cors_header_for_allowed_origin(client: AsyncClient) -> None:
    """CORS headers are returned for allowed origins."""
    response = await client.get(
        "/api/v1/health",
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200
    # CORS header should be present
    assert "access-control-allow-origin" in response.headers
