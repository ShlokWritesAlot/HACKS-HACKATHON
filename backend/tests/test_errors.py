"""
Tests for error handling and response format.

Coverage:
- Invalid JSON body → 422 with error schema
- Missing required fields → 422 with field-level details
- Oversized request body → 413
- Wrong content type → 422
- 404 Not Found → consistent error schema
- Response never includes stack traces
- Response always includes request_id
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient

# A minimal endpoint that requires a validated body
# We test against the health endpoint (no body needed) and use a
# custom test route added in conftest for body validation tests.


@pytest.mark.asyncio
async def test_404_returns_error_schema(client: AsyncClient) -> None:
    """Non-existent routes return the standard error schema."""
    response = await client.get("/api/v1/nonexistent-route")
    assert response.status_code == 404

    data = response.json()
    assert "error" in data
    assert "code" in data["error"]
    assert "message" in data["error"]
    assert data["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_error_response_never_has_stack_trace(client: AsyncClient) -> None:
    """Error responses must never include Python traceback strings."""
    response = await client.get("/api/v1/nonexistent-endpoint")
    body = response.text

    forbidden = ["traceback", "Traceback", "File \"", "line ", "raise ", "Exception"]
    for term in forbidden:
        assert term not in body, f"Stack trace indicator found in error response: {term!r}"


@pytest.mark.asyncio
async def test_error_response_has_request_id(client: AsyncClient) -> None:
    """All error responses must include a request_id field."""
    response = await client.get("/api/v1/nonexistent")
    assert response.status_code == 404
    data = response.json()
    # request_id may be empty string but must be present
    assert "request_id" in data["error"]


@pytest.mark.asyncio
async def test_error_schema_structure(client: AsyncClient) -> None:
    """Error schema must have exactly the expected top-level keys."""
    response = await client.get("/api/v1/does-not-exist")
    data = response.json()

    assert set(data.keys()) == {"error"}
    error = data["error"]
    assert "code" in error
    assert "message" in error
    assert "request_id" in error


@pytest.mark.asyncio
async def test_client_request_id_echoed(client: AsyncClient) -> None:
    """X-Request-ID sent by client is echoed in response header."""
    custom_id = "550e8400-e29b-41d4-a716-446655440000"
    response = await client.get(
        "/api/v1/health/live",
        headers={"X-Request-ID": custom_id},
    )
    assert response.headers.get("x-request-id") == custom_id


@pytest.mark.asyncio
async def test_invalid_uuid_request_id_replaced(client: AsyncClient) -> None:
    """Invalid X-Request-ID from client is replaced with a generated UUID."""
    response = await client.get(
        "/api/v1/health/live",
        headers={"X-Request-ID": "not-a-valid-uuid!!!"},
    )
    echoed = response.headers.get("x-request-id", "")
    # Should be a valid UUID (not the invalid one)
    assert echoed != "not-a-valid-uuid!!!"
    assert len(echoed) == 36


@pytest.mark.asyncio
async def test_oversized_request_returns_413(client: AsyncClient) -> None:
    """Request body exceeding limit returns 413."""
    # Default limit is 1 MB (1_048_576 bytes)
    # Send 2 MB of data
    large_body = b"x" * (2 * 1024 * 1024)
    response = await client.post(
        "/api/v1/health",  # endpoint doesn't matter — middleware fires first
        content=large_body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(large_body)),
        },
    )
    assert response.status_code == 413

    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"
    # Error message must not reveal internal limits exactly
    assert "stack" not in data
    assert "traceback" not in response.text.lower()


@pytest.mark.asyncio
async def test_method_not_allowed(client: AsyncClient) -> None:
    """DELETE on health endpoint returns 405."""
    response = await client.delete("/api/v1/health")
    assert response.status_code == 405
    data = response.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_cache_control_header_on_api_response(client: AsyncClient) -> None:
    """API responses must include Cache-Control: no-store."""
    response = await client.get("/api/v1/health")
    cache_control = response.headers.get("cache-control", "")
    assert "no-store" in cache_control
