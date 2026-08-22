"""
Health check endpoints for BhashaRakshak API v1.
"""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Annotated, Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import Settings, get_settings
from app.db.session import get_db_session
from app.middleware.request_id import get_request_id

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

_START_TIME = time.monotonic()


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class DatabaseHealth(BaseModel):
    status: HealthStatus
    latency_ms: float | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: HealthStatus
    version: str
    environment: str
    uptime_seconds: float
    request_id: str
    database: DatabaseHealth


class LivenessResponse(BaseModel):
    status: str
    request_id: str


class ReadinessResponse(BaseModel):
    status: HealthStatus
    request_id: str
    database: DatabaseHealth


async def _check_database(session: Any) -> DatabaseHealth:
    start = time.monotonic()
    try:
        if hasattr(session, "execute"):
            await session.execute("SELECT 1")
        latency_ms = (time.monotonic() - start) * 1000
        return DatabaseHealth(status=HealthStatus.HEALTHY, latency_ms=round(latency_ms, 2))
    except Exception as exc:
        logger.warning("Database health check failed", extra={"error_type": type(exc).__name__})
        return DatabaseHealth(
            status=HealthStatus.UNHEALTHY,
            error="Database connectivity check failed",
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Full health check",
    description="Returns service status, version, uptime, and dependency health.",
)
async def health_check(
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Any, Depends(get_db_session)],
) -> HealthResponse:
    db_health = await _check_database(db)

    overall = (
        HealthStatus.HEALTHY
        if db_health.status == HealthStatus.HEALTHY
        else HealthStatus.DEGRADED
    )

    return HealthResponse(
        status=overall,
        version=settings.app_version,
        environment=settings.environment,
        uptime_seconds=round(time.monotonic() - _START_TIME, 1),
        request_id=get_request_id(),
        database=db_health,
    )


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Always returns 200 if the process is running. Used by container orchestrators.",
)
async def liveness() -> LivenessResponse:
    return LivenessResponse(status="alive", request_id=get_request_id())


@router.get(
    "/health/ready",
    summary="Readiness probe",
    description="Returns 200 only when all dependencies are ready. Used by load balancers.",
)
async def readiness(
    db: Annotated[Any, Depends(get_db_session)],
) -> JSONResponse:
    db_health = await _check_database(db)
    is_ready = db_health.status == HealthStatus.HEALTHY

    response_data = ReadinessResponse(
        status=HealthStatus.HEALTHY if is_ready else HealthStatus.UNHEALTHY,
        request_id=get_request_id(),
        database=db_health,
    ).model_dump()

    return JSONResponse(
        status_code=status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=response_data,
    )
