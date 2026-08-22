"""
BhashaRakshak FastAPI application factory.

This module creates and configures the FastAPI application:
- Structured logging setup (before anything else)
- Lifespan context for startup/shutdown hooks
- Middleware stack (order matters — applied bottom-up)
- CORS (from environment variables only)
- Exception handlers
- API routers
- Request size limiting

Security:
- CORS origins from environment, never wildcard.
- Request body capped at MAX_REQUEST_SIZE_BYTES.
- API docs disabled in production.
- Stack traces never returned to clients.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.api.v1.router import router as v1_router
from app.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.db.session import close_db, init_db
from app.logging_config import setup_logging
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan context manager.

    Startup:
        1. Initialise the database engine and session pool.

    Shutdown:
        1. Dispose the database engine (drain connections).
    """
    settings: Settings = get_settings()

    logger.info(
        "BhashaRakshak starting up",
        extra={
            "environment": settings.environment,
            "version": settings.app_version,
            "port": settings.backend_port,
        },
    )

    await init_db(settings)

    yield  # Application runs here

    logger.info("BhashaRakshak shutting down")
    await close_db()


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns a fully configured FastAPI instance ready for serving.
    """
    # ── Logging must be set up first ─────────────────────────────────────────
    settings = get_settings()
    setup_logging(settings.log_level)

    # ── FastAPI instance ──────────────────────────────────────────────────────
    app = FastAPI(
        title="BhashaRakshak API",
        description=(
            "AI-powered Scam X-Ray: detects scam intent in multilingual, "
            "transliterated, obfuscated, and code-mixed SMS messages."
        ),
        version=settings.app_version,
        lifespan=lifespan,
        # Disable interactive docs in production — they expose API surface
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        # Disable FastAPI's default exception handler (we register our own)
        default_response_class=JSONResponse,
    )

    # ── Middleware (applied in REVERSE order of registration) ─────────────────
    # 1. Security headers — outermost, applied to all responses
    app.add_middleware(
        SecurityHeadersMiddleware,
        is_production=settings.is_production,
    )

    # 2. Rate limiter — before request ID so it can reference it
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_window=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    # 3. Request ID — innermost middleware, runs first on request
    app.add_middleware(RequestIDMiddleware)

    # 4. CORS — must be registered AFTER custom middleware
    #    (Starlette processes CORSMiddleware before user middleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    # ── Request size limit ────────────────────────────────────────────────────
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next: Any) -> Any:  # type: ignore[misc]
        content_length = request.headers.get("content-length")
        if content_length is not None:
            if int(content_length) > settings.max_request_size_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": (
                                f"Request body exceeds the maximum allowed size "
                                f"of {settings.max_request_size_bytes} bytes."
                            ),
                            "request_id": "",
                        }
                    },
                )
        return await call_next(request)

    # ── Exception handlers ────────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(v1_router)

    # ── Root & Visual Dashboard Routes ─────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def root_dashboard() -> HTMLResponse:
        dashboard_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
        if os.path.exists(dashboard_path):
            with open(dashboard_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse("<h1>BhashaRakshak API Active</h1><p>Visit <a href='/docs'>/docs</a> for API documentation.</p>")

    logger.info(
        "Application configured",
        extra={
            "cors_origins": settings.cors_allowed_origins,
            "docs_enabled": settings.is_development,
            "rate_limit": f"{settings.rate_limit_requests}/{settings.rate_limit_window_seconds}s",
        },
    )

    return app


# Module-level app instance for uvicorn
from typing import Any  # noqa: E402 — needed for middleware type hints above

app = create_app()
