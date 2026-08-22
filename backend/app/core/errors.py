"""
Centralized exception handlers for BhashaRakshak.

Security principles:
- NEVER return stack traces to clients.
- NEVER expose internal error messages in production.
- Always return the consistent ErrorResponse schema.
- Always include the request_id for log correlation.
- Log full details server-side for debugging.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.schemas import ErrorDetail, ErrorEnvelope, ErrorResponse
from app.middleware.request_id import get_request_id

logger = logging.getLogger(__name__)


def _make_error_response(
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    request_id: str = "",
) -> dict[str, object]:
    """Build the standard error response dict."""
    return ErrorResponse(
        error=ErrorEnvelope(
            code=code,
            message=message,
            request_id=request_id or get_request_id(),
            details=details or [],
        )
    ).model_dump()


def register_exception_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI app."""

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """
        Handle Pydantic validation errors (422 Unprocessable Entity).

        Returns structured field-level error details without exposing internals.
        """
        details = []
        for error in exc.errors():
            # Location path → dot-separated field name
            loc = error.get("loc", [])
            field = ".".join(str(part) for part in loc if part != "body")
            details.append(
                ErrorDetail(
                    field=field or None,
                    message=error.get("msg", "Validation error"),
                )
            )

        logger.warning(
            "Request validation failed",
            extra={
                "path": str(request.url.path),
                "method": request.method,
                "error_count": len(details),
                "request_id": get_request_id(),
            },
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_make_error_response(
                code="VALIDATION_ERROR",
                message="Request validation failed",
                details=details,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        """
        Handle HTTP exceptions (4xx, 5xx).

        Maps status codes to safe, generic messages for 5xx errors
        to avoid leaking internal details.
        """
        # For 5xx errors: safe generic message; log the detail
        if exc.status_code >= 500:
            logger.error(
                "Internal HTTP error",
                extra={
                    "status_code": exc.status_code,
                    "detail": exc.detail,
                    "path": str(request.url.path),
                    "request_id": get_request_id(),
                },
            )
            message = "An internal error occurred. Please try again later."
            code = "INTERNAL_ERROR"
        else:
            # 4xx: the detail is safe to return (FastAPI sets it)
            message = str(exc.detail)
            code = _status_to_code(exc.status_code)
            logger.info(
                "HTTP client error",
                extra={
                    "status_code": exc.status_code,
                    "path": str(request.url.path),
                    "request_id": get_request_id(),
                },
            )

        return JSONResponse(
            status_code=exc.status_code,
            content=_make_error_response(code=code, message=message),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """
        Catch-all for unhandled exceptions.

        Logs full exception details server-side.
        Returns a generic safe message to the client — NO stack trace.
        """
        logger.exception(
            "Unhandled exception",
            extra={
                "path": str(request.url.path),
                "method": request.method,
                "request_id": get_request_id(),
            },
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_make_error_response(
                code="INTERNAL_ERROR",
                message="An unexpected error occurred. Please try again later.",
            ),
        )


def _status_to_code(status_code: int) -> str:
    """Map HTTP status code to machine-readable error code."""
    mapping: dict[int, str] = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        413: "PAYLOAD_TOO_LARGE",
        415: "UNSUPPORTED_MEDIA_TYPE",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
    }
    return mapping.get(status_code, f"HTTP_{status_code}")
