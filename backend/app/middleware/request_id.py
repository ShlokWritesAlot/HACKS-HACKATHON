"""
Request ID middleware for BhashaRakshak.

Injects a unique UUID4 correlation ID into every request and response.
The ID is also attached to the logging context so all log lines for a
single request share the same request_id field.

Client behaviour:
- If the client sends X-Request-ID, we echo it back.
- If not, we generate a fresh UUID4.
- We always validate that an incoming ID is a valid UUID to prevent
  header injection.
"""

from __future__ import annotations

import logging
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

REQUEST_ID_HEADER = "X-Request-ID"
logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a correlation ID to every request and response."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Response:  # type: ignore[override]
        request_id = self._extract_or_generate_id(request)

        # Store on request state so route handlers can access it
        request.state.request_id = request_id

        # Attach to logging context for this request
        # (LogRecord enrichment is done in the log filter)
        _request_id_ctx.set(request_id)

        response = await call_next(request)

        # Always echo the request ID in the response
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    @staticmethod
    def _extract_or_generate_id(request: Request) -> str:
        """
        Use client-supplied X-Request-ID if it is a valid UUID4.
        Otherwise generate a fresh one.

        Validation prevents header injection / spoofing of internal IDs.
        """
        client_id = request.headers.get(REQUEST_ID_HEADER, "")
        if client_id:
            try:
                # Validate format — must be a well-formed UUID
                parsed = uuid.UUID(client_id, version=4)
                return str(parsed)
            except ValueError:
                # Invalid UUID — generate our own, ignore theirs
                logger.debug("Ignoring invalid X-Request-ID header from client")
        return str(uuid.uuid4())


# Context variable for request ID propagation within a request lifecycle
from contextvars import ContextVar
from typing import Any

_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")


def get_request_id() -> str:
    """Return the current request's correlation ID."""
    return _request_id_ctx.get()
