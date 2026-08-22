"""
Security headers middleware for BhashaRakshak.

Adds defence-in-depth HTTP security headers to every response.
These headers are not a substitute for proper application security,
but they significantly raise the bar for common browser-based attacks.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject security-oriented HTTP headers on every response.

    Headers applied:
    - X-Content-Type-Options: nosniff — prevents MIME-type sniffing
    - X-Frame-Options: DENY — prevents clickjacking
    - Referrer-Policy: strict-origin-when-cross-origin — limits referrer leakage
    - Permissions-Policy — disables dangerous browser features
    - Strict-Transport-Security — enforces HTTPS (only in production)
    - X-XSS-Protection: 0 — modern browsers ignore it; 1 can be exploited
    - Cache-Control: no-store for API responses — prevents caching of sensitive data
    """

    def __init__(self, app: ASGIApp, is_production: bool = False) -> None:
        super().__init__(app)
        self._is_production = is_production

    async def dispatch(self, request: Request, call_next: Any) -> Response:  # type: ignore[override]
        response: Response = await call_next(request)

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent embedding in iframes (clickjacking)
        response.headers["X-Frame-Options"] = "DENY"

        # Limit referrer information sent to third parties
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Disable browser features not needed by this API
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), interest-cohort=()"
        )

        # Modern browsers handle XSS; value of 1 can be exploited
        response.headers["X-XSS-Protection"] = "0"

        # API responses must not be cached by browsers or proxies
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"

        # HSTS — only set in production (breaks local HTTP dev)
        if self._is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response
