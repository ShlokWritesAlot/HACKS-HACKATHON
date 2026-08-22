"""
Token-bucket rate limiter middleware for BhashaRakshak.

Design:
- In-memory per-IP token bucket.
- Configurable capacity (max tokens) and refill rate (tokens/second).
- Returns HTTP 429 with Retry-After and standard X-RateLimit headers.
- Thread-safe using asyncio.Lock per bucket.
- Automatic LRU cleanup prevents unbounded memory growth from unique client IPs.
- Interface is designed for a Redis-backed replacement in Phase 2.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Maximum distinct IP buckets cached in memory to prevent memory exhaustion
MAX_TRACKED_IPS = 10_000
# Bucket idle expiration in seconds (5 minutes)
BUCKET_TTL_SECONDS = 300.0


@dataclass
class TokenBucket:
    """
    Token bucket for a single client IP.

    Tokens refill continuously at `refill_rate` tokens per second,
    capped at `capacity`.
    """

    capacity: float
    refill_rate: float
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    async def consume(self, tokens: float = 1.0) -> tuple[bool, float, int]:
        """
        Attempt to consume `tokens` from the bucket.

        Returns:
            (allowed, retry_after_seconds, remaining_tokens)
        """
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            # Refill tokens based on elapsed time
            self.tokens = min(
                self.capacity,
                self.tokens + (elapsed * self.refill_rate),
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0, int(self.tokens)

            # Calculate how long until enough tokens refill
            deficit = tokens - self.tokens
            retry_after = deficit / max(0.001, self.refill_rate)
            return False, retry_after, int(self.tokens)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP token-bucket rate limiter.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_per_window: int = 60,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        safe_window = max(1, window_seconds)
        self._capacity = float(max(1, requests_per_window))
        self._refill_rate = self._capacity / float(safe_window)
        self._buckets: dict[str, TokenBucket] = {}
        self._buckets_lock = asyncio.Lock()
        self._last_cleanup = time.monotonic()

        logger.info(
            "Rate limiter initialised",
            extra={
                "capacity": self._capacity,
                "refill_rate_per_sec": self._refill_rate,
            },
        )

    async def _get_bucket(self, ip: str) -> TokenBucket:
        """Retrieve or create a token bucket for the given IP with automatic stale cleanup."""
        async with self._buckets_lock:
            now = time.monotonic()

            # Periodic cleanup of idle buckets every 60s
            if now - self._last_cleanup > 60.0 or len(self._buckets) > MAX_TRACKED_IPS:
                stale_ips = [
                    k for k, b in self._buckets.items()
                    if now - b.last_refill > BUCKET_TTL_SECONDS
                ]
                for k in stale_ips:
                    del self._buckets[k]
                self._last_cleanup = now

            if ip not in self._buckets:
                self._buckets[ip] = TokenBucket(
                    capacity=self._capacity,
                    refill_rate=self._refill_rate,
                )
            return self._buckets[ip]

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP address."""
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    async def dispatch(self, request: Request, call_next: Any) -> Response:  # type: ignore[override]
        path = request.url.path

        # Health checks, OpenAPI docs, and root status bypass rate limiting
        if (
            path.startswith("/api/v1/health")
            or path in ["/", "/health", "/docs", "/redoc", "/openapi.json"]
        ):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        bucket = await self._get_bucket(client_ip)
        allowed, retry_after, remaining = await bucket.consume()

        if not allowed:
            logger.warning(
                "Rate limit exceeded",
                extra={"client_ip": client_ip, "retry_after": retry_after},
            )
            req_id = getattr(request.state, "request_id", "")
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please slow down.",
                        "request_id": req_id,
                    }
                },
                headers={
                    "Retry-After": str(int(retry_after) + 1),
                    "X-RateLimit-Limit": str(int(self._capacity)),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(int(self._capacity))
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        return response
