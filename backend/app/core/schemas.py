"""
Shared Pydantic response schemas for BhashaRakshak API.

All API responses use these schemas for consistency.
Error responses never include stack traces or internal details.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """A single validation error detail."""

    field: str | None = Field(default=None, description="The field that caused the error")
    message: str = Field(description="Human-readable error description")


class ErrorEnvelope(BaseModel):
    """Standard error response body. Never includes stack traces."""

    code: str = Field(description="Machine-readable error code (SCREAMING_SNAKE_CASE)")
    message: str = Field(description="Human-readable error summary")
    request_id: str = Field(default="", description="Correlation ID from X-Request-ID")
    details: list[ErrorDetail] = Field(
        default_factory=list,
        description="Additional error context (validation errors etc.)",
    )


class ErrorResponse(BaseModel):
    """Top-level error response wrapper."""

    error: ErrorEnvelope


class SuccessResponse(BaseModel, Generic[T]):
    """
    Generic success response wrapper.

    Usage:
        SuccessResponse[MyDataModel](data=my_instance)
    """

    data: T
    request_id: str = Field(default="", description="Correlation ID")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list response."""

    items: list[T]
    total: int
    page: int
    page_size: int
    request_id: str = Field(default="")
