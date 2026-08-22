"""
Centralized configuration management for BhashaRakshak backend.

All settings are read from environment variables or .env files.
Sensitive fields are never logged or included in repr output.
The application refuses to start if required settings are missing or invalid.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    HAS_PYDANTIC_SETTINGS = True
except ImportError:
    HAS_PYDANTIC_SETTINGS = False
    BaseSettings = BaseModel  # type: ignore


def _load_dotenv_file(filepath: str = ".env") -> dict[str, str]:
    """Helper to parse a standard .env file if present on disk."""
    env_map: dict[str, str] = {}
    if not os.path.exists(filepath):
        return env_map

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                env_map[k] = v
    except Exception:
        pass
    return env_map


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ───────────────────────────────────────────────────────────
    environment: Literal["development", "staging", "production"] = "development"
    app_name: str = "BhashaRakshak"
    app_version: str = "0.1.0"
    backend_host: str = "0.0.0.0"
    backend_port: int = Field(default=8000, ge=1, le=65535)

    # ── Security ──────────────────────────────────────────────────────────────
    secret_key: Annotated[str, Field(default="bhasharakshak_dev_secret_key_minimum_32_characters_long", min_length=32, repr=False)]

    cors_allowed_origins_raw: str = Field(
        default="http://localhost:3000",
        alias="CORS_ALLOWED_ORIGINS",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: Annotated[str, Field(default="postgresql+asyncpg://postgres:postgres@localhost:5432/bhasharakshak", repr=False)]

    # ── Request limits ────────────────────────────────────────────────────────
    max_request_size_bytes: int = Field(default=1_048_576, ge=1024)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    def __init__(self, **kwargs):
        if not HAS_PYDANTIC_SETTINGS:
            dot_env = _load_dotenv_file()
            # Priority: kwargs > os.environ > .env > defaults
            env_vars = {
                "environment": os.getenv("ENVIRONMENT", dot_env.get("ENVIRONMENT", "development")),
                "app_name": os.getenv("APP_NAME", dot_env.get("APP_NAME", "BhashaRakshak")),
                "app_version": os.getenv("APP_VERSION", dot_env.get("APP_VERSION", "0.1.0")),
                "backend_host": os.getenv("BACKEND_HOST", dot_env.get("BACKEND_HOST", "0.0.0.0")),
                "backend_port": int(os.getenv("BACKEND_PORT", dot_env.get("BACKEND_PORT", "8000"))),
                "secret_key": os.getenv("SECRET_KEY", dot_env.get("SECRET_KEY", "bhasharakshak_dev_secret_key_minimum_32_characters_long")),
                "CORS_ALLOWED_ORIGINS": os.getenv("CORS_ALLOWED_ORIGINS", dot_env.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000")),
                "database_url": os.getenv("DATABASE_URL", dot_env.get("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/bhasharakshak")),
                "max_request_size_bytes": int(os.getenv("MAX_REQUEST_SIZE_BYTES", dot_env.get("MAX_REQUEST_SIZE_BYTES", "1048576"))),
                "rate_limit_requests": int(os.getenv("RATE_LIMIT_REQUESTS", dot_env.get("RATE_LIMIT_REQUESTS", "60"))),
                "rate_limit_window_seconds": int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", dot_env.get("RATE_LIMIT_WINDOW_SECONDS", "60"))),
                "log_level": os.getenv("LOG_LEVEL", dot_env.get("LOG_LEVEL", "INFO")),
            }
            env_vars.update(kwargs)
            super().__init__(**env_vars)
        else:
            super().__init__(**kwargs)

    @property
    def cors_allowed_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_allowed_origins_raw.split(",")
            if origin.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @field_validator("cors_allowed_origins_raw")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        origins = [o.strip() for o in v.split(",")]
        for origin in origins:
            if origin == "*":
                raise ValueError("Wildcard '*' CORS origin is not permitted. Specify explicit origins.")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use asyncpg driver: postgresql+asyncpg://user:pass@host:port/db")
        return v

    @model_validator(mode="after")
    def validate_production_hardening(self) -> "Settings":
        if self.environment == "production":
            if self.secret_key == "bhasharakshak_dev_secret_key_minimum_32_characters_long":
                raise ValueError("Insecure default SECRET_KEY cannot be used in production.")
            for origin in self.cors_allowed_origins:
                if "localhost" in origin or "127.0.0.1" in origin:
                    raise ValueError(f"Production CORS origin '{origin}' cannot point to localhost.")
        return self

    def __repr__(self) -> str:
        return (
            f"Settings("
            f"environment={self.environment!r}, "
            f"app_name={self.app_name!r}, "
            f"app_version={self.app_version!r}, "
            f"backend_port={self.backend_port}, "
            f"log_level={self.log_level!r}, "
            f"secret_key=<redacted>, "
            f"database_url=<redacted>"
            f")"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
