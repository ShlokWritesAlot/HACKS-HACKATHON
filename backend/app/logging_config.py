"""
Structured JSON logging configuration for BhashaRakshak.

Outputs logs as newline-delimited JSON for ingestion by log aggregators.
Includes native JSON formatting fallback if pythonjsonlogger is not installed.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

try:
    from pythonjsonlogger import jsonlogger
    HAS_JSON_LOGGER = True
except ImportError:
    HAS_JSON_LOGGER = False
    jsonlogger = None  # type: ignore

_SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "secret_key",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "access_token",
        "refresh_token",
        "private_key",
        "database_url",
        "db_url",
        "connection_string",
        "ssn",
        "credit_card",
        "cvv",
        "pin",
    }
)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for attr in list(vars(record).keys()):
            if attr.lower() in _SENSITIVE_FIELD_NAMES:
                setattr(record, attr, "<redacted>")

        if isinstance(record.msg, str):
            record.msg = self._redact_message(record.msg)

        return True

    @staticmethod
    def _redact_message(message: str) -> str:
        import re
        patterns = [
            (r'(?i)(password|passwd|secret|token|api_key)\s*[=:]\s*\S+', r"\1=<redacted>"),
            (r"(?i)(Bearer\s+)\S+", r"\1<redacted>"),
        ]
        for pattern, replacement in patterns:
            message = re.sub(pattern, replacement, message)
        return message


class FallbackJsonFormatter(logging.Formatter):
    """Zero-dependency JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id

        return json.dumps(log_obj)


def setup_logging(log_level: str = "INFO") -> None:
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    if HAS_JSON_LOGGER and jsonlogger:
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(level)s %(logger)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        formatter = FallbackJsonFormatter()

    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter())

    root_logger.setLevel(numeric_level)
    root_logger.addHandler(handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
