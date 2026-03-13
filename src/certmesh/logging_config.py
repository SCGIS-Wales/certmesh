"""
certmesh.logging_config
========================

Centralised structured JSON logging configuration.

When ``CM_LOG_FORMAT=json`` (the default for production / Docker),
all log records are emitted as single-line JSON objects.  Set
``CM_LOG_FORMAT=text`` for human-readable console output during
local development.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

try:
    from pythonjsonlogger.json import JsonFormatter as _BaseJsonFormatter
except ImportError:  # older pythonjsonlogger (<3.0)
    from pythonjsonlogger.jsonlogger import JsonFormatter as _BaseJsonFormatter


class _CertMeshJsonFormatter(_BaseJsonFormatter):
    """JSON formatter that adds certmesh-specific default fields."""

    def add_fields(
        self,
        log_record: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record.setdefault("level", record.levelname.lower())
        log_record.setdefault("logger", record.name)
        log_record.setdefault("timestamp", self.formatTime(record))
        # Remove the default 'levelname' in favour of 'level'
        log_record.pop("levelname", None)


_TEXT_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
_JSON_FIELDS = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging(
    level: str = "INFO",
    log_format: str | None = None,
) -> None:
    """Configure root logger for the entire application.

    Parameters
    ----------
    level:
        Log level name (DEBUG, INFO, WARNING, ERROR).
    log_format:
        ``"json"`` for structured JSON output (default in production),
        ``"text"`` for human-readable output.  Falls back to the
        ``CM_LOG_FORMAT`` environment variable, then ``"json"``.
    """
    fmt = (log_format or os.environ.get("CM_LOG_FORMAT", "json")).lower()
    resolved_level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger()
    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()
    root.setLevel(resolved_level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(resolved_level)

    if fmt == "json":
        formatter = _CertMeshJsonFormatter(_JSON_FIELDS)
    else:
        formatter = logging.Formatter(_TEXT_FORMAT)

    handler.setFormatter(formatter)
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    for noisy in ("urllib3", "botocore", "boto3", "hvac", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
