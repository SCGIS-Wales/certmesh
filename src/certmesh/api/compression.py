"""
certmesh.api.compression
==========================

GZip compression middleware.

Enabled by default for responses > 500 bytes.  Configurable via
``CM_COMPRESSION_ENABLED`` and ``CM_COMPRESSION_MIN_SIZE`` environment
variables, or Helm values.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import FastAPI
from starlette.middleware.gzip import GZipMiddleware

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_MIN_SIZE = 500  # bytes — compress responses >= 500B


@dataclass
class CompressionConfig:
    """Compression configuration."""

    enabled: bool = True
    minimum_size: int = DEFAULT_MIN_SIZE  # bytes
    compresslevel: int = 6  # gzip compression level (1-9)


def build_compression_config() -> CompressionConfig:
    """Build compression config from environment variables."""
    return CompressionConfig(
        enabled=os.environ.get("CM_COMPRESSION_ENABLED", "true").lower() in ("1", "true", "yes"),
        minimum_size=int(os.environ.get("CM_COMPRESSION_MIN_SIZE", str(DEFAULT_MIN_SIZE))),
        compresslevel=int(os.environ.get("CM_COMPRESSION_LEVEL", "6")),
    )


def register_compression(app: FastAPI, config: CompressionConfig | None = None) -> None:
    """Register GZip compression middleware on the FastAPI app."""
    if config is None:
        config = build_compression_config()

    if not config.enabled:
        logger.info("Response compression is disabled")
        return

    app.add_middleware(
        GZipMiddleware,
        minimum_size=config.minimum_size,
        compresslevel=config.compresslevel,
    )

    logger.info(
        "GZip compression enabled",
        extra={
            "minimum_size_bytes": config.minimum_size,
            "compresslevel": config.compresslevel,
        },
    )
