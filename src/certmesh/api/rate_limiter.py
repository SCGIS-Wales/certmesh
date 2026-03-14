"""
certmesh.api.rate_limiter
==========================

Configurable rate limiting middleware using SlowAPI.

Returns HTTP 429 with RFC 7231 compliant JSON error body and ``Retry-After``
header when the limit is exceeded.

Default limits are deliberately high (1000 req/min) to avoid impacting normal
operations while protecting against abuse.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_RATE_LIMIT = "1000/minute"  # high default — protection not restriction
DEFAULT_BURST_LIMIT = "100/second"  # burst protection


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    enabled: bool = True
    default_limit: str = DEFAULT_RATE_LIMIT
    burst_limit: str = DEFAULT_BURST_LIMIT
    # Per-endpoint overrides (path prefix → limit string)
    endpoint_limits: dict[str, str] | None = None
    # Exempt paths (health checks, metrics)
    exempt_paths: tuple[str, ...] = (
        "/healthz",
        "/livez",
        "/readyz",
        "/metrics",
    )


def _key_func(request: Request) -> str:
    """Extract client identifier for rate limiting.

    Priority: X-Forwarded-For → X-Real-IP → remote address.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return get_remote_address(request)


def build_rate_limit_config() -> RateLimitConfig:
    """Build rate limit config from environment variables."""
    return RateLimitConfig(
        enabled=os.environ.get("CM_RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes"),
        default_limit=os.environ.get("CM_RATE_LIMIT_DEFAULT", DEFAULT_RATE_LIMIT),
        burst_limit=os.environ.get("CM_RATE_LIMIT_BURST", DEFAULT_BURST_LIMIT),
    )


def create_limiter(config: RateLimitConfig) -> Limiter:
    """Create a configured SlowAPI limiter."""
    limiter = Limiter(
        key_func=_key_func,
        default_limits=[config.default_limit] if config.enabled else [],
        enabled=config.enabled,
    )
    return limiter


def register_rate_limiter(app: FastAPI, config: RateLimitConfig | None = None) -> Limiter:
    """Register rate limiting on the FastAPI app."""
    if config is None:
        config = build_rate_limit_config()

    limiter = create_limiter(config)
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
        request_id = getattr(request.state, "request_id", "unknown")
        client_ip = _key_func(request)

        logger.warning(
            "Rate limit exceeded: client=%s path=%s limit=%s request_id=%s",
            client_ip,
            request.url.path,
            str(exc.detail),
            request_id,
        )

        # RFC 7231 § 6.6.4 — Retry-After header
        retry_after = "60"  # default retry suggestion
        return JSONResponse(
            status_code=429,
            content={
                "error": "too_many_requests",
                "detail": f"Rate limit exceeded: {exc.detail}",
                "request_id": request_id,
                "retry_after_seconds": int(retry_after),
            },
            headers={
                "Retry-After": retry_after,
                "X-Request-ID": request_id,
            },
        )

    logger.info(
        "Rate limiting registered: enabled=%s default=%s burst=%s",
        config.enabled,
        config.default_limit,
        config.burst_limit,
    )
    return limiter
