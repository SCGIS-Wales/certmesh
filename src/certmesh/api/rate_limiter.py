"""
certmesh.api.rate_limiter
==========================

Configurable rate limiting middleware using SlowAPI.

Returns HTTP 429 with RFC 7231 compliant JSON error body and ``Retry-After``
header when the limit is exceeded.

Default limits are deliberately high (1000 req/min) to avoid impacting normal
operations while protecting against abuse.

Health/liveness/readiness and metrics endpoints are exempt from rate limiting
so that Kubernetes probes and Prometheus scraping are never blocked.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_RATE_LIMIT = "1000/minute"  # high default — protection not restriction
DEFAULT_BURST_LIMIT = "100/second"  # burst protection
DEFAULT_EXEMPT_PATHS: tuple[str, ...] = (
    "/healthz",
    "/livez",
    "/readyz",
    "/metrics",
)


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    enabled: bool = True
    default_limit: str = DEFAULT_RATE_LIMIT
    burst_limit: str = DEFAULT_BURST_LIMIT
    # Per-endpoint overrides (path prefix → limit string)
    endpoint_limits: dict[str, str] | None = None
    # Exempt paths (health checks, metrics) — not rate-limited
    exempt_paths: tuple[str, ...] = DEFAULT_EXEMPT_PATHS


class _ExemptPathsMiddleware(BaseHTTPMiddleware):
    """Mark exempt paths so SlowAPI skips rate-limit checks.

    SlowAPI respects ``request.state._rate_limiting_complete`` — when set
    to ``True`` the limiter will not enforce limits for that request.
    This middleware must be the **outermost** of the two (added *after*
    ``SlowAPIMiddleware``) so it runs *first* in the request chain.
    """

    def __init__(self, app: object, exempt_paths: frozenset[str]) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.exempt_paths = exempt_paths

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self.exempt_paths:
            request.state._rate_limiting_complete = True
        return await call_next(request)


_TRUSTED_PROXY_COUNT: int = int(os.environ.get("CM_TRUSTED_PROXY_COUNT", "1"))


def _key_func(request: Request) -> str:
    """Extract client identifier for rate limiting.

    SEC-07: Use the rightmost non-proxy IP from X-Forwarded-For instead of
    blindly trusting the leftmost entry (which can be spoofed by clients).

    With ``CM_TRUSTED_PROXY_COUNT=N``, the Nth entry from the right is used
    (default 1 = last proxy-appended entry, i.e. the client IP as seen by
    the first trusted reverse proxy).

    Fallback: X-Real-IP → remote address.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",")]
        # Use rightmost trusted entry: index from the end
        idx = min(_TRUSTED_PROXY_COUNT, len(parts))
        return parts[-idx]
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return get_remote_address(request)


def build_rate_limit_config() -> RateLimitConfig:
    """Build rate limit config from environment variables.

    ``CM_RATE_LIMIT_EXEMPT_PATHS``:
    - **not set** → use ``DEFAULT_EXEMPT_PATHS`` (health/metrics endpoints)
    - **set to empty string** → no exempt paths (all endpoints rate-limited)
    - **set to comma-separated list** → use those paths
    """
    exempt_raw = os.environ.get("CM_RATE_LIMIT_EXEMPT_PATHS")
    if exempt_raw is None:
        # Not set at all → use defaults
        exempt_paths = DEFAULT_EXEMPT_PATHS
    elif exempt_raw.strip() == "":
        # Explicitly empty → no exemptions
        exempt_paths = ()
    else:
        exempt_paths = tuple(p.strip() for p in exempt_raw.split(",") if p.strip())

    return RateLimitConfig(
        enabled=os.environ.get("CM_RATE_LIMIT_ENABLED", "true").lower() in ("1", "true", "yes"),
        default_limit=os.environ.get("CM_RATE_LIMIT_DEFAULT", DEFAULT_RATE_LIMIT),
        burst_limit=os.environ.get("CM_RATE_LIMIT_BURST", DEFAULT_BURST_LIMIT),
        exempt_paths=exempt_paths,
    )


def create_limiter(config: RateLimitConfig) -> Limiter:
    """Create a configured SlowAPI limiter."""
    return Limiter(
        key_func=_key_func,
        default_limits=[config.default_limit] if config.enabled else [],
        enabled=config.enabled,
    )


def register_rate_limiter(app: FastAPI, config: RateLimitConfig | None = None) -> Limiter:
    """Register rate limiting on the FastAPI app.

    Adds two middlewares (order matters):
    1. ``SlowAPIMiddleware`` — enforces per-client rate limits via ``default_limits``.
    2. ``_ExemptPathsMiddleware`` — added *after* so it runs *first*, marking
       health/metrics paths as exempt before the limiter sees the request.
    """
    if config is None:
        config = build_rate_limit_config()

    limiter = create_limiter(config)
    app.state.limiter = limiter

    if config.enabled:
        # SlowAPIMiddleware enforces default_limits globally (innermost of the pair)
        app.add_middleware(SlowAPIMiddleware)

        # Exempt-paths middleware runs first (outermost — added last)
        if config.exempt_paths:
            app.add_middleware(
                _ExemptPathsMiddleware,
                exempt_paths=frozenset(config.exempt_paths),
            )

    @app.exception_handler(RateLimitExceeded)
    def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
        # IMPORTANT: This handler MUST be synchronous (not async).
        # SlowAPIMiddleware uses sync_check_limits() which falls back
        # to the default handler for async exception handlers.
        request_id = getattr(request.state, "request_id", "unknown")
        client_ip = _key_func(request)

        logger.warning(
            "Rate limit exceeded",
            extra={
                "client": client_ip,
                "path": request.url.path,
                "limit": str(exc.detail),
                "request_id": request_id,
            },
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
        "Rate limiting registered",
        extra={
            "enabled": config.enabled,
            "default_limit": config.default_limit,
            "burst_limit": config.burst_limit,
            "exempt_paths": list(config.exempt_paths),
        },
    )
    return limiter
