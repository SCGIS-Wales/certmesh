"""
certmesh.api.routes.health
============================

Health check endpoints: /healthz, /readyz, /livez
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Request

from certmesh import __version__
from certmesh.api.schemas import HealthResponse, ReadinessDetail, ReadinessResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    """Liveness probe — always returns OK if the process is running."""
    return HealthResponse(status="ok", version=__version__)


@router.get("/livez", response_model=HealthResponse)
async def livez() -> HealthResponse:
    """Alias for /healthz."""
    return HealthResponse(status="ok", version=__version__)


@router.get("/readyz", response_model=ReadinessResponse)
async def readiness(request: Request) -> ReadinessResponse:
    """Readiness probe — checks Vault and AWS connectivity."""
    checks = ReadinessDetail()
    overall = "ok"

    # Check Vault if configured
    vault_client = getattr(request.app.state, "vault_client", None)
    if vault_client is not None:
        try:
            if vault_client.is_authenticated():
                checks.vault = "ok"
            else:
                checks.vault = "unauthenticated"
                overall = "degraded"
        except Exception:
            checks.vault = "unreachable"
            overall = "degraded"
    else:
        checks.vault = "not_configured"

    # AWS connectivity — lightweight STS check with caching (REL-02)
    checks.aws = _get_cached_aws_status()
    if checks.aws != "ok" and getattr(request.app.state, "aws_required", False):
        overall = "degraded"

    return ReadinessResponse(status=overall, checks=checks)


# REL-02: Cache STS result to avoid calling get_caller_identity() on every probe
_sts_cache_result: str = ""
_sts_cache_time: float = 0.0
_STS_CACHE_TTL: float = 60.0  # 1 minute


def _get_cached_aws_status() -> str:
    """Return cached AWS STS connectivity status, refreshing after TTL."""
    global _sts_cache_result, _sts_cache_time

    now = time.monotonic()
    if _sts_cache_result and (now - _sts_cache_time) < _STS_CACHE_TTL:
        return _sts_cache_result

    try:
        import boto3

        sts = boto3.client("sts")
        sts.get_caller_identity()
        _sts_cache_result = "ok"
    except Exception:
        _sts_cache_result = "unavailable"

    _sts_cache_time = now
    return _sts_cache_result
