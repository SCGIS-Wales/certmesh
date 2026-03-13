"""
certmesh.api.routes.health
============================

Health check endpoints: /healthz, /readyz, /livez
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from certmesh.api.schemas import HealthResponse, ReadinessDetail, ReadinessResponse

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    """Liveness probe — always returns OK if the process is running."""
    return HealthResponse(status="ok", version="3.0.0")


@router.get("/livez", response_model=HealthResponse)
async def livez() -> HealthResponse:
    """Alias for /healthz."""
    return HealthResponse(status="ok", version="3.0.0")


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

    # AWS connectivity — lightweight STS check
    try:
        import boto3

        sts = boto3.client("sts")
        sts.get_caller_identity()
        checks.aws = "ok"
    except Exception:
        checks.aws = "unavailable"
        # Don't mark degraded if AWS is optional
        if getattr(request.app.state, "aws_required", False):
            overall = "degraded"

    return ReadinessResponse(status=overall, checks=checks)
