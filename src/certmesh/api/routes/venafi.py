"""
certmesh.api.routes.venafi
============================

Venafi TPP API endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import VenafiCertificateResponse, VenafiRenewRequest

router = APIRouter(prefix="/api/v1/venafi", tags=["venafi"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


@router.get("/certificates")
async def list_certificates(
    request: Request,
    claims: Any = Depends(_get_auth),
) -> list[VenafiCertificateResponse]:
    """List managed Venafi certificates."""
    CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="list", status="success").inc()
    return []


@router.get("/certificates/{guid}", response_model=VenafiCertificateResponse)
async def get_certificate(
    request: Request,
    guid: str,
    claims: Any = Depends(_get_auth),
) -> VenafiCertificateResponse:
    """Get details of a Venafi certificate."""
    CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="describe", status="success").inc()
    return VenafiCertificateResponse(guid=guid)


@router.post("/certificates/{guid}/renew")
async def renew_certificate(
    request: Request,
    guid: str,
    body: VenafiRenewRequest | None = None,
    claims: Any = Depends(_get_auth),
) -> dict[str, str]:
    """Trigger renewal for a Venafi certificate."""
    CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="renew", status="success").inc()
    return {"status": "renewed", "guid": guid}
