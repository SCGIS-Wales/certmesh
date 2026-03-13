"""
certmesh.api.routes.digicert
==============================

DigiCert CertCentral API endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    DigiCertCertificateResponse,
    DigiCertOrderRequest,
    DigiCertOrderResponse,
    DigiCertRevokeRequest,
    DigiCertSearchRequest,
    PaginatedResponse,
)

router = APIRouter(prefix="/api/v1/digicert", tags=["digicert"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


@router.get("/certificates", response_model=PaginatedResponse)
async def list_certificates(
    request: Request,
    page: int = 1,
    per_page: int = 20,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """List issued certificates."""
    from certmesh import digicert_client as dc

    cfg = request.app.state.config["digicert"]
    session = dc._build_session(cfg)
    data = dc.list_issued_certificates(session, cfg, page=page, per_page=per_page)
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="list", status="success").inc()
    return PaginatedResponse(
        items=data.get("certificates", []),
        page=page,
        per_page=per_page,
        total=data.get("total", 0),
    )


@router.post("/certificates/search", response_model=PaginatedResponse)
async def search_certificates(
    request: Request,
    body: DigiCertSearchRequest,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """Search certificates by criteria."""
    from certmesh import digicert_client as dc

    cfg = request.app.state.config["digicert"]
    session = dc._build_session(cfg)
    data = dc.search_certificates(
        session,
        cfg,
        common_name=body.common_name,
        status=body.status,
        page=body.page,
        per_page=body.per_page,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="search", status="success").inc()
    return PaginatedResponse(
        items=data.get("certificates", []),
        page=body.page,
        per_page=body.per_page,
        total=data.get("total", 0),
    )


@router.get("/certificates/{order_id}", response_model=DigiCertCertificateResponse)
async def get_certificate(
    request: Request,
    order_id: str,
    claims: Any = Depends(_get_auth),
) -> DigiCertCertificateResponse:
    """Get details of a specific certificate order."""
    from certmesh import digicert_client as dc

    cfg = request.app.state.config["digicert"]
    session = dc._build_session(cfg)
    data = dc.describe_certificate(session, cfg, order_id)
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="describe", status="success").inc()
    return DigiCertCertificateResponse(
        order_id=str(data.get("id", order_id)),
        common_name=data.get("certificate", {}).get("common_name", ""),
        status=data.get("status", ""),
        serial_number=data.get("certificate", {}).get("serial_number", ""),
    )


@router.post("/orders", response_model=DigiCertOrderResponse)
async def order_certificate(
    request: Request,
    body: DigiCertOrderRequest,
    claims: Any = Depends(_get_auth),
) -> DigiCertOrderResponse:
    """Order a new certificate and await issuance."""
    from certmesh import digicert_client as dc
    from certmesh.certificate_utils import SubjectInfo

    cfg = request.app.state.config["digicert"]
    vault_cl = getattr(request.app.state, "vault_client", None)

    subject = SubjectInfo(
        common_name=body.common_name,
        san_dns_names=body.san_dns_names,
        organisation=body.organisation,
        organisational_unit=body.organisational_unit,
        country=body.country,
        state=body.state,
        locality=body.locality,
    )

    result = dc.order_and_await_certificate(
        cfg,
        subject,
        vault_client=vault_cl,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="order", status="success").inc()
    return DigiCertOrderResponse(
        order_id=str(result.get("order_id", "")),
        common_name=body.common_name,
        serial_number=result.get("serial_number", ""),
        not_after=result.get("not_after", ""),
        written_to=result.get("written_to", {}),
    )


@router.post("/certificates/{order_id}/revoke")
async def revoke_certificate(
    request: Request,
    order_id: str,
    body: DigiCertRevokeRequest,
    claims: Any = Depends(_get_auth),
) -> dict[str, str]:
    """Revoke a certificate."""
    from certmesh import digicert_client as dc

    cfg = request.app.state.config["digicert"]
    session = dc._build_session(cfg)
    dc.revoke_certificate(session, cfg, order_id, reason=body.reason, comments=body.comments)
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="revoke", status="success").inc()
    return {"status": "revoked", "order_id": order_id}
