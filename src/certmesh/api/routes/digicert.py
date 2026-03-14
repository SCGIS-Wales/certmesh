"""
certmesh.api.routes.digicert
==============================

DigiCert CertCentral API endpoints.

Each handler extracts ``digicert_cfg``, ``vault_cfg``, and ``vault_client``
from ``request.app.state`` and forwards them to the provider functions in
``certmesh.providers.digicert_client``.

Spec reference: https://dev.digicert.com/en/certcentral-apis.html
"""

from __future__ import annotations

import dataclasses
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


def _extract_digicert_deps(request: Request) -> tuple[dict, dict, Any]:
    """Extract DigiCert config, Vault config, and Vault client from app state."""
    digicert_cfg = request.app.state.config["digicert"]
    vault_cfg = request.app.state.config.get("vault", {})
    vault_cl = getattr(request.app.state, "vault_client", None)
    return digicert_cfg, vault_cfg, vault_cl


@router.get("/certificates", response_model=PaginatedResponse)
async def list_certificates(
    request: Request,
    page: int = 1,
    per_page: int = 20,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """List issued certificates.

    Calls ``dc.list_issued_certificates`` which paginates through
    ``GET /order/certificate`` on the DigiCert CertCentral API.
    """
    from certmesh.providers import digicert_client as dc

    digicert_cfg, vault_cfg, vault_cl = _extract_digicert_deps(request)
    certs = dc.list_issued_certificates(
        digicert_cfg,
        vault_cfg,
        vault_cl,
        page_size=per_page,
    )
    # Convert dataclass instances to dicts for the paginated response.
    items = [dataclasses.asdict(c) for c in certs]
    # Client-side pagination slice (the provider fetches all pages internally).
    start = (page - 1) * per_page
    page_items = items[start : start + per_page]
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="list", status="success").inc()
    return PaginatedResponse(
        items=page_items,
        page=page,
        per_page=per_page,
        total=len(items),
    )


@router.post("/certificates/search", response_model=PaginatedResponse)
async def search_certificates(
    request: Request,
    body: DigiCertSearchRequest,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """Search certificates by criteria.

    Calls ``dc.search_certificates`` which forwards server-side filters
    (``common_name``, ``status``) to ``GET /order/certificate?filters[...]=``.
    """
    from certmesh.providers import digicert_client as dc

    digicert_cfg, vault_cfg, vault_cl = _extract_digicert_deps(request)
    certs = dc.search_certificates(
        digicert_cfg,
        vault_cfg,
        vault_cl,
        common_name=body.common_name or None,
        status=body.status or None,
    )
    items = [dataclasses.asdict(c) for c in certs]
    start = (body.page - 1) * body.per_page
    page_items = items[start : start + body.per_page]
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="search", status="success").inc()
    return PaginatedResponse(
        items=page_items,
        page=body.page,
        per_page=body.per_page,
        total=len(items),
    )


@router.get("/certificates/{certificate_id}", response_model=DigiCertCertificateResponse)
async def get_certificate(
    request: Request,
    certificate_id: int,
    claims: Any = Depends(_get_auth),
) -> DigiCertCertificateResponse:
    """Get details of a specific certificate.

    Calls ``dc.describe_certificate`` which maps to
    ``GET /order/certificate/{id}`` on the DigiCert API.
    """
    from certmesh.providers import digicert_client as dc

    digicert_cfg, vault_cfg, vault_cl = _extract_digicert_deps(request)
    detail = dc.describe_certificate(digicert_cfg, vault_cfg, vault_cl, certificate_id)
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="describe", status="success").inc()
    return DigiCertCertificateResponse(
        order_id=str(detail.order_id),
        common_name=detail.common_name,
        status=detail.status,
        serial_number=detail.serial_number,
        valid_from=detail.valid_from,
        valid_till=detail.valid_till,
    )


@router.post("/orders", response_model=DigiCertOrderResponse)
async def order_certificate(
    request: Request,
    body: DigiCertOrderRequest,
    claims: Any = Depends(_get_auth),
) -> DigiCertOrderResponse:
    """Order a new certificate and await issuance.

    Builds an ``OrderRequest``, then calls ``dc.order_and_await_certificate``
    which submits to ``POST /order/certificate/{product_name_id}`` and polls
    until the certificate is issued.
    """
    from certmesh.providers import digicert_client as dc

    digicert_cfg, vault_cfg, vault_cl = _extract_digicert_deps(request)

    order_req = dc.OrderRequest(
        common_name=body.common_name,
        san_dns_names=body.san_dns_names,
        organisation=body.organisation,
        organisational_unit=body.organisational_unit,
        country=body.country,
        state=body.state,
        locality=body.locality,
        product_name_id=body.product_name_id,
        validity_years=body.validity_years,
        validity_days=body.validity_days,
        payment_method=body.payment_method,
        dcv_method=body.dcv_method,
    )

    bundle = dc.order_and_await_certificate(digicert_cfg, vault_cfg, vault_cl, order_req)
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="order", status="success").inc()
    return DigiCertOrderResponse(
        order_id=bundle.source_id,
        common_name=bundle.common_name,
        serial_number=bundle.serial_number,
        not_after=bundle.not_after.isoformat() if bundle.not_after else "",
    )


@router.post("/certificates/{order_id}/revoke")
async def revoke_certificate(
    request: Request,
    order_id: int,
    body: DigiCertRevokeRequest,
    claims: Any = Depends(_get_auth),
) -> dict[str, str]:
    """Revoke a certificate by order ID.

    Calls ``dc.revoke_certificate`` which maps to
    ``PUT /certificate/{id}/revoke`` on the DigiCert API.
    The ``revocation_reason`` field name and valid reason codes follow the
    CertCentral API v2 spec.
    """
    from certmesh.providers import digicert_client as dc

    digicert_cfg, vault_cfg, vault_cl = _extract_digicert_deps(request)
    dc.revoke_certificate(
        digicert_cfg,
        vault_cfg,
        vault_cl,
        order_id=order_id,
        reason=body.reason,
        comments=body.comments,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="digicert", operation="revoke", status="success").inc()
    return {"status": "revoked", "order_id": str(order_id)}
