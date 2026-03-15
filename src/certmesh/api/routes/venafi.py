"""
certmesh.api.routes.venafi
============================

Venafi Trust Protection Platform (TPP) API endpoints.

Each handler extracts ``venafi_cfg``, ``vault_cfg``, and ``vault_client``
from ``request.app.state``, authenticates a Venafi session, and forwards
to the provider functions in ``certmesh.providers.venafi_client``.

Supports both TPP v23 (SDK 23.x) and v25.3 (SDK 25.3).

Spec reference:
    https://docs.venafi.com/Docs/current/TopNav/Content/SDK/WebSDK/API_reference.htm
"""

from __future__ import annotations

import dataclasses
from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    PaginatedResponse,
    VenafiCertificateDetailResponse,
    VenafiRenewRequest,
    VenafiRenewResponse,
    VenafiRevokeRequest,
    VenafiSearchRequest,
)

router = APIRouter(prefix="/api/v1/venafi", tags=["venafi"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


def _extract_venafi_deps(request: Request) -> tuple[dict, dict, Any]:
    """Extract Venafi config, Vault config, and Vault client from app state."""
    venafi_cfg = request.app.state.config["venafi"]
    vault_cfg = request.app.state.config.get("vault", {})
    vault_cl = getattr(request.app.state, "vault_client", None)
    return venafi_cfg, vault_cfg, vault_cl


@router.get("/certificates", response_model=PaginatedResponse)
async def list_certificates(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """List managed Venafi certificates.

    Calls ``vc.list_certificates`` which maps to
    ``GET /vedsdk/Certificates/`` with ``Limit`` and ``Offset`` parameters.
    """
    from certmesh.providers import venafi_client as vc

    venafi_cfg, vault_cfg, vault_cl = _extract_venafi_deps(request)
    session = vc.authenticate(venafi_cfg, vault_cfg, vault_cl)
    try:
        certs = vc.list_certificates(session, venafi_cfg, limit=limit, offset=offset)
        items = [dataclasses.asdict(c) for c in certs]
        CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="list", status="success").inc()
        return PaginatedResponse(
            items=items,
            page=(offset // limit) + 1 if limit > 0 else 1,
            per_page=limit,
            total=len(items),
        )
    finally:
        session.close()


@router.post("/certificates/search", response_model=PaginatedResponse)
async def search_certificates(
    request: Request,
    body: VenafiSearchRequest,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """Search certificates by criteria.

    Calls ``vc.search_certificates`` which forwards filters to
    ``GET /vedsdk/Certificates/`` with appropriate query parameters.
    """
    from certmesh.providers import venafi_client as vc

    venafi_cfg, vault_cfg, vault_cl = _extract_venafi_deps(request)
    session = vc.authenticate(venafi_cfg, vault_cfg, vault_cl)
    try:
        certs = vc.search_certificates(
            session,
            venafi_cfg,
            common_name=body.common_name or None,
            san_dns=body.san_dns or None,
            thumbprint=body.thumbprint or None,
            serial_number=body.serial_number or None,
            issuer=body.issuer or None,
            key_size=body.key_size,
            stage=body.stage,
            limit=body.limit,
            offset=body.offset,
        )
        items = [dataclasses.asdict(c) for c in certs]
        CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="search", status="success").inc()
        return PaginatedResponse(
            items=items,
            page=(body.offset // body.limit) + 1 if body.limit > 0 else 1,
            per_page=body.limit,
            total=len(items),
        )
    finally:
        session.close()


@router.get(
    "/certificates/{guid}",
    response_model=VenafiCertificateDetailResponse,
)
async def get_certificate(
    request: Request,
    guid: str,
    claims: Any = Depends(_get_auth),
) -> VenafiCertificateDetailResponse:
    """Get details of a specific Venafi certificate by GUID.

    Calls ``vc.describe_certificate`` which maps to
    ``GET /vedsdk/Certificates/{guid}``.
    """
    from certmesh.providers import venafi_client as vc

    venafi_cfg, vault_cfg, vault_cl = _extract_venafi_deps(request)
    session = vc.authenticate(venafi_cfg, vault_cfg, vault_cl)
    try:
        detail = vc.describe_certificate(session, venafi_cfg, certificate_guid=guid)
        CERTIFICATE_OPS_TOTAL.labels(
            provider="venafi", operation="describe", status="success"
        ).inc()
        return VenafiCertificateDetailResponse(
            guid=detail.guid,
            dn=detail.dn,
            name=detail.name,
            serial_number=detail.serial_number,
            thumbprint=detail.thumbprint,
            valid_from=detail.valid_from,
            valid_to=detail.valid_to,
            issuer=detail.issuer,
            subject=detail.subject,
            key_algorithm=detail.key_algorithm,
            key_size=detail.key_size,
            san_dns_names=detail.san_dns_names,
            stage=detail.stage,
            status=detail.status,
            in_error=detail.in_error,
        )
    finally:
        session.close()


@router.post("/certificates/{guid}/renew", response_model=VenafiRenewResponse)
async def renew_certificate(
    request: Request,
    guid: str,
    body: VenafiRenewRequest | None = None,
    claims: Any = Depends(_get_auth),
) -> VenafiRenewResponse:
    """Trigger renewal for a Venafi certificate.

    Calls ``vc.renew_and_download_certificate`` which maps to
    ``POST /vedsdk/Certificates/Renew``, polls for completion, and
    downloads the renewed certificate material.
    """
    from certmesh.providers import venafi_client as vc

    venafi_cfg, vault_cfg, vault_cl = _extract_venafi_deps(request)
    session = vc.authenticate(venafi_cfg, vault_cfg, vault_cl)
    try:
        bundle = vc.renew_and_download_certificate(
            session,
            venafi_cfg,
            vault_cfg,
            vault_cl,
            certificate_guid=guid,
        )
        CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="renew", status="success").inc()
        return VenafiRenewResponse(
            guid=guid,
            common_name=bundle.common_name,
            serial_number=bundle.serial_number,
            not_after=bundle.not_after.isoformat() if bundle.not_after else "",
        )
    finally:
        session.close()


@router.post("/certificates/{guid}/revoke")
async def revoke_certificate(
    request: Request,
    guid: str,
    body: VenafiRevokeRequest,
    claims: Any = Depends(_get_auth),
) -> dict[str, str]:
    """Revoke a certificate in Venafi TPP.

    Calls ``vc.revoke_certificate`` which maps to
    ``POST /vedsdk/Certificates/Revoke``.
    Reason codes follow RFC 5280 CRLReason (0-5).
    """
    from certmesh.providers import venafi_client as vc

    venafi_cfg, vault_cfg, vault_cl = _extract_venafi_deps(request)
    session = vc.authenticate(venafi_cfg, vault_cfg, vault_cl)
    try:
        # Resolve DN from GUID for the revocation call
        detail = vc.describe_certificate(session, venafi_cfg, certificate_guid=guid)
        vc.revoke_certificate(
            session,
            venafi_cfg,
            certificate_dn=detail.dn,
            reason=body.reason,
            comments=body.comments,
            disable=body.disable,
        )
        CERTIFICATE_OPS_TOTAL.labels(provider="venafi", operation="revoke", status="success").inc()
        return {"status": "revoked", "guid": guid}
    finally:
        session.close()
