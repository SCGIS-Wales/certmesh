"""
certmesh.api.routes.vault_pki
================================

Vault PKI engine API endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    VaultPKICertificateResponse,
    VaultPKIIssueRequest,
    VaultPKISignRequest,
)

router = APIRouter(prefix="/api/v1/vault-pki", tags=["vault-pki"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


@router.get("/certificates")
async def list_certificates(
    request: Request,
    claims: Any = Depends(_get_auth),
) -> list[VaultPKICertificateResponse]:
    """List certificates issued by Vault PKI."""
    from certmesh.backends import vault_client as vc

    vault_cl = getattr(request.app.state, "vault_client", None)
    if vault_cl is None:
        return []

    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    certs = vc.list_pki_certificates(vault_cl, cfg)
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="list", status="success").inc()
    return [VaultPKICertificateResponse(serial_number=s) for s in certs]


@router.post("/certificates", response_model=VaultPKICertificateResponse)
async def issue_certificate(
    request: Request,
    body: VaultPKIIssueRequest,
    claims: Any = Depends(_get_auth),
) -> VaultPKICertificateResponse:
    """Issue a new certificate via Vault PKI."""
    from certmesh.backends import vault_client as vc

    vault_cl = request.app.state.vault_client
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    result = vc.issue_pki_certificate(
        vault_cl,
        cfg,
        common_name=body.common_name,
        alt_names=body.alt_names,
        ttl=body.ttl,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="issue", status="success").inc()
    return VaultPKICertificateResponse(
        serial_number=result.get("serial_number", ""),
        certificate_pem=result.get("certificate", ""),
        issuing_ca_pem=result.get("issuing_ca", ""),
        expiration=str(result.get("expiration", "")),
    )


@router.get("/certificates/{serial}", response_model=VaultPKICertificateResponse)
async def get_certificate(
    request: Request,
    serial: str,
    claims: Any = Depends(_get_auth),
) -> VaultPKICertificateResponse:
    """Read a specific certificate by serial number."""
    from certmesh.backends import vault_client as vc

    vault_cl = request.app.state.vault_client
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    result = vc.read_pki_certificate(vault_cl, cfg, serial)
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="read", status="success").inc()
    return VaultPKICertificateResponse(
        serial_number=serial,
        certificate_pem=result.get("certificate", ""),
    )


@router.post("/sign", response_model=VaultPKICertificateResponse)
async def sign_csr(
    request: Request,
    body: VaultPKISignRequest,
    claims: Any = Depends(_get_auth),
) -> VaultPKICertificateResponse:
    """Sign a CSR using Vault PKI."""
    from certmesh.backends import vault_client as vc

    vault_cl = request.app.state.vault_client
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    result = vc.sign_pki_csr(
        vault_cl,
        cfg,
        csr_pem=body.csr_pem,
        common_name=body.common_name,
        alt_names=body.alt_names,
        ttl=body.ttl,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="sign", status="success").inc()
    return VaultPKICertificateResponse(
        serial_number=result.get("serial_number", ""),
        certificate_pem=result.get("certificate", ""),
        issuing_ca_pem=result.get("issuing_ca", ""),
    )
