"""
certmesh.api.routes.vault_pki
================================

Vault PKI engine API endpoints.

Spec reference:
    https://developer.hashicorp.com/vault/api-docs/secret/pki

Key lifecycle notes (from Vault PKI spec):
    - Vault PKI does NOT support certificate renewal.  The correct pattern
      is to re-issue before expiry.
    - Private keys are ONLY present in the initial ``/issue`` response
      and are never stored by Vault.
    - Certificate data is always in ``response["data"]``.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    VaultPKICertificateResponse,
    VaultPKIIssueRequest,
    VaultPKIRevokeRequest,
    VaultPKISignRequest,
)
from certmesh.exceptions import (
    ConfigurationError,
    VaultAuthenticationError,
    VaultPKIError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vault-pki", tags=["vault-pki"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


def _require_vault_client(request: Request) -> Any:
    """Return the Vault client or raise 503 if unavailable."""
    vault_cl = getattr(request.app.state, "vault_client", None)
    if vault_cl is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault client is not configured or unavailable.",
        )
    return vault_cl


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
    try:
        certs = vc.list_pki_certificates(vault_cl, cfg)
    except VaultAuthenticationError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="list", status="error").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except VaultPKIError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="list", status="error").inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="list", status="success").inc()
    return [VaultPKICertificateResponse(serial_number=s) for s in certs]


@router.post("/certificates", response_model=VaultPKICertificateResponse)
async def issue_certificate(
    request: Request,
    body: VaultPKIIssueRequest,
    claims: Any = Depends(_get_auth),
) -> VaultPKICertificateResponse:
    """Issue a new certificate via Vault PKI.

    Calls ``POST /v1/{mount}/issue/{role}`` which generates a private key
    server-side and returns it along with the certificate.  The private key
    is only available in this response and is never stored by Vault.
    """
    from certmesh.backends import vault_client as vc

    vault_cl = _require_vault_client(request)
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    try:
        result = vc.issue_pki_certificate(
            vault_cl,
            cfg,
            common_name=body.common_name,
            alt_names=body.alt_names or None,
            ttl=body.ttl or None,
            ip_sans=body.ip_sans or None,
        )
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except VaultAuthenticationError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="issue", status="error").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except VaultPKIError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="issue", status="error").inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
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

    vault_cl = _require_vault_client(request)
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    try:
        result = vc.read_pki_certificate(vault_cl, cfg, serial)
    except VaultAuthenticationError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="read", status="error").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except VaultPKIError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="read", status="error").inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
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
    """Sign a CSR using Vault PKI.

    Calls ``POST /v1/{mount}/sign/{role}``.  The private key never
    enters Vault — it stays with the caller who generated the CSR.
    """
    from certmesh.backends import vault_client as vc

    vault_cl = _require_vault_client(request)
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    try:
        result = vc.sign_pki_certificate(
            vault_cl,
            cfg,
            common_name=body.common_name,
            csr=body.csr_pem,
            alt_names=body.alt_names or None,
            ttl=body.ttl or None,
            ip_sans=body.ip_sans or None,
        )
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except VaultAuthenticationError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="sign", status="error").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except VaultPKIError as exc:
        CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="sign", status="error").inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="sign", status="success").inc()
    return VaultPKICertificateResponse(
        serial_number=result.get("serial_number", ""),
        certificate_pem=result.get("certificate", ""),
        issuing_ca_pem=result.get("issuing_ca", ""),
    )


@router.post("/revoke", response_model=VaultPKICertificateResponse)
async def revoke_certificate(
    request: Request,
    body: VaultPKIRevokeRequest,
    claims: Any = Depends(_get_auth),
) -> VaultPKICertificateResponse:
    """Revoke a certificate by serial number.

    Calls ``POST /v1/{mount}/revoke`` with the colon-separated hex serial.
    """
    from certmesh.backends import vault_client as vc

    vault_cl = _require_vault_client(request)
    cfg = request.app.state.config.get("vault", {}).get("pki", {})
    try:
        vc.revoke_pki_certificate(vault_cl, cfg, body.serial_number)
    except VaultAuthenticationError as exc:
        CERTIFICATE_OPS_TOTAL.labels(
            provider="vault_pki", operation="revoke", status="error"
        ).inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except VaultPKIError as exc:
        CERTIFICATE_OPS_TOTAL.labels(
            provider="vault_pki", operation="revoke", status="error"
        ).inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    CERTIFICATE_OPS_TOTAL.labels(provider="vault_pki", operation="revoke", status="success").inc()
    return VaultPKICertificateResponse(serial_number=body.serial_number)
