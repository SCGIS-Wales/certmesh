"""
certmesh.api.routes.acm
=========================

AWS ACM API endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    ACMCertificateResponse,
    ACMExportResponse,
    ACMRequestCertRequest,
    ACMRoute53SyncRequest,
    ACMRoute53SyncResponse,
    ACMValidationRecord,
    PaginatedResponse,
)

router = APIRouter(prefix="/api/v1/acm", tags=["acm"])


def _get_auth(request: Request) -> JWTBearer:
    return request.app.state.jwt_bearer


@router.get("/certificates", response_model=PaginatedResponse)
async def list_certificates(
    request: Request,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """List ACM certificates."""
    from certmesh import acm_client

    cfg = request.app.state.config["acm"]
    certs = acm_client.list_certificates(cfg)
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="list", status="success").inc()
    return PaginatedResponse(items=certs, total=len(certs))


@router.post("/certificates", response_model=ACMCertificateResponse)
async def request_certificate(
    request: Request,
    body: ACMRequestCertRequest,
    claims: Any = Depends(_get_auth),
) -> ACMCertificateResponse:
    """Request a new ACM certificate."""
    from certmesh import acm_client

    cfg = request.app.state.config["acm"]
    result = acm_client.request_certificate(
        cfg,
        domain_name=body.domain_name,
        subject_alternative_names=body.subject_alternative_names,
        validation_method=body.validation_method,
        key_algorithm=body.key_algorithm,
        idempotency_token=body.idempotency_token,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="request", status="success").inc()
    return ACMCertificateResponse(
        certificate_arn=result.get("CertificateArn", ""),
        domain_name=body.domain_name,
        status="PENDING_VALIDATION",
    )


@router.get("/certificates/{cert_arn:path}/validation-records")
async def get_validation_records(
    request: Request,
    cert_arn: str,
    claims: Any = Depends(_get_auth),
) -> list[ACMValidationRecord]:
    """Get DNS validation records for an ACM certificate."""
    from certmesh import acm_client

    cfg = request.app.state.config["acm"]
    records = acm_client.get_validation_records(cfg, cert_arn)
    return [
        ACMValidationRecord(
            name=r.get("Name", ""),
            type=r.get("Type", ""),
            value=r.get("Value", ""),
        )
        for r in records
    ]


@router.post("/certificates/{cert_arn:path}/export", response_model=ACMExportResponse)
async def export_certificate(
    request: Request,
    cert_arn: str,
    claims: Any = Depends(_get_auth),
) -> ACMExportResponse:
    """Export a certificate from ACM."""
    from certmesh import acm_client

    cfg = request.app.state.config["acm"]
    vault_cl = getattr(request.app.state, "vault_client", None)
    result = acm_client.export_certificate(cfg, cert_arn, vault_client=vault_cl)
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="export", status="success").inc()
    return ACMExportResponse(
        certificate_arn=cert_arn,
        written_to=result.get("written_to", {}),
    )


@router.post("/route53/sync", response_model=ACMRoute53SyncResponse)
async def sync_route53_records(
    request: Request,
    body: ACMRoute53SyncRequest,
    claims: Any = Depends(_get_auth),
) -> ACMRoute53SyncResponse:
    """Create Route53 DNS records for ACM certificate validation."""
    from certmesh import route53_client

    records = route53_client.sync_validation_records(
        hosted_zone_id=body.hosted_zone_id,
        certificate_arn=body.certificate_arn,
        acm_cfg=request.app.state.config["acm"],
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="route53_sync", status="success").inc()
    return ACMRoute53SyncResponse(
        synced_records=records,
        message=f"Synced {records} DNS validation record(s) to Route53",
    )
