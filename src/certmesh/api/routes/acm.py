"""
certmesh.api.routes.acm
=========================

AWS Certificate Manager (ACM) API endpoints.

Each handler extracts ``acm_cfg`` and optionally ``vault_client`` from
``request.app.state``, then delegates to provider functions in
``certmesh.providers.acm_client``.

Spec references:
    - ACM API: https://docs.aws.amazon.com/acm/latest/APIReference/
    - All ACM API calls are HTTP POST to ``https://acm.{region}.amazonaws.com/``
      with ``Content-Type: application/x-amz-json-1.1``.
    - Operations are specified via the ``X-Amz-Target`` header using
      ``CertificateManager.{OperationName}``.

Rate limits:
    - ACM uses AWS standard throttling (``ThrottlingException``).
    - Retryable errors: ``ThrottlingException``, ``RequestInProgressException``,
      ``ConflictException``.

ExportCertificate:
    - Requires a passphrase (4-128 ASCII chars, excluding #, $, %).
    - As of June 17, 2025, ACM public certificates can also be exported.
      Certificates created before that date cannot be exported.
    - Private CA certificates have always been exportable.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from fastapi import APIRouter, Depends, Request

from certmesh.api.auth import JWTBearer
from certmesh.api.metrics import CERTIFICATE_OPS_TOTAL
from certmesh.api.schemas import (
    ACMCertificateDetailResponse,
    ACMCertificateResponse,
    ACMExportRequest,
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


def _extract_acm_deps(request: Request) -> tuple[dict, Any]:
    """Extract ACM config and Vault client from app state."""
    acm_cfg = request.app.state.config["acm"]
    vault_cl = getattr(request.app.state, "vault_client", None)
    return acm_cfg, vault_cl


@router.get("/certificates", response_model=PaginatedResponse)
async def list_certificates(
    request: Request,
    claims: Any = Depends(_get_auth),
) -> PaginatedResponse:
    """List ACM certificates.

    Spec: ``CertificateManager.ListCertificates``
    Uses paginator to retrieve all certificates in the configured region.
    Returns ``ACMCertificateSummary`` objects converted to dicts.
    """
    from certmesh.providers import acm_client

    acm_cfg, _vault_cl = _extract_acm_deps(request)
    certs = acm_client.list_certificates(acm_cfg)
    items = [dataclasses.asdict(c) for c in certs]
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="list", status="success").inc()
    return PaginatedResponse(items=items, total=len(items))


@router.post("/certificates", response_model=ACMCertificateResponse)
async def request_certificate(
    request: Request,
    body: ACMRequestCertRequest,
    claims: Any = Depends(_get_auth),
) -> ACMCertificateResponse:
    """Request a new ACM certificate.

    Spec: ``CertificateManager.RequestCertificate``
    Returns the ARN of the newly requested certificate with
    ``PENDING_VALIDATION`` status.

    Valid key algorithms: ``RSA_2048``, ``RSA_3072``, ``RSA_4096``,
    ``EC_prime256v1``, ``EC_secp384r1``, ``EC_secp521r1``.
    Valid validation methods: ``DNS`` (recommended) or ``EMAIL``.
    """
    from certmesh.providers import acm_client

    acm_cfg, _vault_cl = _extract_acm_deps(request)

    # Convert tags from list[dict[str, str]] to list[JsonDict] for boto3
    tags = [{"Key": t["Key"], "Value": t["Value"]} for t in body.tags] if body.tags else None

    # acm_client.request_certificate returns a string ARN, not a dict.
    certificate_arn: str = acm_client.request_certificate(
        acm_cfg,
        domain_name=body.domain_name,
        subject_alternative_names=body.subject_alternative_names or None,
        validation_method=body.validation_method,
        key_algorithm=body.key_algorithm,
        idempotency_token=body.idempotency_token or None,
        tags=tags,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="request", status="success").inc()
    return ACMCertificateResponse(
        certificate_arn=certificate_arn,
        domain_name=body.domain_name,
        status="PENDING_VALIDATION",
        key_algorithm=body.key_algorithm,
    )


@router.get(
    "/certificates/{cert_arn:path}/detail",
    response_model=ACMCertificateDetailResponse,
)
async def describe_certificate(
    request: Request,
    cert_arn: str,
    claims: Any = Depends(_get_auth),
) -> ACMCertificateDetailResponse:
    """Get full details of an ACM certificate.

    Spec: ``CertificateManager.DescribeCertificate``
    Returns the full ``CertificateDetail`` metadata for the given ARN.
    """
    from certmesh.providers import acm_client

    acm_cfg, _vault_cl = _extract_acm_deps(request)
    detail = acm_client.describe_certificate(acm_cfg, cert_arn)
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="describe", status="success").inc()
    return ACMCertificateDetailResponse(
        certificate_arn=detail.certificate_arn,
        domain_name=detail.domain_name,
        subject_alternative_names=detail.subject_alternative_names,
        status=detail.status,
        type=detail.type,
        key_algorithm=detail.key_algorithm,
        serial=detail.serial,
        issuer=detail.issuer,
        not_before=detail.not_before.isoformat() if detail.not_before else "",
        not_after=detail.not_after.isoformat() if detail.not_after else "",
        created_at=detail.created_at.isoformat() if detail.created_at else "",
        renewal_eligibility=detail.renewal_eligibility,
        in_use_by=detail.in_use_by,
        failure_reason=detail.failure_reason,
    )


@router.get("/certificates/{cert_arn:path}/validation-records")
async def get_validation_records(
    request: Request,
    cert_arn: str,
    claims: Any = Depends(_get_auth),
) -> list[ACMValidationRecord]:
    """Get DNS/email validation records for an ACM certificate.

    Spec: ``CertificateManager.DescribeCertificate`` ->
    ``DomainValidationOptions[].ResourceRecord``

    Returns validation records needed to prove domain ownership.
    For DNS validation, the ``resource_record_*`` fields contain the
    CNAME record that must be created in DNS.
    """
    from certmesh.providers import acm_client

    acm_cfg, _vault_cl = _extract_acm_deps(request)
    # acm_client.get_validation_records returns ACMValidationRecord dataclass
    # objects, not dicts.
    records = acm_client.get_validation_records(acm_cfg, cert_arn)
    return [
        ACMValidationRecord(
            domain_name=r.domain_name,
            validation_method=r.validation_method,
            validation_status=r.validation_status,
            resource_record_name=r.resource_record_name,
            resource_record_type=r.resource_record_type,
            resource_record_value=r.resource_record_value,
        )
        for r in records
    ]


@router.post("/certificates/{cert_arn:path}/export", response_model=ACMExportResponse)
async def export_certificate(
    request: Request,
    cert_arn: str,
    body: ACMExportRequest,
    claims: Any = Depends(_get_auth),
) -> ACMExportResponse:
    """Export a certificate and private key from ACM.

    Spec: ``CertificateManager.ExportCertificate``
    Requires a passphrase (4-128 ASCII chars, excluding #, $, %).

    As of June 17, 2025, ACM public certificates can also be exported.
    Certificates created before that date cannot be exported.
    Private CA certificates have always been exportable.

    Uses ``export_and_persist`` to export the certificate bundle and
    optionally persist it to Vault or the filesystem.
    """
    from certmesh.providers import acm_client

    acm_cfg, vault_cl = _extract_acm_deps(request)
    passphrase_bytes = body.passphrase.encode("utf-8")

    # export_and_persist combines export_certificate + persist_bundle.
    # It requires passphrase as bytes and optionally writes to Vault.
    written = acm_client.export_and_persist(
        acm_cfg,
        cert_arn,
        passphrase_bytes,
        vault_client=vault_cl,
    )
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="export", status="success").inc()
    return ACMExportResponse(
        certificate_arn=cert_arn,
        written_to=written,
    )


@router.delete("/certificates/{cert_arn:path}")
async def delete_certificate(
    request: Request,
    cert_arn: str,
    claims: Any = Depends(_get_auth),
) -> dict[str, str]:
    """Delete an ACM certificate.

    Spec: ``CertificateManager.DeleteCertificate``
    The certificate must not be associated with any AWS resource
    (ALB, CloudFront, API Gateway, etc.) or the call will fail
    with ``ResourceInUseException``.
    """
    from certmesh.providers import acm_client

    acm_cfg, _vault_cl = _extract_acm_deps(request)
    acm_client.delete_certificate(acm_cfg, cert_arn)
    CERTIFICATE_OPS_TOTAL.labels(provider="acm", operation="delete", status="success").inc()
    return {"status": "deleted", "certificate_arn": cert_arn}


@router.post("/route53/sync", response_model=ACMRoute53SyncResponse)
async def sync_route53_records(
    request: Request,
    body: ACMRoute53SyncRequest,
    claims: Any = Depends(_get_auth),
) -> ACMRoute53SyncResponse:
    """Create Route53 DNS records for ACM certificate validation.

    Spec: Creates CNAME records in Route53 that ACM needs for DNS
    domain validation.  The CNAME record must remain present for the
    lifetime of the certificate to enable managed automatic renewal.

    ACM polls DNS approximately every 15 minutes; validation typically
    completes within 30 minutes of correct DNS propagation.
    """
    from certmesh.backends import route53_client

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
