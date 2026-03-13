"""
certmesh.api.schemas
=====================

Pydantic request/response models for the REST API.
Strict mode: no type coercion, reject unknown fields.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# =============================================================================
# Common
# =============================================================================


class ErrorResponse(BaseModel):
    """Standard error response body."""

    model_config = ConfigDict(strict=True)

    detail: str
    request_id: str = ""


class HealthResponse(BaseModel):
    status: str
    version: str = ""


class ReadinessDetail(BaseModel):
    vault: str = "unknown"
    aws: str = "unknown"


class ReadinessResponse(BaseModel):
    status: str
    checks: ReadinessDetail = ReadinessDetail()


# =============================================================================
# DigiCert
# =============================================================================


class DigiCertOrderRequest(BaseModel):
    """Request body for ordering a DigiCert certificate."""

    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str
    san_dns_names: list[str] = []
    organisation: str = ""
    organisational_unit: str = ""
    country: str = "US"
    state: str = ""
    locality: str = ""
    validity_years: int = 1
    product_name_id: str = "ssl_plus"


class DigiCertCertificateResponse(BaseModel):
    order_id: str
    common_name: str
    status: str = ""
    serial_number: str = ""
    valid_from: str = ""
    valid_till: str = ""


class DigiCertOrderResponse(BaseModel):
    order_id: str
    common_name: str
    serial_number: str = ""
    not_after: str = ""
    written_to: dict[str, str] = {}


class DigiCertRevokeRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    reason: str = "cessation_of_operation"
    comments: str = ""


class DigiCertSearchRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str = ""
    status: str = ""
    page: int = 1
    per_page: int = 20


# =============================================================================
# Venafi
# =============================================================================


class VenafiRenewRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    key_size: int = 4096


class VenafiCertificateResponse(BaseModel):
    guid: str
    common_name: str = ""
    status: str = ""


# =============================================================================
# Vault PKI
# =============================================================================


class VaultPKIIssueRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str
    alt_names: list[str] = []
    ttl: str = ""


class VaultPKISignRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    csr_pem: str
    common_name: str
    alt_names: list[str] = []
    ttl: str = ""


class VaultPKICertificateResponse(BaseModel):
    serial_number: str
    certificate_pem: str = ""
    issuing_ca_pem: str = ""
    expiration: str = ""


# =============================================================================
# ACM
# =============================================================================


class ACMRequestCertRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    domain_name: str
    subject_alternative_names: list[str] = []
    validation_method: str = "DNS"
    key_algorithm: str = "RSA_2048"
    idempotency_token: str = ""


class ACMCertificateResponse(BaseModel):
    certificate_arn: str
    domain_name: str = ""
    status: str = ""
    not_after: str = ""


class ACMExportResponse(BaseModel):
    certificate_arn: str
    written_to: dict[str, str] = {}


class ACMValidationRecord(BaseModel):
    name: str
    type: str
    value: str


class ACMRoute53SyncRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    certificate_arn: str
    hosted_zone_id: str


class ACMRoute53SyncResponse(BaseModel):
    synced_records: int = 0
    message: str = ""


# =============================================================================
# Pagination
# =============================================================================


class PaginatedResponse(BaseModel):
    """Generic paginated wrapper."""

    items: list[dict] = []
    page: int = 1
    per_page: int = 20
    total: int = 0
