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
    """Request body for ordering a DigiCert certificate.

    Uses ``order_validity`` (``years`` or ``days``) per CertCentral API v2 spec.
    Max certificate validity is 199 days as of Feb 2026.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str
    san_dns_names: list[str] = []
    organisation: str = ""
    organisational_unit: str = ""
    country: str = "US"
    state: str = ""
    locality: str = ""
    validity_years: int = 1
    validity_days: int | None = None  # Alternative to years; max 199
    product_name_id: str = "ssl_plus"
    payment_method: str = "balance"  # "balance" or "card"
    dcv_method: str = ""  # "dns-txt-token", "dns-cname-token", "email", "http-token"


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
    """Request body for revoking a DigiCert certificate.

    Valid reasons per CertCentral API v2 spec: ``unspecified``,
    ``key_compromise``, ``affiliation_change``, ``superseded``,
    ``cessation_of_operation``.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    reason: str = "unspecified"
    comments: str = ""


class DigiCertSearchRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str = ""
    status: str = ""
    page: int = 1
    per_page: int = 20


# =============================================================================
# Venafi TPP
# =============================================================================


class VenafiSearchRequest(BaseModel):
    """Search filters for Venafi certificates.

    Filter names map to Venafi TPP ``GET /vedsdk/Certificates/`` query
    parameters: ``CN``, ``SAN-DNS``, ``Thumbprint``, ``Serial``, etc.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str = ""
    san_dns: str = ""
    thumbprint: str = ""
    serial_number: str = ""
    issuer: str = ""
    key_size: int | None = None
    stage: int | None = None
    limit: int = 100
    offset: int = 0


class VenafiRenewRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    key_size: int = 4096


class VenafiCertificateResponse(BaseModel):
    """Lightweight certificate summary returned by list/search."""

    guid: str
    dn: str = ""
    name: str = ""
    common_name: str = ""
    status: str = ""
    created_on: str = ""
    approx_not_after: str = ""


class VenafiCertificateDetailResponse(BaseModel):
    """Detailed certificate info returned by the describe endpoint."""

    guid: str
    dn: str = ""
    name: str = ""
    serial_number: str = ""
    thumbprint: str = ""
    valid_from: str = ""
    valid_to: str = ""
    issuer: str = ""
    subject: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    san_dns_names: list[str] = []
    stage: int = 0
    status: str = ""
    in_error: bool = False


class VenafiRenewResponse(BaseModel):
    """Response for certificate renewal."""

    guid: str
    common_name: str = ""
    serial_number: str = ""
    not_after: str = ""


class VenafiRevokeRequest(BaseModel):
    """Request body for revoking a Venafi certificate.

    Spec reference: ``POST /vedsdk/Certificates/Revoke``
    Reason codes follow RFC 5280 CRLReason (0-5).
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    reason: int = 0
    comments: str = ""
    disable: bool = False


# =============================================================================
# Vault PKI
# =============================================================================


class VaultPKIIssueRequest(BaseModel):
    """Request body for issuing a certificate via Vault PKI.

    Spec reference: ``POST /v1/{mount}/issue/{role}``
    ``alt_names`` and ``ip_sans`` are comma-joined before sending to Vault.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    common_name: str
    alt_names: list[str] = []
    ip_sans: list[str] = []
    ttl: str = ""


class VaultPKISignRequest(BaseModel):
    """Request body for signing a CSR via Vault PKI.

    Spec reference: ``POST /v1/{mount}/sign/{role}``
    The private key never enters Vault — it stays with the caller.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    csr_pem: str
    common_name: str
    alt_names: list[str] = []
    ip_sans: list[str] = []
    ttl: str = ""


class VaultPKIRevokeRequest(BaseModel):
    """Request body for revoking a certificate via Vault PKI.

    Spec reference: ``POST /v1/{mount}/revoke``
    The serial_number must be colon-separated hex (e.g. ``3a:bc:12:...``).
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    serial_number: str


class VaultPKICertificateResponse(BaseModel):
    serial_number: str
    certificate_pem: str = ""
    issuing_ca_pem: str = ""
    expiration: str = ""


# =============================================================================
# ACM
# =============================================================================


class ACMRequestCertRequest(BaseModel):
    """Request body for requesting a new ACM certificate.

    Spec reference: ``CertificateManager.RequestCertificate``
    Valid key algorithms: ``RSA_2048``, ``RSA_3072``, ``RSA_4096``,
    ``EC_prime256v1``, ``EC_secp384r1``, ``EC_secp521r1``.
    Valid validation methods: ``DNS`` (recommended) or ``EMAIL``.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    domain_name: str
    subject_alternative_names: list[str] = []
    validation_method: str = "DNS"
    key_algorithm: str = "RSA_2048"
    idempotency_token: str = ""
    tags: list[dict[str, str]] = []


class ACMCertificateResponse(BaseModel):
    """Certificate summary returned by request and describe operations."""

    certificate_arn: str
    domain_name: str = ""
    status: str = ""
    not_after: str = ""
    key_algorithm: str = ""
    type: str = ""


class ACMCertificateDetailResponse(BaseModel):
    """Full certificate detail returned by the describe endpoint.

    Maps to the ``CertificateDetail`` structure from
    ``CertificateManager.DescribeCertificate``.
    """

    certificate_arn: str
    domain_name: str = ""
    subject_alternative_names: list[str] = []
    status: str = ""
    type: str = ""
    key_algorithm: str = ""
    serial: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    created_at: str = ""
    renewal_eligibility: str = ""
    in_use_by: list[str] = []
    failure_reason: str = ""


class ACMExportRequest(BaseModel):
    """Request body for exporting a certificate from ACM.

    Spec reference: ``CertificateManager.ExportCertificate``
    The passphrase encrypts the exported private key (PKCS#8).
    Must be 4-128 ASCII characters (excluding ``#``, ``$``, ``%``).

    Note: As of June 17, 2025 ACM public certificates can also be exported.
    Certificates created before that date cannot be exported.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    passphrase: str


class ACMExportResponse(BaseModel):
    """Response for certificate export operations."""

    certificate_arn: str
    written_to: dict[str, str] = {}


class ACMValidationRecord(BaseModel):
    """A DNS or email validation record for a pending ACM certificate.

    Maps to ``DomainValidationOptions[].ResourceRecord`` from
    ``CertificateManager.DescribeCertificate``.
    """

    domain_name: str = ""
    validation_method: str = ""
    validation_status: str = ""
    resource_record_name: str = ""
    resource_record_type: str = ""
    resource_record_value: str = ""


class ACMRoute53SyncRequest(BaseModel):
    """Request body for syncing ACM DNS validation records to Route53.

    Creates CNAME records in the specified Route53 hosted zone for
    ACM certificate DNS validation.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    certificate_arn: str
    hosted_zone_id: str


class ACMRoute53SyncResponse(BaseModel):
    """Response for Route53 DNS validation sync."""

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
