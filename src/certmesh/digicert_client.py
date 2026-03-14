"""Backward-compatibility shim -- use certmesh.providers.digicert_client instead."""

from certmesh.providers.digicert_client import (  # noqa: F401
    DigiCertCertificateDetail,
    IssuedCertificateSummary,
    OrderRequest,
    describe_certificate,
    download_issued_certificate,
    duplicate_certificate,
    list_issued_certificates,
    order_and_await_certificate,
    revoke_certificate,
    search_certificates,
)
