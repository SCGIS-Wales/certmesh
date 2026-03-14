"""Backward-compatibility shim -- use certmesh.providers.venafi_client instead."""

from certmesh.providers.venafi_client import (  # noqa: F401
    REVOCATION_REASONS,
    VenafiCertificateDetail,
    VenafiCertificateSummary,
    authenticate,
    describe_certificate,
    list_certificates,
    renew_and_download_certificate,
    request_certificate,
    revoke_certificate,
    search_certificates,
)
