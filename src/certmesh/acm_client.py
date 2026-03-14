"""Backward-compatibility shim -- use certmesh.providers.acm_client instead."""

from certmesh.providers.acm_client import (  # noqa: F401
    ACMCertificateDetail,
    ACMCertificateSummary,
    ACMValidationRecord,
    arn_short_id,
    delete_certificate,
    describe_certificate,
    export_and_persist,
    export_certificate,
    get_private_certificate,
    get_validation_records,
    issue_private_certificate,
    list_certificates,
    list_private_certificates,
    renew_certificate,
    request_certificate,
    revoke_private_certificate,
    wait_for_issuance,
)
