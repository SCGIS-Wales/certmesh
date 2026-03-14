"""Backward-compatibility shim -- use certmesh.backends.vault_client instead."""

from certmesh.backends.vault_client import (  # noqa: F401
    get_authenticated_client,
    issue_pki_certificate,
    list_pki_certificates,
    read_all_secret_fields,
    read_all_secret_fields_v1,
    read_all_secrets_versioned,
    read_pki_certificate,
    read_secret_field,
    read_secret_field_v1,
    read_secret_versioned,
    revoke_pki_certificate,
    sign_pki_certificate,
    write_secret,
    write_secret_v1,
    write_secret_versioned,
)
