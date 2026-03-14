"""Backward-compatibility shim -- use certmesh.backends.route53_client instead."""

from certmesh.backends.route53_client import (  # noqa: F401
    delete_validation_records,
    sync_validation_records,
)
