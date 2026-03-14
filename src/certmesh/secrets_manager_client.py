"""Backward-compatibility shim -- use certmesh.backends.secrets_manager_client instead."""

from certmesh.backends.secrets_manager_client import (  # noqa: F401
    read_secret,
    write_secret,
)
