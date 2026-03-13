"""
certmesh.credentials
=====================

Secret resolution with environment-first, Vault-fallback semantics.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import hvac

from certmesh.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

_ENV_DIGICERT_API_KEY = "CM_DIGICERT_API_KEY"
_ENV_VENAFI_USERNAME = "CM_VENAFI_USERNAME"
_ENV_VENAFI_PASSWORD = "CM_VENAFI_PASSWORD"


# =============================================================================
# Vault requirement checks
# =============================================================================


def vault_required_for_digicert() -> bool:
    """Return True when Vault is needed to resolve the DigiCert API key."""
    return not bool(os.environ.get(_ENV_DIGICERT_API_KEY))


def vault_required_for_venafi() -> bool:
    """Return True when Vault is needed to resolve Venafi AD credentials."""
    has_user = bool(os.environ.get(_ENV_VENAFI_USERNAME))
    has_pass = bool(os.environ.get(_ENV_VENAFI_PASSWORD))
    if has_user != has_pass:
        raise ConfigurationError(
            f"Both {_ENV_VENAFI_USERNAME} and {_ENV_VENAFI_PASSWORD} must be set "
            "together to bypass Vault for Venafi credentials."
        )
    return not has_user


def vault_required(cfg: JsonDict) -> bool:
    """Return True if any *enabled* component requires a live Vault client.

    Inspects ``cfg`` to determine which providers are active, and only
    checks Vault requirements for those providers.  Previously this
    function ignored ``cfg`` entirely, which caused false Vault
    requirement checks for disabled providers (e.g. checking Venafi env
    vars when only DigiCert is configured).
    """
    needs_vault = False

    # DigiCert — check only when the digicert section is present and enabled.
    digicert_cfg = cfg.get("digicert", {})
    if digicert_cfg.get("enabled", True):
        needs_vault = needs_vault or vault_required_for_digicert()

    # Venafi — check only when the venafi section is present and enabled.
    venafi_cfg = cfg.get("venafi", {})
    if venafi_cfg.get("enabled", True):
        needs_vault = needs_vault or vault_required_for_venafi()

    return needs_vault


# =============================================================================
# Secret resolvers
# =============================================================================


def resolve_digicert_api_key(
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> str:
    """Resolve the DigiCert CertCentral API key."""
    from certmesh.backends import vault_client as _vc

    api_key = os.environ.get(_ENV_DIGICERT_API_KEY)
    if api_key:
        logger.debug("DigiCert API key resolved from environment variable.")
        return api_key

    if vault_cl is None:
        raise ConfigurationError(
            f"No DigiCert API key available: '{_ENV_DIGICERT_API_KEY}' is not set "
            "and no Vault client was provided."
        )

    path: str = vault_cfg["paths"]["digicert_api_key"]
    kv_version = int(vault_cfg.get("kv_version", 2))
    key = _vc.read_secret_versioned(vault_cl, path, "value", kv_version=kv_version)
    logger.debug("DigiCert API key resolved from Vault path '%s' (KV v%d).", path, kv_version)
    return key


def resolve_venafi_credentials(
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> dict[str, str]:
    """Resolve Venafi TPP Active Directory credentials."""
    from certmesh.backends import vault_client as _vc

    username = os.environ.get(_ENV_VENAFI_USERNAME)
    password = os.environ.get(_ENV_VENAFI_PASSWORD)

    if username and password:
        logger.debug("Venafi credentials resolved from environment variables.")
        return {"username": username, "password": password}

    if bool(username) != bool(password):
        raise ConfigurationError(
            f"Both {_ENV_VENAFI_USERNAME} and {_ENV_VENAFI_PASSWORD} must be set together."
        )

    if vault_cl is None:
        raise ConfigurationError(
            f"No Venafi credentials available: '{_ENV_VENAFI_USERNAME}' / "
            f"'{_ENV_VENAFI_PASSWORD}' are not set and no Vault client was provided."
        )

    path: str = vault_cfg["paths"]["venafi_credentials"]
    kv_version = int(vault_cfg.get("kv_version", 2))
    data = _vc.read_all_secrets_versioned(vault_cl, path, kv_version=kv_version)
    logger.debug("Venafi credentials resolved from Vault path '%s' (KV v%d).", path, kv_version)
    return data
