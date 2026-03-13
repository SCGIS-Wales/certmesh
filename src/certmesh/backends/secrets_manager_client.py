"""
certmesh.secrets_manager_client
================================

AWS Secrets Manager integration for persisting and retrieving
certificate material as JSON-encoded secrets.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from certmesh.exceptions import (
    SecretsManagerReadError,
    SecretsManagerWriteError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


# =============================================================================
# Write
# =============================================================================


def write_secret(
    secret_name: str,
    secret_data: JsonDict,
    region: str,
) -> str:
    """Write (create or update) a JSON secret in AWS Secrets Manager.

    Parameters
    ----------
    secret_name:
        The name/path of the secret (e.g. ``certmesh/tls/digicert/12345``).
    secret_data:
        Dictionary to JSON-encode and persist.
    region:
        AWS region for the Secrets Manager endpoint.

    Returns
    -------
    str
        The ARN of the created/updated secret.

    Raises
    ------
    SecretsManagerWriteError
        When the API call fails.
    """
    client = boto3.client("secretsmanager", region_name=region)
    secret_string = json.dumps(secret_data)

    try:
        # Try update first (common path for certificate renewals)
        response = client.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string,
        )
        arn: str = response["ARN"]
        logger.info(
            "Updated secret '%s' in Secrets Manager (region=%s).",
            secret_name,
            region,
        )
        return arn
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            # Secret does not exist yet — create it
            return _create_secret(client, secret_name, secret_string, region)
        raise SecretsManagerWriteError(
            f"Failed to write secret '{secret_name}' in region '{region}': {error_code} — {exc}"
        ) from exc


def _create_secret(
    client: Any,
    secret_name: str,
    secret_string: str,
    region: str,
) -> str:
    """Create a new secret in AWS Secrets Manager."""
    try:
        response = client.create_secret(
            Name=secret_name,
            SecretString=secret_string,
            Description="Managed by certmesh — TLS certificate material",
        )
        arn: str = response["ARN"]
        logger.info(
            "Created secret '%s' in Secrets Manager (region=%s).",
            secret_name,
            region,
        )
        return arn
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        raise SecretsManagerWriteError(
            f"Failed to create secret '{secret_name}' in region '{region}': {error_code} — {exc}"
        ) from exc


# =============================================================================
# Read
# =============================================================================


def read_secret(
    secret_name: str,
    region: str,
) -> JsonDict:
    """Read a JSON secret from AWS Secrets Manager.

    Parameters
    ----------
    secret_name:
        The name/path of the secret.
    region:
        AWS region for the Secrets Manager endpoint.

    Returns
    -------
    dict
        The parsed JSON payload.

    Raises
    ------
    SecretsManagerReadError
        When the secret cannot be found or parsed.
    """
    client = boto3.client("secretsmanager", region_name=region)

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            raise SecretsManagerReadError(
                f"Secret '{secret_name}' not found in region '{region}'."
            ) from exc
        raise SecretsManagerReadError(
            f"Failed to read secret '{secret_name}' in region '{region}': {error_code} — {exc}"
        ) from exc

    secret_string = response.get("SecretString", "")
    if not secret_string:
        raise SecretsManagerReadError(
            f"Secret '{secret_name}' exists but contains no string value "
            f"(binary secrets are not supported)."
        )

    try:
        data: JsonDict = json.loads(secret_string)
    except json.JSONDecodeError as exc:
        raise SecretsManagerReadError(
            f"Secret '{secret_name}' contains invalid JSON: {exc}"
        ) from exc

    logger.info(
        "Read secret '%s' from Secrets Manager (region=%s, %d keys).",
        secret_name,
        region,
        len(data),
    )
    return data
