"""Tests for AWS Secrets Manager integration (Phase 3)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from certmesh.backends.secrets_manager_client import read_secret, write_secret
from certmesh.exceptions import (
    ConfigurationError,
    SecretsManagerReadError,
    SecretsManagerWriteError,
)
from certmesh.settings import normalize_destinations

JsonDict = dict[str, Any]

TEST_REGION = "us-east-1"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def _sm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set dummy AWS creds for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", TEST_REGION)


# =============================================================================
# secrets_manager_client — write
# =============================================================================


class TestWriteSecret:
    @mock_aws
    def test_create_new_secret(self, _sm_env: None) -> None:
        arn = write_secret(
            "certmesh/test/new",
            {"certificate_pem": "CERT", "private_key_pem": "KEY"},
            TEST_REGION,
        )
        assert arn
        assert "certmesh/test/new" in arn

        # Verify secret content via boto3 directly
        client = boto3.client("secretsmanager", region_name=TEST_REGION)
        resp = client.get_secret_value(SecretId="certmesh/test/new")
        data = json.loads(resp["SecretString"])
        assert data["certificate_pem"] == "CERT"
        assert data["private_key_pem"] == "KEY"

    @mock_aws
    def test_update_existing_secret(self, _sm_env: None) -> None:
        # Create first
        write_secret("certmesh/test/update", {"version": "1"}, TEST_REGION)

        # Update
        arn = write_secret("certmesh/test/update", {"version": "2"}, TEST_REGION)
        assert arn

        # Verify updated content
        client = boto3.client("secretsmanager", region_name=TEST_REGION)
        resp = client.get_secret_value(SecretId="certmesh/test/update")
        data = json.loads(resp["SecretString"])
        assert data["version"] == "2"

    def test_write_error_raises(self, _sm_env: None) -> None:
        """When both put and create fail, SecretsManagerWriteError is raised."""
        mock_client = MagicMock()
        # put_secret_value → non-ResourceNotFound error
        from botocore.exceptions import ClientError

        mock_client.put_secret_value.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "PutSecretValue",
        )
        with patch("certmesh.backends.secrets_manager_client.boto3") as mock_boto:
            mock_boto.client.return_value = mock_client
            with pytest.raises(SecretsManagerWriteError, match="AccessDeniedException"):
                write_secret("certmesh/test/denied", {"k": "v"}, TEST_REGION)


# =============================================================================
# secrets_manager_client — read
# =============================================================================


class TestReadSecret:
    @mock_aws
    def test_read_existing_secret(self, _sm_env: None) -> None:
        write_secret("certmesh/test/read", {"a": "1", "b": "2"}, TEST_REGION)

        data = read_secret("certmesh/test/read", TEST_REGION)
        assert data == {"a": "1", "b": "2"}

    @mock_aws
    def test_read_not_found(self, _sm_env: None) -> None:
        with pytest.raises(SecretsManagerReadError, match="not found"):
            read_secret("certmesh/test/nonexistent", TEST_REGION)

    def test_read_invalid_json(self, _sm_env: None) -> None:
        """Secret exists but contains non-JSON string."""
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": "not-json{{{",
        }
        with patch("certmesh.backends.secrets_manager_client.boto3") as mock_boto:
            mock_boto.client.return_value = mock_client
            with pytest.raises(SecretsManagerReadError, match="invalid JSON"):
                read_secret("certmesh/test/bad-json", TEST_REGION)

    def test_read_binary_secret_raises(self, _sm_env: None) -> None:
        """Binary secrets are not supported."""
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": "",
        }
        with patch("certmesh.backends.secrets_manager_client.boto3") as mock_boto:
            mock_boto.client.return_value = mock_client
            with pytest.raises(SecretsManagerReadError, match="no string value"):
                read_secret("certmesh/test/binary", TEST_REGION)

    def test_read_access_denied_raises(self, _sm_env: None) -> None:
        mock_client = MagicMock()
        from botocore.exceptions import ClientError

        mock_client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetSecretValue",
        )
        with patch("certmesh.backends.secrets_manager_client.boto3") as mock_boto:
            mock_boto.client.return_value = mock_client
            with pytest.raises(SecretsManagerReadError, match="AccessDeniedException"):
                read_secret("certmesh/test/denied", TEST_REGION)


# =============================================================================
# normalize_destinations
# =============================================================================


class TestNormalizeDestinations:
    def test_legacy_filesystem(self) -> None:
        assert normalize_destinations("filesystem") == ["filesystem"]

    def test_legacy_vault(self) -> None:
        assert normalize_destinations("vault") == ["vault"]

    def test_legacy_both(self) -> None:
        result = normalize_destinations("both")
        assert "filesystem" in result
        assert "vault" in result
        assert len(result) == 2

    def test_list_single(self) -> None:
        assert normalize_destinations(["filesystem"]) == ["filesystem"]

    def test_list_multiple(self) -> None:
        result = normalize_destinations(["filesystem", "secrets_manager"])
        assert result == ["filesystem", "secrets_manager"]

    def test_list_all_three(self) -> None:
        result = normalize_destinations(["filesystem", "vault", "secrets_manager"])
        assert len(result) == 3

    def test_invalid_legacy_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid output destination"):
            normalize_destinations("invalid")

    def test_invalid_list_item_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="Invalid output destination"):
            normalize_destinations(["filesystem", "s3"])

    def test_empty_string(self) -> None:
        assert normalize_destinations("") == []

    def test_whitespace_stripped(self) -> None:
        assert normalize_destinations([" filesystem ", " vault "]) == ["filesystem", "vault"]


# =============================================================================
# persist_bundle — Secrets Manager integration
# =============================================================================


class TestPersistBundleSecretsManager:
    """Test persist_bundle with secrets_manager destination."""

    @mock_aws
    def test_persist_to_secrets_manager(
        self,
        _sm_env: None,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        from certmesh.certificate_utils import assemble_bundle, persist_bundle

        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="order-42",
        )
        output_cfg: JsonDict = {
            "destination": ["secrets_manager"],
            "sm_secret_name_template": "certmesh/tls/{order_id}",
            "sm_region": TEST_REGION,
        }
        result = persist_bundle(bundle, output_cfg)
        assert "secrets_manager" in result
        assert result["secrets_manager"] == "certmesh/tls/order-42"

        # Verify content in SM
        data = read_secret("certmesh/tls/order-42", TEST_REGION)
        assert data["common_name"] == "test.example.com"
        assert data["source_id"] == "order-42"
        assert "certificate_pem" in data
        assert "private_key_pem" in data

    @mock_aws
    def test_persist_multi_destination(
        self,
        _sm_env: None,
        tmp_path: Any,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        from certmesh.certificate_utils import assemble_bundle, persist_bundle

        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="order-multi",
        )
        output_cfg: JsonDict = {
            "destination": ["filesystem", "secrets_manager"],
            "base_path": str(tmp_path / "certs"),
            "cert_filename": "{order_id}_cert.pem",
            "key_filename": "{order_id}_key.pem",
            "sm_secret_name_template": "certmesh/tls/{order_id}",
            "sm_region": TEST_REGION,
        }
        result = persist_bundle(bundle, output_cfg)
        assert "filesystem_cert" in result
        assert "filesystem_key" in result
        assert "secrets_manager" in result

    def test_legacy_both_backward_compat(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
        mock_vault_client: MagicMock,
    ) -> None:
        """Legacy 'both' destination still works."""
        from certmesh.certificate_utils import assemble_bundle, persist_bundle

        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="legacy-both",
        )
        output_cfg: JsonDict = {
            "destination": "both",
            "base_path": "/tmp/test_legacy",
            "cert_filename": "{order_id}_cert.pem",
            "key_filename": "{order_id}_key.pem",
            "vault_path_template": "secret/test/{order_id}",
            "kv_version": 2,
        }
        result = persist_bundle(bundle, output_cfg, vault_client=mock_vault_client)
        assert "filesystem_cert" in result
        assert "vault" in result

    def test_missing_sm_template_raises(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        from certmesh.certificate_utils import assemble_bundle, persist_bundle

        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="no-template",
        )
        output_cfg: JsonDict = {
            "destination": ["secrets_manager"],
            "sm_secret_name_template": "",
            "sm_region": TEST_REGION,
        }
        with pytest.raises(ConfigurationError, match="sm_secret_name_template"):
            persist_bundle(bundle, output_cfg)

    def test_missing_sm_region_raises(
        self,
        self_signed_cert_pem: bytes,
        private_key_pem: bytes,
    ) -> None:
        from certmesh.certificate_utils import assemble_bundle, persist_bundle

        bundle = assemble_bundle(
            cert_pem=self_signed_cert_pem,
            private_key_pem=private_key_pem,
            chain_pem=None,
            source_id="no-region",
        )
        output_cfg: JsonDict = {
            "destination": ["secrets_manager"],
            "sm_secret_name_template": "certmesh/tls/{order_id}",
            "sm_region": "",
        }
        with pytest.raises(ConfigurationError, match="sm_region"):
            persist_bundle(bundle, output_cfg)


# =============================================================================
# Settings — SM env overrides
# =============================================================================


class TestSecretsManagerEnvOverrides:
    def test_digicert_sm_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_DIGICERT_SM_SECRET_NAME", "certmesh/tls/digicert/{order_id}")
        monkeypatch.setenv("CM_DIGICERT_SM_REGION", "eu-west-1")
        cfg = build_config()
        assert cfg["digicert"]["output"]["sm_secret_name_template"] == (
            "certmesh/tls/digicert/{order_id}"
        )
        assert cfg["digicert"]["output"]["sm_region"] == "eu-west-1"

    def test_venafi_sm_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_VENAFI_SM_SECRET_NAME", "certmesh/tls/venafi/{guid}")
        monkeypatch.setenv("CM_VENAFI_SM_REGION", "us-west-2")
        cfg = build_config()
        assert cfg["venafi"]["output"]["sm_secret_name_template"] == ("certmesh/tls/venafi/{guid}")
        assert cfg["venafi"]["output"]["sm_region"] == "us-west-2"

    def test_acm_sm_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from certmesh.settings import build_config

        monkeypatch.setenv("CM_ACM_SM_SECRET_NAME", "certmesh/tls/acm/{cert_arn_short}")
        monkeypatch.setenv("CM_ACM_SM_REGION", "ap-southeast-1")
        cfg = build_config()
        assert cfg["acm"]["output"]["sm_secret_name_template"] == (
            "certmesh/tls/acm/{cert_arn_short}"
        )
        assert cfg["acm"]["output"]["sm_region"] == "ap-southeast-1"

    def test_sm_defaults_are_empty(self) -> None:
        from certmesh.settings import build_config

        cfg = build_config()
        assert cfg["digicert"]["output"]["sm_secret_name_template"] == ""
        assert cfg["digicert"]["output"]["sm_region"] == ""
        assert cfg["venafi"]["output"]["sm_secret_name_template"] == ""
        assert cfg["acm"]["output"]["sm_secret_name_template"] == ""


# =============================================================================
# Settings validation — SM destination
# =============================================================================


class TestValidationSecretsManager:
    def test_digicert_sm_missing_template_raises(self) -> None:
        from certmesh.settings import build_config, validate_config

        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["digicert"]["output"]["destination"] = ["secrets_manager"]
        cfg["digicert"]["output"]["sm_secret_name_template"] = ""
        with pytest.raises(ConfigurationError, match="sm_secret_name_template"):
            validate_config(cfg)

    def test_digicert_sm_with_template_passes(self) -> None:
        from certmesh.settings import build_config, validate_config

        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["digicert"]["output"]["destination"] = ["secrets_manager"]
        cfg["digicert"]["output"]["sm_secret_name_template"] = "certmesh/{order_id}"
        validate_config(cfg)  # should NOT raise

    def test_list_destination_with_vault_requires_vault_template(self) -> None:
        from certmesh.settings import build_config, validate_config

        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["digicert"]["output"]["destination"] = ["vault"]
        cfg["digicert"]["output"]["vault_path_template"] = ""
        with pytest.raises(ConfigurationError, match="vault_path_template"):
            validate_config(cfg)
