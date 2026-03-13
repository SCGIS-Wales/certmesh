"""Tests for Vault KV v1 support and version-aware dispatch (Phase 2)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from hvac.exceptions import Forbidden, InvalidPath

from certmesh import vault_client as vc
from certmesh.exceptions import (
    VaultAuthenticationError,
    VaultSecretNotFoundError,
)

JsonDict = dict[str, Any]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture()
def mock_client() -> MagicMock:
    """Mock hvac.Client with KV v1 and v2 sub-objects."""
    client = MagicMock()
    return client


# =============================================================================
# KV v1 read
# =============================================================================


class TestReadAllSecretFieldsV1:
    """Test KV v1 read operations (single-wrapped response)."""

    def test_success(self, mock_client: MagicMock) -> None:
        # KV v1 returns single-wrapped data: response["data"]
        mock_client.secrets.kv.v1.read_secret.return_value = {
            "data": {"username": "admin", "password": "secret123"}
        }
        result = vc.read_all_secret_fields_v1(mock_client, "secret/myapp")
        assert result == {"username": "admin", "password": "secret123"}
        mock_client.secrets.kv.v1.read_secret.assert_called_once_with(
            path="myapp", mount_point="secret"
        )

    def test_invalid_path_raises(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.side_effect = InvalidPath("not found")
        with pytest.raises(VaultSecretNotFoundError, match="KV v1"):
            vc.read_all_secret_fields_v1(mock_client, "secret/missing")

    def test_forbidden_raises(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.side_effect = Forbidden("denied")
        with pytest.raises(VaultAuthenticationError, match="KV v1"):
            vc.read_all_secret_fields_v1(mock_client, "secret/denied")

    def test_empty_response(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.return_value = {"data": {}}
        result = vc.read_all_secret_fields_v1(mock_client, "secret/empty")
        assert result == {}


class TestReadSecretFieldV1:
    def test_field_found(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.return_value = {"data": {"value": "my-api-key"}}
        result = vc.read_secret_field_v1(mock_client, "secret/api", "value")
        assert result == "my-api-key"

    def test_field_not_found(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.return_value = {"data": {"other_field": "x"}}
        with pytest.raises(VaultSecretNotFoundError, match="value"):
            vc.read_secret_field_v1(mock_client, "secret/api", "value")


# =============================================================================
# KV v1 write
# =============================================================================


class TestWriteSecretV1:
    def test_success(self, mock_client: MagicMock) -> None:
        vc.write_secret_v1(mock_client, "secret/myapp", {"key": "val"})
        mock_client.secrets.kv.v1.create_or_update_secret.assert_called_once_with(
            path="myapp", secret={"key": "val"}, mount_point="secret"
        )

    def test_forbidden_raises(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.create_or_update_secret.side_effect = Forbidden("denied")
        with pytest.raises(VaultAuthenticationError, match="KV v1"):
            vc.write_secret_v1(mock_client, "secret/denied", {"k": "v"})


# =============================================================================
# Version-aware dispatch
# =============================================================================


class TestVersionedDispatch:
    """Test version-aware wrappers route to correct KV version."""

    def test_read_secret_versioned_v1(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.return_value = {"data": {"value": "v1-key"}}
        result = vc.read_secret_versioned(mock_client, "secret/key", "value", kv_version=1)
        assert result == "v1-key"
        mock_client.secrets.kv.v1.read_secret.assert_called_once()

    def test_read_secret_versioned_v2(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "v2-key"}}
        }
        result = vc.read_secret_versioned(mock_client, "secret/key", "value", kv_version=2)
        assert result == "v2-key"
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once()

    def test_read_all_secrets_versioned_v1(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v1.read_secret.return_value = {"data": {"a": "1", "b": "2"}}
        result = vc.read_all_secrets_versioned(mock_client, "secret/multi", kv_version=1)
        assert result == {"a": "1", "b": "2"}

    def test_read_all_secrets_versioned_v2(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"a": "1", "b": "2"}}
        }
        result = vc.read_all_secrets_versioned(mock_client, "secret/multi", kv_version=2)
        assert result == {"a": "1", "b": "2"}

    def test_write_secret_versioned_v1(self, mock_client: MagicMock) -> None:
        vc.write_secret_versioned(mock_client, "secret/out", {"k": "v"}, kv_version=1)
        mock_client.secrets.kv.v1.create_or_update_secret.assert_called_once()

    def test_write_secret_versioned_v2(self, mock_client: MagicMock) -> None:
        vc.write_secret_versioned(mock_client, "secret/out", {"k": "v"}, kv_version=2)
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_default_version_is_v2(self, mock_client: MagicMock) -> None:
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "default-v2"}}
        }
        result = vc.read_secret_versioned(mock_client, "secret/key", "value")
        assert result == "default-v2"
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once()


# =============================================================================
# Credentials versioned dispatch integration
# =============================================================================


class TestCredentialsVersionedDispatch:
    """Test that credentials module uses version-aware functions."""

    def test_digicert_api_key_v1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CM_DIGICERT_API_KEY", raising=False)
        vault_cfg: JsonDict = {
            "kv_version": 1,
            "paths": {"digicert_api_key": "secret/digicert/api"},
        }
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v1.read_secret.return_value = {"data": {"value": "dc-key-v1"}}

        from certmesh.credentials import resolve_digicert_api_key

        result = resolve_digicert_api_key(vault_cfg, mock_cl)
        assert result == "dc-key-v1"
        mock_cl.secrets.kv.v1.read_secret.assert_called_once()

    def test_venafi_credentials_v1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CM_VENAFI_USERNAME", raising=False)
        monkeypatch.delenv("CM_VENAFI_PASSWORD", raising=False)
        vault_cfg: JsonDict = {
            "kv_version": 1,
            "paths": {"venafi_credentials": "secret/venafi/creds"},
        }
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v1.read_secret.return_value = {
            "data": {"username": "admin", "password": "pass"}
        }

        from certmesh.credentials import resolve_venafi_credentials

        result = resolve_venafi_credentials(vault_cfg, mock_cl)
        assert result == {"username": "admin", "password": "pass"}
        mock_cl.secrets.kv.v1.read_secret.assert_called_once()
