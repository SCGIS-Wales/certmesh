"""Tests for certmesh.exitcodes and the CLI main() exit code wrapper."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from certmesh.exceptions import (
    ACMError,
    CertificateError,
    CertMeshError,
    ConfigurationError,
    DigiCertAuthenticationError,
    DigiCertError,
    VaultAuthenticationError,
    VenafiAuthenticationError,
    VenafiError,
)
from certmesh.exitcodes import (
    EXIT_CERT_OPERATION_ERROR,
    EXIT_CONFIG_AUTH_ERROR,
    EXIT_SUCCESS,
    EXIT_UNEXPECTED_ERROR,
)


class TestExitCodeConstants:
    """Verify exit code constant values."""

    def test_success(self):
        assert EXIT_SUCCESS == 0

    def test_config_auth_error(self):
        assert EXIT_CONFIG_AUTH_ERROR == 1

    def test_cert_operation_error(self):
        assert EXIT_CERT_OPERATION_ERROR == 2

    def test_unexpected_error(self):
        assert EXIT_UNEXPECTED_ERROR == 3


class TestMainExitCodes:
    """Test that main() maps exceptions to the correct exit codes."""

    def _run_main_with_side_effect(self, side_effect):
        """Run main() with a patched cli() that raises the given exception."""
        from certmesh.cli import main

        with patch("certmesh.cli.cli", side_effect=side_effect):
            with pytest.raises(SystemExit) as exc_info:
                main()
        return exc_info.value.code

    def test_configuration_error_returns_exit_1(self):
        code = self._run_main_with_side_effect(ConfigurationError("bad config"))
        assert code == EXIT_CONFIG_AUTH_ERROR

    def test_vault_authentication_error_returns_exit_1(self):
        code = self._run_main_with_side_effect(VaultAuthenticationError("auth failed"))
        assert code == EXIT_CONFIG_AUTH_ERROR

    def test_venafi_authentication_error_returns_exit_1(self):
        code = self._run_main_with_side_effect(VenafiAuthenticationError("auth failed"))
        assert code == EXIT_CONFIG_AUTH_ERROR

    def test_digicert_authentication_error_returns_exit_1(self):
        code = self._run_main_with_side_effect(DigiCertAuthenticationError("auth failed"))
        assert code == EXIT_CONFIG_AUTH_ERROR

    def test_digicert_error_returns_exit_2(self):
        code = self._run_main_with_side_effect(DigiCertError("API failure"))
        assert code == EXIT_CERT_OPERATION_ERROR

    def test_venafi_error_returns_exit_2(self):
        code = self._run_main_with_side_effect(VenafiError("API failure"))
        assert code == EXIT_CERT_OPERATION_ERROR

    def test_acm_error_returns_exit_2(self):
        code = self._run_main_with_side_effect(ACMError("API failure"))
        assert code == EXIT_CERT_OPERATION_ERROR

    def test_certificate_error_returns_exit_2(self):
        code = self._run_main_with_side_effect(CertificateError("parse failure"))
        assert code == EXIT_CERT_OPERATION_ERROR

    def test_generic_certmesh_error_returns_exit_2(self):
        code = self._run_main_with_side_effect(CertMeshError("generic error"))
        assert code == EXIT_CERT_OPERATION_ERROR

    def test_unexpected_exception_returns_exit_3(self):
        code = self._run_main_with_side_effect(RuntimeError("something went wrong"))
        assert code == EXIT_UNEXPECTED_ERROR

    def test_system_exit_propagates_code(self):
        code = self._run_main_with_side_effect(SystemExit(42))
        assert code == 42

    def test_system_exit_zero_propagates(self):
        code = self._run_main_with_side_effect(SystemExit(0))
        assert code == 0
