"""Tests for certmesh.providers.letsencrypt_client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from certmesh.exceptions import (
    LetsEncryptChallengeError,
    LetsEncryptError,
    LetsEncryptOrderError,
    LetsEncryptRateLimitError,
    LetsEncryptRegistrationError,
)
from certmesh.providers import letsencrypt_client as lec

# ---------------------------------------------------------------------------
# Account key helpers
# ---------------------------------------------------------------------------


class TestAccountKey:
    def test_generate_account_key(self):
        key = lec.generate_account_key()
        assert key is not None
        assert hasattr(key, "key")

    def test_serialize_and_load_roundtrip(self):
        key = lec.generate_account_key()
        pem = lec.serialize_account_key(key)
        assert b"PRIVATE KEY" in pem
        loaded = lec.load_account_key(pem)
        assert loaded is not None

    def test_load_invalid_key_raises(self):
        with pytest.raises((ValueError, TypeError)):
            lec.load_account_key(b"not a key")


# ---------------------------------------------------------------------------
# ACME client creation
# ---------------------------------------------------------------------------


class TestCreateAcmeClient:
    @patch("certmesh.providers.letsencrypt_client.client")
    @patch("certmesh.providers.letsencrypt_client.messages")
    def test_success(self, mock_messages, mock_client):
        mock_net = MagicMock()
        mock_net.get.return_value.json.return_value = {"newAccount": "/acme/new-acct"}
        mock_client.ClientNetwork.return_value = mock_net
        mock_client.ClientV2.return_value = MagicMock()
        mock_messages.Directory.from_json.return_value = MagicMock()
        mock_messages.NewRegistration.from_data.return_value = MagicMock()

        result = lec.create_acme_client(
            directory_url="https://acme-staging.example.com/directory",
            email="test@example.com",
            agree_tos=True,
        )
        assert result is not None
        mock_client.ClientV2.return_value.new_account.assert_called_once()

    @patch("certmesh.providers.letsencrypt_client.client")
    @patch("certmesh.providers.letsencrypt_client.messages")
    def test_existing_account(self, mock_messages, mock_client):
        mock_net = MagicMock()
        mock_net.get.return_value.json.return_value = {}
        mock_client.ClientNetwork.return_value = mock_net
        mock_client.ClientV2.return_value = MagicMock()
        mock_messages.Directory.from_json.return_value = MagicMock()
        mock_messages.NewRegistration.from_data.return_value = MagicMock()
        mock_client.ClientV2.return_value.new_account.side_effect = Exception(
            "Account already exists"
        )

        result = lec.create_acme_client(email="test@example.com", agree_tos=True)
        assert result is not None

    @patch("certmesh.providers.letsencrypt_client.client")
    @patch("certmesh.providers.letsencrypt_client.messages")
    def test_registration_failure(self, mock_messages, mock_client):
        mock_net = MagicMock()
        mock_net.get.return_value.json.return_value = {}
        mock_client.ClientNetwork.return_value = mock_net
        mock_client.ClientV2.return_value = MagicMock()
        mock_messages.Directory.from_json.return_value = MagicMock()
        mock_messages.NewRegistration.from_data.return_value = MagicMock()
        mock_client.ClientV2.return_value.new_account.side_effect = Exception(
            "Server refused registration"
        )

        with pytest.raises(LetsEncryptRegistrationError, match="Server refused"):
            lec.create_acme_client(email="test@example.com", agree_tos=True)

    @patch("certmesh.providers.letsencrypt_client.client")
    def test_directory_connection_failure(self, mock_client):
        mock_client.ClientNetwork.side_effect = ConnectionError("unreachable")

        with pytest.raises(LetsEncryptError, match="Failed to connect"):
            lec.create_acme_client()


# ---------------------------------------------------------------------------
# Challenge selection
# ---------------------------------------------------------------------------


class TestSelectChallenge:
    def test_dns01_found(self):
        from acme import challenges as real_challenges

        dns_chall = MagicMock()
        dns_chall.chall = MagicMock(spec=real_challenges.DNS01)
        authz = MagicMock()
        authz.challenges = [dns_chall]
        authz.identifier.value = "example.com"

        result = lec._select_challenge(authz, "dns-01")
        assert result is dns_chall

    def test_http01_found(self):
        from acme import challenges as real_challenges

        http_chall = MagicMock()
        http_chall.chall = MagicMock(spec=real_challenges.HTTP01)
        authz = MagicMock()
        authz.challenges = [http_chall]
        authz.identifier.value = "example.com"

        result = lec._select_challenge(authz, "http-01")
        assert result is http_chall

    def test_challenge_not_available(self):
        from acme import challenges as real_challenges

        dns_chall = MagicMock()
        dns_chall.chall = MagicMock(spec=real_challenges.DNS01)
        authz = MagicMock()
        authz.challenges = [dns_chall]
        authz.identifier.value = "example.com"

        with pytest.raises(LetsEncryptChallengeError, match="not offered"):
            lec._select_challenge(authz, "http-01")


# ---------------------------------------------------------------------------
# Fullchain splitting
# ---------------------------------------------------------------------------


class TestSplitFullchain:
    def test_single_cert(self):
        pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
        cert, chain = lec._split_fullchain(pem)
        assert "AAA" in cert
        assert chain == ""

    def test_fullchain_two_certs(self):
        pem = (
            "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"
        )
        cert, chain = lec._split_fullchain(pem)
        assert "LEAF" in cert
        assert "INTER" in chain


# ---------------------------------------------------------------------------
# Rate limit detection
# ---------------------------------------------------------------------------


class TestRateLimitCheck:
    def test_rate_limit_detected(self):
        with pytest.raises(LetsEncryptRateLimitError, match="rate limit"):
            lec._check_rate_limit(
                Exception("Rate limit exceeded"),
                "example.com",
                "order creation",
            )

    def test_too_many_detected(self):
        with pytest.raises(LetsEncryptRateLimitError):
            lec._check_rate_limit(
                Exception("Too many requests"),
                "example.com",
                "finalization",
            )

    def test_non_rate_limit_passes(self):
        # Should NOT raise
        lec._check_rate_limit(
            Exception("Server error"),
            "example.com",
            "order creation",
        )


# ---------------------------------------------------------------------------
# Certificate request (mocked)
# ---------------------------------------------------------------------------


class TestRequestCertificate:
    @patch("certmesh.providers.letsencrypt_client._select_challenge")
    def test_order_creation_failure(self, mock_select):
        mock_acme = MagicMock()
        mock_acme.new_order.side_effect = Exception("Order failed")

        with pytest.raises(LetsEncryptOrderError, match="Failed to create"):
            lec.request_certificate(mock_acme, "example.com")

    @patch("certmesh.providers.letsencrypt_client._select_challenge")
    def test_order_rate_limit(self, mock_select):
        mock_acme = MagicMock()
        mock_acme.new_order.side_effect = Exception("Rate limit exceeded")

        with pytest.raises(LetsEncryptRateLimitError):
            lec.request_certificate(mock_acme, "example.com")

    @patch("certmesh.providers.letsencrypt_client._select_challenge")
    def test_challenge_handler_failure(self, mock_select):
        mock_acme = MagicMock()
        mock_order = MagicMock()
        mock_authz = MagicMock()
        mock_authz.body.identifier.value = "example.com"

        mock_chall = MagicMock()
        mock_chall.chall.validation.return_value = "validation_value"
        mock_chall.chall.encode.return_value = "token_value"
        mock_chall.response.return_value = MagicMock()
        mock_select.return_value = mock_chall

        mock_order.authorizations = [mock_authz]
        mock_acme.new_order.return_value = mock_order

        def bad_handler(domain, token, validation):
            raise RuntimeError("DNS update failed")

        with pytest.raises(LetsEncryptChallengeError, match="Challenge handler failed"):
            lec.request_certificate(
                mock_acme,
                "example.com",
                challenge_handler=bad_handler,
            )

    @patch("certmesh.providers.letsencrypt_client._select_challenge")
    def test_finalization_failure(self, mock_select):
        mock_acme = MagicMock()
        mock_order = MagicMock()
        mock_authz = MagicMock()
        mock_authz.body.identifier.value = "example.com"

        mock_chall = MagicMock()
        mock_chall.chall.validation.return_value = "val"
        mock_chall.chall.encode.return_value = "tok"
        mock_chall.response.return_value = MagicMock()
        mock_select.return_value = mock_chall

        mock_order.authorizations = [mock_authz]
        mock_acme.new_order.return_value = mock_order
        mock_acme.poll_and_finalize.side_effect = Exception("Finalization timeout")

        with pytest.raises(LetsEncryptOrderError, match="finalization failed"):
            lec.request_certificate(mock_acme, "example.com")

    @patch("certmesh.providers.letsencrypt_client._select_challenge")
    def test_success(self, mock_select):
        mock_acme = MagicMock()
        mock_order = MagicMock()
        mock_authz = MagicMock()
        mock_authz.body.identifier.value = "example.com"

        mock_chall = MagicMock()
        mock_chall.chall.validation.return_value = "val"
        mock_chall.chall.encode.return_value = "tok"
        mock_chall.response.return_value = MagicMock()
        mock_select.return_value = mock_chall

        mock_order.authorizations = [mock_authz]
        mock_acme.new_order.return_value = mock_order

        finalized_order = MagicMock()
        finalized_order.fullchain_pem = (
            "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n"
        )
        mock_acme.poll_and_finalize.return_value = finalized_order

        result = lec.request_certificate(mock_acme, "example.com", san=["www.example.com"])
        assert "certificate" in result
        assert "chain" in result
        assert "fullchain" in result
        assert "private_key" in result
        assert "PRIVATE KEY" in result["private_key"]


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestRevokeCertificate:
    def test_revoke_failure(self):
        mock_acme = MagicMock()
        mock_acme.revoke.side_effect = Exception("Revocation denied")

        with pytest.raises(LetsEncryptError, match="revocation failed"):
            lec.revoke_certificate(mock_acme, "not-a-valid-cert")

    @patch("certmesh.providers.letsencrypt_client.x509")
    @patch("certmesh.providers.letsencrypt_client.jose")
    def test_revoke_success(self, mock_jose, mock_x509):
        mock_acme = MagicMock()
        mock_cert = MagicMock()
        mock_x509.load_pem_x509_certificate.return_value = mock_cert
        mock_jose.ComparableX509.return_value = MagicMock()

        lec.revoke_certificate(
            mock_acme, "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
        )
        mock_acme.revoke.assert_called_once()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_directory_urls(self):
        assert "acme-v02" in lec.LETSENCRYPT_PRODUCTION
        assert "staging" in lec.LETSENCRYPT_STAGING
