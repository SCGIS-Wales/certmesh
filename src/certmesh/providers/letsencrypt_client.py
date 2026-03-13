"""
certmesh.providers.letsencrypt_client
======================================

Let's Encrypt / ACME (RFC 8555) certificate provider.

Supports DNS-01 and HTTP-01 challenge types.  This provider is
**disabled by default** and must be explicitly enabled in configuration.

Dependencies: ``acme>=2.0.0``, ``josepy>=1.13.0``, ``cryptography``
"""

from __future__ import annotations

import logging
import time
from typing import Any

import josepy as jose
from acme import challenges, client, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certmesh.exceptions import (
    LetsEncryptChallengeError,
    LetsEncryptError,
    LetsEncryptOrderError,
    LetsEncryptRateLimitError,
    LetsEncryptRegistrationError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

# ACME directory URLs
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-le-staging-v02.api.letsencrypt.org/directory"

_ACCOUNT_KEY_BITS = 2048


# ---------------------------------------------------------------------------
# Account key helpers
# ---------------------------------------------------------------------------


def generate_account_key() -> jose.JWKRSA:
    """Generate a new RSA key pair for ACME account registration."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=_ACCOUNT_KEY_BITS)
    return jose.JWKRSA(key=private_key)


def load_account_key(pem_data: bytes) -> jose.JWKRSA:
    """Load an existing ACME account key from PEM bytes."""
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    return jose.JWKRSA(key=private_key)


def serialize_account_key(account_key: jose.JWKRSA) -> bytes:
    """Serialize an ACME account key to PEM bytes."""
    return account_key.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# ACME client creation
# ---------------------------------------------------------------------------


def create_acme_client(
    directory_url: str = LETSENCRYPT_STAGING,
    account_key: jose.JWKRSA | None = None,
    email: str | None = None,
    agree_tos: bool = False,
) -> client.ClientV2:
    """Create and register an ACME v2 client.

    Parameters
    ----------
    directory_url:
        ACME directory URL.  Defaults to Let's Encrypt **staging**.
    account_key:
        Existing account key.  A new one is generated if ``None``.
    email:
        Contact e-mail for the ACME account.
    agree_tos:
        Whether to agree to the CA's Terms of Service.

    Returns
    -------
    client.ClientV2
    """
    if account_key is None:
        account_key = generate_account_key()
        logger.info("Generated new ACME account key.")

    try:
        net = client.ClientNetwork(account_key, user_agent="certmesh")
        directory = messages.Directory.from_json(net.get(directory_url).json())
        acme_client = client.ClientV2(directory, net=net)
    except Exception as exc:
        raise LetsEncryptError(
            f"Failed to connect to ACME directory at {directory_url}: {exc}"
        ) from exc

    registration = messages.NewRegistration.from_data(
        email=email,
        terms_of_service_agreed=agree_tos,
    )
    try:
        acme_client.new_account(registration)
        logger.info("ACME account registered (email=%s).", email or "<none>")
    except Exception as exc:
        error_str = str(exc).lower()
        if "already" in error_str or "existing" in error_str:
            logger.info("Using existing ACME account.")
        else:
            raise LetsEncryptRegistrationError(f"ACME account registration failed: {exc}") from exc

    return acme_client


# ---------------------------------------------------------------------------
# Certificate request
# ---------------------------------------------------------------------------


def _select_challenge(
    authz_body: messages.Authorization,
    challenge_type: str,
) -> messages.ChallengeBody:
    """Select the requested challenge type from an authorization."""
    for chall_body in authz_body.challenges:
        if challenge_type == "dns-01" and isinstance(chall_body.chall, challenges.DNS01):
            return chall_body
        if challenge_type == "http-01" and isinstance(chall_body.chall, challenges.HTTP01):
            return chall_body
    available = [type(c.chall).__name__ for c in authz_body.challenges]
    raise LetsEncryptChallengeError(
        f"Challenge type '{challenge_type}' not offered for "
        f"{authz_body.identifier.value}.  Available: {available}"
    )


def request_certificate(
    acme_client: client.ClientV2,
    common_name: str,
    san: list[str] | None = None,
    challenge_type: str = "dns-01",
    challenge_handler: Any | None = None,
    timeout: int = 300,
) -> dict[str, str]:
    """Request a certificate via ACME.

    Parameters
    ----------
    acme_client:
        Authenticated ACME v2 client.
    common_name:
        Primary domain name.
    san:
        Additional Subject Alternative Names.
    challenge_type:
        ``"dns-01"`` or ``"http-01"``.
    challenge_handler:
        Callable ``(domain, token, validation) -> None`` that provisions
        the challenge response and blocks until it is live.
    timeout:
        Max seconds for order finalization.

    Returns
    -------
    dict
        Keys: ``certificate``, ``chain``, ``fullchain``, ``private_key``
        (all PEM-encoded strings).
    """
    domains = [common_name] + (san or [])
    logger.info(
        "Requesting ACME certificate for %s (SANs: %s, challenge: %s).",
        common_name,
        san or [],
        challenge_type,
    )

    # Generate certificate private key
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    all_dns_names = [x509.DNSName(d) for d in domains]
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(all_dns_names),
        critical=False,
    )
    csr = csr_builder.sign(cert_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Place order
    try:
        order = acme_client.new_order(csr_pem)
    except Exception as exc:
        _check_rate_limit(exc, common_name, "order creation")
        raise LetsEncryptOrderError(
            f"Failed to create ACME order for {common_name}: {exc}"
        ) from exc

    # Process authorizations
    for authz in order.authorizations:
        domain = authz.body.identifier.value
        logger.debug("Processing authorization for domain: %s", domain)

        chall_body = _select_challenge(authz.body, challenge_type)
        validation = chall_body.chall.validation(acme_client.net.key)
        token = chall_body.chall.encode("token")

        if challenge_handler is not None:
            try:
                challenge_handler(domain, token, validation)
            except Exception as exc:
                raise LetsEncryptChallengeError(
                    f"Challenge handler failed for {domain}: {exc}"
                ) from exc
        else:
            logger.warning(
                "No challenge handler provided for %s — challenge token: %s, validation: %s",
                domain,
                token,
                validation,
            )

        try:
            acme_client.answer_challenge(
                chall_body,
                chall_body.response(acme_client.net.key),
            )
        except Exception as exc:
            raise LetsEncryptChallengeError(
                f"Failed to answer {challenge_type} challenge for {domain}: {exc}"
            ) from exc

    # Finalize
    deadline = time.monotonic() + timeout
    try:
        order = acme_client.poll_and_finalize(order, deadline=deadline)
    except Exception as exc:
        _check_rate_limit(exc, common_name, "finalization")
        raise LetsEncryptOrderError(f"Order finalization failed for {common_name}: {exc}") from exc

    fullchain_pem = order.fullchain_pem
    cert_pem, chain_pem = _split_fullchain(fullchain_pem)

    private_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    logger.info("ACME certificate issued for %s.", common_name)
    return {
        "certificate": cert_pem,
        "chain": chain_pem,
        "fullchain": fullchain_pem,
        "private_key": private_key_pem,
    }


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revoke_certificate(
    acme_client: client.ClientV2,
    cert_pem: str,
    reason: int = 0,
) -> None:
    """Revoke a previously issued ACME certificate.

    Parameters
    ----------
    acme_client:
        Authenticated ACME client.
    cert_pem:
        PEM-encoded certificate to revoke.
    reason:
        RFC 5280 revocation reason code (0 = unspecified).
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        wrapped = jose.ComparableX509(cert)
        acme_client.revoke(wrapped, reason)
        logger.info("ACME certificate revoked (reason=%d).", reason)
    except Exception as exc:
        raise LetsEncryptError(f"Certificate revocation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_fullchain(fullchain_pem: str) -> tuple[str, str]:
    """Split a fullchain PEM into (leaf cert, intermediates)."""
    marker = "-----END CERTIFICATE-----"
    parts = fullchain_pem.split(marker)
    if len(parts) < 2:
        return fullchain_pem, ""
    cert = parts[0] + marker + "\n"
    chain = marker.join(parts[1:]).strip()
    if chain:
        chain += "\n"
    return cert, chain


def _check_rate_limit(exc: Exception, cn: str, context: str) -> None:
    """Raise ``LetsEncryptRateLimitError`` if the error looks like a rate limit."""
    msg = str(exc).lower()
    if "rate" in msg or "limit" in msg or "too many" in msg:
        raise LetsEncryptRateLimitError(
            f"ACME rate limit during {context} for {cn}: {exc}"
        ) from exc
