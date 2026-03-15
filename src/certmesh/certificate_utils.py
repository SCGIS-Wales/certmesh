"""
certmesh.certificate_utils
============================

Pure-function utilities for cryptographic operations and certificate
material persistence.  No network calls; no Vault interaction.
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import hvac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from certmesh.exceptions import (
    CertificateExportError,
    ConfigurationError,
    CSRGenerationError,
    KeyGenerationError,
    PKCS12ParseError,
    SecretsManagerWriteError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]


# =============================================================================
# Data models
# =============================================================================


@dataclass(slots=True, frozen=True)
class SubjectInfo:
    """X.509 distinguished name components for a certificate subject."""

    common_name: str
    organisation: str = ""
    organisational_unit: str = ""
    country: str = "US"
    state: str = ""
    locality: str = ""
    san_dns_names: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class CertificateBundle:
    """All material produced by a successful certificate issuance."""

    certificate_pem: str
    private_key_pem: str
    chain_pem: str | None
    certificate_pem_b64: str
    serial_number: str
    common_name: str
    not_after: datetime
    source_id: str


# =============================================================================
# Key generation
# =============================================================================


def generate_rsa_private_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    if key_size not in (2048, 3072, 4096):
        raise KeyGenerationError(
            f"Unsupported key_size {key_size}. Permitted values: 2048, 3072, 4096."
        )
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    except Exception as exc:
        raise KeyGenerationError(
            f"RSA key generation failed (key_size={key_size}): {exc}"
        ) from exc

    logger.debug("Generated RSA private key", extra={"key_size": key_size})
    return private_key


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialise an RSA private key to unencrypted PKCS#1 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# =============================================================================
# CSR generation
# =============================================================================


def build_csr(
    private_key: rsa.RSAPrivateKey,
    subject: SubjectInfo,
) -> x509.CertificateSigningRequest:
    """Build and sign a Certificate Signing Request."""
    try:
        name_attrs: list[x509.NameAttribute] = []
        if subject.country:
            name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country))
        if subject.state:
            name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.state))
        if subject.locality:
            name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality))
        if subject.organisation:
            name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organisation))
        if subject.organisational_unit:
            name_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organisational_unit)
            )
        name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject.common_name))

        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attrs))

        san_entries: list[x509.GeneralName] = [
            x509.DNSName(name) for name in subject.san_dns_names
        ]
        if not san_entries:
            san_entries = [x509.DNSName(subject.common_name)]

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

        csr = builder.sign(private_key, hashes.SHA256())
    except Exception as exc:
        raise CSRGenerationError(
            f"Failed to build CSR for '{subject.common_name}': {exc}"
        ) from exc

    logger.debug(
        "Built CSR",
        extra={"common_name": subject.common_name, "san_count": len(san_entries)},
    )
    return csr


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    """Return the CSR as a PEM-encoded string (UTF-8)."""
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# =============================================================================
# PKCS#12 parsing
# =============================================================================


def parse_pkcs12_bundle(
    pkcs12_bytes: bytes,
    passphrase: str | None,
) -> tuple[bytes, bytes, bytes | None]:
    """Extract certificate, private key, and optional chain from a PKCS#12 bundle."""
    password_bytes: bytes | None = passphrase.encode("utf-8") if passphrase else None

    try:
        loaded = pkcs12.load_pkcs12(pkcs12_bytes, password_bytes)
    except Exception as exc:
        raise PKCS12ParseError(
            f"Failed to parse PKCS#12 bundle: {exc}. "
            "Verify the passphrase and that the bundle is valid PKCS#12 data."
        ) from exc

    if loaded.key is None:
        raise PKCS12ParseError("PKCS#12 bundle does not contain a private key.")

    private_key_pem: bytes = loaded.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    if loaded.cert is None:
        raise PKCS12ParseError("PKCS#12 bundle does not contain a certificate.")
    cert_pem: bytes = loaded.cert.certificate.public_bytes(serialization.Encoding.PEM)

    chain_pem: bytes | None = None
    if loaded.additional_certs:
        chain_pem = b"".join(
            ac.certificate.public_bytes(serialization.Encoding.PEM)
            for ac in loaded.additional_certs
        )

    logger.debug("Parsed PKCS#12 bundle successfully.")
    return cert_pem, private_key_pem, chain_pem


# =============================================================================
# Bundle assembly
# =============================================================================


def assemble_bundle(
    *,
    cert_pem: bytes,
    private_key_pem: bytes,
    chain_pem: bytes | None,
    source_id: str,
) -> CertificateBundle:
    """Parse a PEM certificate and assemble a ``CertificateBundle``."""
    try:
        parsed_cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:
        raise CertificateExportError(
            f"Failed to parse PEM certificate for source '{source_id}': {exc}"
        ) from exc

    cn_attrs = parsed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else "unknown"

    cert_pem_str = cert_pem.decode("utf-8")
    return CertificateBundle(
        certificate_pem=cert_pem_str,
        private_key_pem=private_key_pem.decode("utf-8"),
        chain_pem=chain_pem.decode("utf-8") if chain_pem else None,
        certificate_pem_b64=base64.b64encode(cert_pem).decode("utf-8"),
        serial_number=format(parsed_cert.serial_number, "x"),
        common_name=common_name,
        not_after=parsed_cert.not_valid_after_utc,
        source_id=source_id,
    )


# =============================================================================
# Output persistence
# =============================================================================


def persist_bundle(
    bundle: CertificateBundle,
    output_cfg: JsonDict,
    vault_client: hvac.Client | None = None,
) -> dict[str, str]:
    """Write certificate and private key material to configured destination(s).

    Supports both legacy string destinations (``"filesystem"``, ``"vault"``,
    ``"both"``) and the new-style list format
    (``["filesystem", "vault", "secrets_manager"]``).
    """
    from certmesh.settings import normalize_destinations

    raw_dest = output_cfg.get("destination", "filesystem")
    destinations = normalize_destinations(raw_dest)
    written: dict[str, str] = {}

    if "filesystem" in destinations:
        paths = _write_to_filesystem(bundle, output_cfg)
        written.update(paths)

    if "vault" in destinations:
        vault_path = _write_to_vault(bundle, output_cfg, vault_client)
        written["vault"] = vault_path

    if "secrets_manager" in destinations:
        secret_name = _write_to_secrets_manager(bundle, output_cfg)
        written["secrets_manager"] = secret_name

    return written


def _write_to_filesystem(
    bundle: CertificateBundle,
    output_cfg: JsonDict,
) -> dict[str, str]:
    """Write PEM files to the filesystem base_path."""
    sid = bundle.source_id
    base = Path(output_cfg["base_path"])
    written_files: list[Path] = []

    try:
        base.mkdir(parents=True, exist_ok=True)

        cert_path = base / output_cfg["cert_filename"].format(
            order_id=sid, guid=sid, cert_arn_short=sid
        )
        key_path = base / output_cfg["key_filename"].format(
            order_id=sid, guid=sid, cert_arn_short=sid
        )

        cert_fd = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(cert_fd, "w", encoding="utf-8") as cf:
            cf.write(bundle.certificate_pem)
        written_files.append(cert_path)
        logger.info("Wrote certificate PEM", extra={"path": str(cert_path), "mode": "0644"})

        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as kf:
            kf.write(bundle.private_key_pem)
        written_files.append(key_path)
        logger.info("Wrote private key PEM", extra={"path": str(key_path), "mode": "0600"})

        result = {
            "filesystem_cert": str(cert_path),
            "filesystem_key": str(key_path),
        }

        if bundle.chain_pem and "chain_filename" in output_cfg:
            chain_path = base / output_cfg["chain_filename"].format(
                order_id=sid, guid=sid, cert_arn_short=sid
            )
            # Write chain with restricted permissions (0600) like the key file
            chain_fd = os.open(chain_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(chain_fd, "w", encoding="utf-8") as cf:
                cf.write(bundle.chain_pem)
            written_files.append(chain_path)
            logger.info("Wrote CA chain PEM", extra={"path": str(chain_path)})
            result["filesystem_chain"] = str(chain_path)

        return result

    except OSError as exc:
        # Clean up any partially-written files to avoid leaving stale
        # artefacts on disk (e.g. cert written but key write failed).
        for partial in written_files:
            try:
                partial.unlink(missing_ok=True)
                logger.warning(
                    "Cleaned up partial file after write failure", extra={"path": str(partial)}
                )
            except OSError:
                pass  # best-effort cleanup
        raise CertificateExportError(
            f"Failed to write certificate material to filesystem path '{base}': {exc}"
        ) from exc


def _write_to_vault(
    bundle: CertificateBundle,
    output_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> str:
    """Write PEM material to a Vault KV path (v1 or v2 based on config)."""
    from certmesh.backends import vault_client as vc

    if vault_cl is None:
        raise ConfigurationError(
            "vault_client must be provided when output destination includes 'vault'."
        )

    vault_path: str = output_cfg["vault_path_template"].format(
        order_id=bundle.source_id,
        guid=bundle.source_id,
        cert_arn_short=bundle.source_id,
    )

    secret_data: dict[str, str] = {
        "certificate_pem": bundle.certificate_pem,
        "private_key_pem": bundle.private_key_pem,
        "certificate_pem_b64": bundle.certificate_pem_b64,
        "serial_number": bundle.serial_number,
        "common_name": bundle.common_name,
        "not_after": bundle.not_after.isoformat(),
        "source_id": bundle.source_id,
    }
    if bundle.chain_pem:
        secret_data["chain_pem"] = bundle.chain_pem

    kv_version = int(output_cfg.get("kv_version", 2))
    vc.write_secret_versioned(vault_cl, vault_path, secret_data, kv_version=kv_version)
    logger.info(
        "Certificate material stored in Vault",
        extra={
            "common_name": bundle.common_name,
            "vault_path": vault_path,
            "kv_version": kv_version,
        },
    )
    return vault_path


def _write_to_secrets_manager(
    bundle: CertificateBundle,
    output_cfg: JsonDict,
) -> str:
    """Write PEM material to AWS Secrets Manager."""
    from certmesh.backends import secrets_manager_client as smc

    template: str = output_cfg.get("sm_secret_name_template", "")
    if not template:
        raise ConfigurationError(
            "output destination includes 'secrets_manager' but no "
            "sm_secret_name_template is configured."
        )

    region: str = output_cfg.get("sm_region", "")
    if not region:
        raise ConfigurationError(
            "output destination includes 'secrets_manager' but no sm_region is configured."
        )

    secret_name = template.format(
        order_id=bundle.source_id,
        guid=bundle.source_id,
        cert_arn_short=bundle.source_id,
    )

    secret_data: dict[str, str] = {
        "certificate_pem": bundle.certificate_pem,
        "private_key_pem": bundle.private_key_pem,
        "certificate_pem_b64": bundle.certificate_pem_b64,
        "serial_number": bundle.serial_number,
        "common_name": bundle.common_name,
        "not_after": bundle.not_after.isoformat(),
        "source_id": bundle.source_id,
    }
    if bundle.chain_pem:
        secret_data["chain_pem"] = bundle.chain_pem

    try:
        smc.write_secret(secret_name, secret_data, region)
    except SecretsManagerWriteError:
        raise
    except Exception as exc:
        raise SecretsManagerWriteError(
            f"Failed to write certificate material for '{bundle.common_name}' "
            f"to Secrets Manager secret '{secret_name}': {exc}"
        ) from exc

    logger.info(
        "Certificate material stored in Secrets Manager",
        extra={
            "common_name": bundle.common_name,
            "secret_name": secret_name,
            "region": region,
        },
    )
    return secret_name
