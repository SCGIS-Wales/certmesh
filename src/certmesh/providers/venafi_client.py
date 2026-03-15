"""
certmesh.venafi_client
=======================

Venafi Trust Protection Platform (TPP) / CyberArk Trust Protection Foundation
client for the full certificate lifecycle: authenticate, renew, list, search,
describe, revoke, and request.

Supported API versions
~~~~~~~~~~~~~~~~~~~~~~
* **v23 (SDK 23.x)** and **v25.3 (SDK 25.3)** — certificate lifecycle
  endpoints on ``/vedsdk/`` are structurally identical across both versions.
  v25.3 adds ``SidExtensionIdentity`` and ``SidExtensionValue`` fields to
  certificate requests.

Authentication
~~~~~~~~~~~~~~
* **OAuth 2.0 password-grant** (``/vedauth/authorize/oauth``) — returns a
  Bearer token used in ``Authorization`` headers.  This is the **only**
  authentication method on TPP 22.3+.
* **Legacy LDAP / VEdSDK** (``/vedsdk/authorize``) — returns an API key
  placed in ``X-Venafi-Api-Key`` headers.  **Deprecated in TPP 20.1 and
  completely removed in TPP 22.3** (returns HTTP 401: "API keys are
  deprecated").  Retained here for pre-22.3 deployments.

Download modes
~~~~~~~~~~~~~~
1. **Server-side key** — Venafi holds the private key; the client retrieves a
   PKCS#12 bundle and extracts the key locally.
2. **Client-side CSR** — The client generates a key pair and CSR, submits the
   CSR to Venafi for signing, and downloads only the signed certificate.

Rate limits and concurrency
~~~~~~~~~~~~~~~~~~~~~~~~~~~
TPP does **not** enforce traditional per-request rate limits (no HTTP 429
responses).  It uses a configurable **session pool model**.  Always reuse
OAuth tokens across requests until expiration.

Field name case sensitivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~
API method paths are case-insensitive, but request body field names are
**case-sensitive** (``"ObjectDN"`` not ``"objectdn"``).

References
----------
* Venafi TPP Web SDK:
  https://docs.venafi.com/Docs/current/TopNav/Content/SDK/WebSDK/API_reference.htm
* Auth SDK (OAuth 2.0):
  https://docs.venafi.com/Docs/current/TopNav/Content/SDK/AuthSDK/r-SDKa-AUTH.php
* Swagger explorer:  ``https://{tpp_host}/VEDSDK/swagger.aspx``
"""

from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import hvac
import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from certmesh import certificate_utils as cu
from certmesh import credentials as creds
from certmesh.certificate_utils import CertificateBundle, SubjectInfo
from certmesh.circuit_breaker import create_circuit_breaker
from certmesh.exceptions import (
    ConfigurationError,
    VenafiAPIError,
    VenafiAuthenticationError,
    VenafiCertificateNotFoundError,
    VenafiLDAPAuthError,
    VenafiPollingTimeoutError,
    VenafiPrivateKeyExportError,
    VenafiWorkflowApprovalError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

_CONTENT_TYPE_JSON = "application/json"

# ---------------------------------------------------------------------------
# Revocation reason codes (RFC 5280 CRLReason)
#
# Spec reference: POST /vedsdk/Certificates/Revoke — ``Reason`` field.
#   0 = None (Unspecified)
#   1 = User key compromised (KeyCompromise)
#   2 = CA key compromised (CACompromise)
#   3 = User changed affiliation (AffiliationChanged)
#   4 = Certificate superseded (Superseded)
#   5 = Original use no longer valid (CessationOfOperation)
# ---------------------------------------------------------------------------

REVOCATION_REASONS: dict[str, int] = {
    "unspecified": 0,
    "key_compromise": 1,
    "ca_compromise": 2,
    "affiliation_changed": 3,
    "superseded": 4,
    "cessation_of_operation": 5,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class VenafiCertificateSummary:
    """Lightweight summary returned by list/search operations."""

    guid: str
    dn: str
    name: str
    created_on: str
    schema_class: str
    approx_not_after: str = ""


@dataclass(slots=True, frozen=True)
class VenafiCertificateDetail:
    """Extended detail returned by the describe operation."""

    guid: str
    dn: str
    name: str
    created_on: str
    serial_number: str
    thumbprint: str
    valid_from: str
    valid_to: str
    issuer: str
    subject: str
    key_algorithm: str
    key_size: int
    san_dns_names: list[str] = field(default_factory=list)
    stage: int = 0
    status: str = ""
    in_error: bool = False


# ============================================================================
# Internal: session / auth helpers
# ============================================================================


def _build_session(venafi_cfg: JsonDict) -> requests.Session:
    """Build a ``requests.Session`` pre-configured for Venafi TPP."""
    session = requests.Session()
    session.verify = venafi_cfg.get("tls_verify", True)
    session.headers.update(
        {
            "Content-Type": _CONTENT_TYPE_JSON,
            "Accept": _CONTENT_TYPE_JSON,
        }
    )
    return session


def _base_url(venafi_cfg: JsonDict) -> str:
    """Return the base URL stripped of a trailing slash."""
    url: str = venafi_cfg.get("base_url", "")
    if not url:
        raise ConfigurationError("venafi.base_url is required. Set CM_VENAFI_BASE_URL.")
    return url.rstrip("/")


def _timeout(venafi_cfg: JsonDict) -> int:
    """Return the HTTP timeout in seconds."""
    return int(venafi_cfg.get("timeout_seconds", 30))


# ============================================================================
# Authentication
# ============================================================================


def _authenticate_oauth(
    session: requests.Session,
    base: str,
    username: str,
    password: str,
    venafi_cfg: JsonDict,
    *,
    timeout: int = 30,
) -> None:
    """Authenticate via the Venafi OAuth2 password-grant endpoint.

    Spec reference: ``POST /vedauth/authorize/oauth``

    Required request body fields per spec: ``client_id``, ``username``,
    ``password``, ``scope``.  Optional: ``state`` (CSRF prevention).

    On success the session is updated with an ``Authorization: Bearer <token>``
    header for all subsequent calls.  The response also includes a
    ``refresh_token`` for future token renewal via
    ``POST /vedauth/authorize/token``.

    .. note::
       The ``grant_type`` field is **not** part of the Venafi VedAuth spec
       and has been intentionally omitted.  VedAuth infers the grant type
       from the endpoint path (``/authorize/oauth`` = password grant).
    """
    client_id: str = venafi_cfg.get("oauth_client_id", "certapi")
    scope: str = venafi_cfg.get("oauth_scope", "certificate:manage")
    url = f"{base}/vedauth/authorize/oauth"

    payload: JsonDict = {
        "client_id": client_id,
        "username": username,
        "password": password,
        "scope": scope,
    }

    logger.debug("Venafi OAuth: requesting token.", extra={"url": url, "client_id": client_id})

    resp = session.post(url, json=payload, timeout=timeout)

    if resp.status_code == 401:
        raise VenafiAuthenticationError(
            f"Venafi OAuth authentication failed (HTTP 401). "
            f"Verify username/password and client_id '{client_id}'."
        )
    if resp.status_code == 400:
        body = resp.text[:300]
        raise VenafiAuthenticationError(f"Venafi OAuth authentication rejected (HTTP 400): {body}")
    if not resp.ok:
        raise VenafiAuthenticationError(
            f"Venafi OAuth unexpected response: HTTP {resp.status_code} — {resp.text[:300]}"
        )

    data: JsonDict = resp.json()
    access_token: str = data.get("access_token", "")
    if not access_token:
        raise VenafiAuthenticationError("Venafi OAuth response did not contain an access_token.")

    session.headers["Authorization"] = f"Bearer {access_token}"
    logger.info("Venafi: authenticated via OAuth.", extra={"client_id": client_id})


def _authenticate_ldap(
    session: requests.Session,
    base: str,
    username: str,
    password: str,
    *,
    timeout: int = 30,
) -> None:
    """Authenticate via the Venafi legacy VEdSDK / LDAP endpoint.

    Spec reference: ``POST /vedsdk/authorize/`` (pre-22.3 only)

    .. deprecated:: TPP 22.3
       The ``/vedsdk/authorize/`` endpoint was deprecated in TPP 20.1 and
       **completely removed in TPP 22.3** (returns HTTP 401: "API keys are
       deprecated").  This method is retained for pre-22.3 deployments.
       For TPP 22.3+ use OAuth 2.0 via ``/vedauth/authorize/oauth``.

    On success the session is updated with an ``X-Venafi-Api-Key`` header for
    all subsequent calls.
    """
    url = f"{base}/vedsdk/authorize"

    payload: JsonDict = {
        "Username": username,
        "Password": password,
    }

    logger.warning(
        "Venafi: using legacy LDAP/API-key authentication (/vedsdk/authorize). "
        "This endpoint was removed in TPP 22.3. Consider migrating to OAuth 2.0 "
        "(/vedauth/authorize/oauth) for TPP 22.3+ compatibility.",
        extra={"url": url},
    )

    resp = session.post(url, json=payload, timeout=timeout)

    if resp.status_code == 401:
        raise VenafiLDAPAuthError(
            "Venafi LDAP authentication failed (HTTP 401). Verify credentials."
        )
    if not resp.ok:
        raise VenafiLDAPAuthError(
            f"Venafi LDAP unexpected response: HTTP {resp.status_code} — {resp.text[:300]}"
        )

    data: JsonDict = resp.json()
    api_key: str = data.get("APIKey", "")
    if not api_key:
        raise VenafiLDAPAuthError("Venafi LDAP response did not contain an APIKey.")

    session.headers["X-Venafi-Api-Key"] = api_key
    logger.info("Venafi: authenticated via LDAP/VEdSDK.", extra={})


def authenticate(
    venafi_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> requests.Session:
    """Build an authenticated ``requests.Session`` for the Venafi TPP API.

    Credential resolution order:
    1. ``CM_VENAFI_USERNAME`` / ``CM_VENAFI_PASSWORD`` environment variables.
    2. Vault secret at the configured path.

    The auth method (``oauth`` or ``ldap``) is determined by
    ``venafi_cfg["auth_method"]``:

    * ``"oauth"`` — Uses ``POST /vedauth/authorize/oauth`` (TPP 20.1+,
      required for TPP 22.3+).  Returns a Bearer token.
    * ``"ldap"`` — Uses ``POST /vedsdk/authorize`` (pre-22.3 only).
      Returns an API key.  **Removed in TPP 22.3.**

    .. note::
       The caller is responsible for closing the returned session (e.g. via a
       ``with`` statement or an explicit ``session.close()`` call) to release
       the underlying connection pool.  On authentication failure the session
       is closed automatically before the exception is re-raised.
    """
    session = _build_session(venafi_cfg)
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)

    resolved = creds.resolve_venafi_credentials(vault_cfg, vault_cl)
    username = resolved["username"]
    password = resolved["password"]

    auth_method: str = venafi_cfg.get("auth_method", "oauth")

    try:
        if auth_method == "oauth":
            # OAuth 2.0 via /vedauth/authorize/oauth — supported on TPP 20.1+,
            # required on TPP 22.3+ (v23, v25.3).
            _authenticate_oauth(
                session,
                base,
                username,
                password,
                venafi_cfg,
                timeout=timeout,
            )
        elif auth_method == "ldap":
            # Legacy API-key via /vedsdk/authorize — supported on TPP < 22.3
            # only.  Deprecated in TPP 20.1, removed in TPP 22.3.
            _authenticate_ldap(
                session,
                base,
                username,
                password,
                timeout=timeout,
            )
        else:
            raise ConfigurationError(
                f"Unsupported venafi.auth_method '{auth_method}'. "
                f"Supported: 'oauth' (TPP 20.1+, required 22.3+), "
                f"'ldap' (TPP < 22.3 only)."
            )
    except Exception:
        session.close()
        raise

    return session


# ============================================================================
# Retry / circuit breaker helpers
# ============================================================================


def _build_retry_decorator(venafi_cfg: JsonDict):
    """Return a tenacity ``retry`` decorator from the venafi retry config."""
    retry_cfg: JsonDict = venafi_cfg.get("retry", {})
    return retry(
        retry=retry_if_exception_type(
            (requests.ConnectionError, requests.Timeout, requests.exceptions.HTTPError)
        ),
        stop=stop_after_attempt(int(retry_cfg.get("max_attempts", 5))),
        wait=wait_exponential(
            multiplier=float(retry_cfg.get("wait_multiplier", 1.5)),
            min=float(retry_cfg.get("wait_min_seconds", 2)),
            max=float(retry_cfg.get("wait_max_seconds", 60)),
        ),
        reraise=True,
    )


def _build_circuit_breaker(venafi_cfg: JsonDict):
    """Return a circuit breaker decorator from the venafi config."""
    cb_cfg: JsonDict = venafi_cfg.get("circuit_breaker", {})
    return create_circuit_breaker(
        failure_threshold=int(cb_cfg.get("failure_threshold", 5)),
        recovery_timeout_seconds=float(cb_cfg.get("recovery_timeout_seconds", 120)),
        name="venafi-tpp",
    )


def _parse_certificate_summary(entry: JsonDict) -> VenafiCertificateSummary:
    """Parse a raw API entry into a ``VenafiCertificateSummary``."""
    return VenafiCertificateSummary(
        guid=entry.get("Guid", entry.get("guid", "")),
        dn=entry.get("DN", entry.get("dn", "")),
        name=entry.get("Name", entry.get("name", "")),
        created_on=entry.get("CreatedOn", entry.get("created_on", "")),
        schema_class=entry.get("SchemaClass", entry.get("schema_class", "")),
        approx_not_after=entry.get(
            "X509.NotAfter",
            entry.get("ValidTo", ""),
        ),
    )


# ============================================================================
# Response helpers
# ============================================================================


def _raise_for_status(resp: requests.Response, context: str) -> None:
    """Raise an appropriate Venafi exception for non-2xx responses.

    HTTP status code mapping per Venafi TPP spec:
    * **401** — Expired/revoked token.  Consider refreshing via
      ``POST /vedauth/authorize/token``.
    * **403** — Insufficient scope (since TPP 20.4; was 401 before).
    * **404** — Object does not exist.
    * **400** — Missing/invalid parameters, expired grant.
    * **409** — Object already exists or read-only.
    * **500** — CA unreachable, internal failures.

    .. note::
       TPP does **not** return HTTP 429.  Rate limiting is handled via the
       configurable session pool model.
    """
    if resp.ok:
        return

    status = resp.status_code
    body = resp.text[:500]

    if status == 401:
        raise VenafiAuthenticationError(
            f"{context}: authentication expired or invalid (HTTP 401). "
            "If using OAuth, try refreshing the token via "
            "POST /vedauth/authorize/token."
        )
    if status == 403:
        raise VenafiAuthenticationError(
            f"{context}: forbidden (HTTP 403). Check token scopes and "
            "object permissions. Note: TPP 20.4+ returns 403 for "
            "insufficient scope (was 401 in earlier versions)."
        )
    if status == 404:
        raise VenafiCertificateNotFoundError(f"{context}: resource not found (HTTP 404).")

    raise VenafiAPIError(
        f"{context}: unexpected response.",
        status_code=status,
        body=body,
    )


# ============================================================================
# Workflow approval
# ============================================================================


def _approve_workflow_tickets(
    session: requests.Session,
    base: str,
    certificate_dn: str,
    venafi_cfg: JsonDict,
    *,
    timeout: int = 30,
) -> None:
    """Find and approve any pending workflow tickets for a certificate DN.

    Spec reference:
    * ``POST /vedsdk/workflow/ticket/enumerate`` — list tickets for an object.
    * ``POST /vedsdk/workflow/ticket/updatestatus`` — approve or reject.
      Request: ``{"GUID": "...", "Status": "Approved", "Explanation": "..."}``.
    """
    approval_cfg: JsonDict = venafi_cfg.get("approval", {})
    reason: str = approval_cfg.get("reason", "Automated renewal approved by certmesh")

    # Step 1: list pending tickets for the object
    # Spec: POST /vedsdk/workflow/ticket/enumerate
    list_url = f"{base}/vedsdk/workflow/ticket/enumerate"
    list_payload: JsonDict = {"ObjectDN": certificate_dn}

    resp = session.post(list_url, json=list_payload, timeout=timeout)
    _raise_for_status(resp, "Workflow ticket enumerate")

    data: JsonDict = resp.json()
    tickets: list[JsonDict] = data.get("Tickets", data.get("tickets", []))

    if not tickets:
        logger.debug("No pending workflow tickets.", extra={"certificate_dn": certificate_dn})
        return

    # Step 2: approve each ticket
    # Spec: POST /vedsdk/workflow/ticket/updatestatus (NOT /ticket/update)
    approve_url = f"{base}/vedsdk/workflow/ticket/updatestatus"

    for ticket in tickets:
        # Tickets carry a GUID identifier per spec.  Fall back to "Id" for
        # older TPP versions that may still use integer IDs.
        ticket_guid = ticket.get("GUID", ticket.get("Guid", ticket.get("Id", ticket.get("id"))))
        if ticket_guid is None:
            logger.warning("Workflow ticket missing GUID/Id field.", extra={"ticket": ticket})
            continue

        # Spec: {"GUID": "...", "Status": "Approved", "Explanation": "..."}
        approve_payload: JsonDict = {
            "GUID": str(ticket_guid),
            "Status": "Approved",
            "Explanation": reason,
        }

        approve_resp = session.post(
            approve_url,
            json=approve_payload,
            timeout=timeout,
        )

        if not approve_resp.ok:
            raise VenafiWorkflowApprovalError(
                f"Failed to approve workflow ticket {ticket_guid} for "
                f"DN='{certificate_dn}': HTTP {approve_resp.status_code} — "
                f"{approve_resp.text[:300]}"
            )

        logger.info(
            "Approved workflow ticket.",
            extra={"ticket_guid": ticket_guid, "certificate_dn": certificate_dn},
        )


# ============================================================================
# Polling helper
# ============================================================================


def _poll_certificate_ready(
    session: requests.Session,
    base: str,
    certificate_dn: str,
    venafi_cfg: JsonDict,
    *,
    timeout: int = 30,
) -> None:
    """Poll until the certificate DN has reached ``stage >= 500`` (issued).

    Spec reference: ``GET /vedsdk/Certificates/{guid}`` for metadata.
    Stage values per spec:
    * Stage -1 = "Queued for renewal"
    * Stage 0 = "Not yet available"
    * Stage >= 500 = Certificate issued / available for download

    .. note::
       TPP uses a **Workflow/Ticket** system for approvals — there are no
       WebSocket, long-polling, or async job endpoints.  Polling is the
       standard approach.

    Raises ``VenafiPollingTimeoutError`` if the timeout elapses.
    """
    polling_cfg: JsonDict = venafi_cfg.get("polling", {})
    interval: int = int(polling_cfg.get("interval_seconds", 15))
    max_wait: int = int(polling_cfg.get("max_wait_seconds", 1800))

    detail_url = f"{base}/vedsdk/certificates"
    start_time = time.monotonic()

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed >= max_wait:
            break

        params: JsonDict = {"ObjectDN": certificate_dn}
        resp = session.get(detail_url, params=params, timeout=timeout)

        if resp.ok:
            data: JsonDict = resp.json()
            stage: int = data.get("Stage", data.get("stage", 0))
            status_text: str = data.get("Status", data.get("status", ""))

            logger.debug(
                "Poll certificate status.",
                extra={
                    "certificate_dn": certificate_dn,
                    "stage": stage,
                    "status": status_text,
                    "elapsed_seconds": elapsed,
                },
            )

            if stage >= 500:
                logger.info(
                    "Certificate is ready.",
                    extra={"certificate_dn": certificate_dn, "stage": stage},
                )
                return
        else:
            # Permanent client errors (except 404/503) should abort immediately
            # rather than wasting the full polling timeout.
            if 400 <= resp.status_code < 500 and resp.status_code not in (404, 408, 429):
                _raise_for_status(resp, f"Poll certificate DN='{certificate_dn}'")
            logger.warning(
                "Poll certificate: unexpected HTTP status (will retry).",
                extra={"certificate_dn": certificate_dn, "status_code": resp.status_code},
            )

        time.sleep(interval)

    raise VenafiPollingTimeoutError(
        f"Certificate DN='{certificate_dn}' did not reach ready state within {max_wait}s."
    )


# ============================================================================
# Download helpers
# ============================================================================


def _download_pkcs12(
    session: requests.Session,
    base: str,
    certificate_dn: str,
    passphrase: str,
    *,
    include_chain: bool = True,
    timeout: int = 30,
) -> bytes:
    """Retrieve a PKCS#12 bundle from Venafi TPP (server-side key mode).

    Spec reference: ``POST /vedsdk/Certificates/Retrieve``
    Required token scope: ``certificate:manage``
    Required permissions: Read + Private Key Read

    Format MIME type for PKCS#12: ``application/x-pkcs12``.
    Password must be at least 12 chars with 3 of 4 char types.
    """
    url = f"{base}/vedsdk/certificates/retrieve"

    payload: JsonDict = {
        "CertificateDN": certificate_dn,
        "Format": "PKCS #12",
        "Password": passphrase,
        "IncludeChain": include_chain,
        "IncludePrivateKey": True,
    }

    resp = session.post(url, json=payload, timeout=timeout)

    if resp.status_code == 400:
        body = resp.text[:300]
        if "private key" in body.lower() or "denied" in body.lower():
            raise VenafiPrivateKeyExportError(
                f"Private key export denied for DN='{certificate_dn}'. Check the policy: {body}"
            )
        _raise_for_status(resp, f"PKCS#12 retrieve DN='{certificate_dn}'")

    _raise_for_status(resp, f"PKCS#12 retrieve DN='{certificate_dn}'")

    content_type = resp.headers.get("Content-Type", "")
    if _CONTENT_TYPE_JSON in content_type:
        # Venafi sometimes returns a JSON wrapper with a Base64-encoded body
        data: JsonDict = resp.json()
        cert_data_b64: str = data.get("CertificateData", "")
        if not cert_data_b64:
            raise VenafiAPIError(
                f"PKCS#12 retrieve for DN='{certificate_dn}' returned JSON "
                "without CertificateData.",
                status_code=resp.status_code,
                body=resp.text[:300],
            )
        return base64.b64decode(cert_data_b64)

    # Binary response
    return resp.content


def _download_base64_cert(
    session: requests.Session,
    base: str,
    certificate_dn: str,
    *,
    include_chain: bool = True,
    timeout: int = 30,
) -> str:
    """Retrieve a Base64-encoded certificate (no private key) from Venafi TPP.

    Spec reference: ``POST /vedsdk/Certificates/Retrieve`` with
    ``Format="Base64"`` and ``IncludePrivateKey=false``.

    Used in the client-side CSR flow where the private key was never sent to
    Venafi.  For Base64/PEM format, ``CertificateData`` IS the PEM content
    (already base64-encoded PEM).
    """
    url = f"{base}/vedsdk/certificates/retrieve"

    payload: JsonDict = {
        "CertificateDN": certificate_dn,
        "Format": "Base64",
        "IncludeChain": include_chain,
        "IncludePrivateKey": False,
    }

    resp = session.post(url, json=payload, timeout=timeout)
    _raise_for_status(resp, f"Base64 retrieve DN='{certificate_dn}'")

    content_type = resp.headers.get("Content-Type", "")
    if _CONTENT_TYPE_JSON in content_type:
        data: JsonDict = resp.json()
        cert_data: str = data.get("CertificateData", "")
        if not cert_data:
            raise VenafiAPIError(
                f"Base64 retrieve for DN='{certificate_dn}' returned JSON "
                "without CertificateData.",
                status_code=resp.status_code,
                body=resp.text[:300],
            )
        return cert_data

    return resp.text


def _resolve_pkcs12_passphrase(venafi_cfg: JsonDict) -> str:
    """Resolve the PKCS#12 export passphrase from an environment variable."""
    cert_cfg: JsonDict = venafi_cfg.get("certificate", {})
    env_var: str = cert_cfg.get("pkcs12_export_passphrase_env", "CM_VENAFI_PKCS12_PASSPHRASE")
    passphrase = os.environ.get(env_var, "")
    if not passphrase:
        raise ConfigurationError(
            f"PKCS#12 export passphrase not set. "
            f"Provide it via the '{env_var}' environment variable."
        )
    return passphrase


# ============================================================================
# Public API: renew_and_download_certificate
# ============================================================================


def renew_and_download_certificate(
    session: requests.Session,
    venafi_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    *,
    certificate_guid: str,
) -> CertificateBundle:
    """Renew an existing Venafi TPP certificate and download the result.

    Spec reference: ``POST /vedsdk/Certificates/Renew``
    Required token scope: ``certificate:manage``
    Required permissions: Write + Private Key Read

    Workflow:
    1. ``POST /vedsdk/certificates/renew`` to initiate the renewal.
    2. ``POST /vedsdk/workflow/ticket/enumerate`` + ``updatestatus`` to
       approve any pending workflow tickets.
    3. Poll ``GET /vedsdk/certificates/{guid}`` until stage ≥ 500 (issued).
    4. ``POST /vedsdk/certificates/retrieve`` to download the PKCS#12 bundle.
    5. Assemble and return a ``CertificateBundle``.

    This function is wrapped with tenacity retry + circuit breaker decorators.
    """
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> CertificateBundle:
        # ----- 1. Initiate renewal -----
        renew_url = f"{base}/vedsdk/certificates/renew"
        renew_payload: JsonDict
        if _is_guid(certificate_guid):
            renew_payload = {
                "CertificateGUID": f"{{{certificate_guid}}}",
            }
        else:
            # Accept both short names (prefixed automatically) and full
            # DN paths (starting with \VED\) to avoid double-prefixing.
            dn = certificate_guid
            if not dn.startswith("\\VED\\"):
                dn = f"\\VED\\Policy\\{dn}"
            renew_payload = {"CertificateDN": dn}

        resp = session.post(renew_url, json=renew_payload, timeout=timeout)
        _raise_for_status(resp, f"Renew certificate GUID='{certificate_guid}'")

        renew_data: JsonDict = resp.json()
        success: bool = renew_data.get("Success", renew_data.get("success", False))
        if not success:
            error_msg = renew_data.get("Error", renew_data.get("error", "unknown"))
            raise VenafiAPIError(
                f"Renewal request rejected for GUID='{certificate_guid}': {error_msg}",
                status_code=resp.status_code,
            )

        logger.info("Renewal initiated.", extra={"certificate_guid": certificate_guid})

        # We need the DN for subsequent calls
        certificate_dn: str = renew_data.get(
            "CertificateDN",
            renew_data.get("DN", ""),
        )

        # If the renewal response did not include a DN, look it up
        if not certificate_dn:
            certificate_dn = _resolve_dn_from_guid(
                session,
                base,
                certificate_guid,
                timeout=timeout,
            )

        # ----- 2. Approve workflow tickets -----
        try:
            _approve_workflow_tickets(
                session,
                base,
                certificate_dn,
                venafi_cfg,
                timeout=timeout,
            )
        except VenafiWorkflowApprovalError:
            logger.warning(
                "Workflow approval failed; certificate may already be approved.",
                extra={"certificate_dn": certificate_dn},
            )

        # ----- 3. Poll for completion -----
        _poll_certificate_ready(
            session,
            base,
            certificate_dn,
            venafi_cfg,
            timeout=timeout,
        )

        # ----- 4. Download PKCS#12 and extract -----
        passphrase = _resolve_pkcs12_passphrase(venafi_cfg)

        pkcs12_bytes = _download_pkcs12(
            session,
            base,
            certificate_dn,
            passphrase,
            timeout=timeout,
        )

        cert_pem, key_pem, chain_pem = cu.parse_pkcs12_bundle(
            pkcs12_bytes,
            passphrase,
        )

        # ----- 5. Assemble bundle -----
        bundle = cu.assemble_bundle(
            cert_pem=cert_pem,
            private_key_pem=key_pem,
            chain_pem=chain_pem,
            source_id=certificate_guid,
        )

        logger.info(
            "Venafi renewal complete.",
            extra={
                "certificate_guid": certificate_guid,
                "common_name": bundle.common_name,
                "serial": bundle.serial_number,
            },
        )
        return bundle

    return _inner()


# ============================================================================
# Public API: list_certificates
# ============================================================================


def list_certificates(
    session: requests.Session,
    venafi_cfg: JsonDict,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[VenafiCertificateSummary]:
    """List certificates managed by Venafi TPP with pagination.

    Spec reference: ``GET /vedsdk/Certificates/``
    Required token scope: ``certificate`` (read access implied)

    Query parameters: ``Limit`` (default 100), ``Offset``.
    Response includes ``Certificates`` array, ``DataRange``, ``TotalCount``,
    and ``_links`` for next/previous pagination.

    .. note::
       Trailing slash on the URL may be required in some TPP versions —
       included for safety per spec.
    """
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> list[VenafiCertificateSummary]:
        url = f"{base}/vedsdk/certificates/"
        params: JsonDict = {"Limit": limit, "Offset": offset}

        resp = session.get(url, params=params, timeout=timeout)
        _raise_for_status(resp, "List certificates")

        data: JsonDict = resp.json()
        raw_certs: list[JsonDict] = data.get("Certificates", data.get("certificates", []))
        summaries = [_parse_certificate_summary(entry) for entry in raw_certs]

        logger.info(
            "Venafi: listed certificates.",
            extra={"count": len(summaries), "offset": offset, "limit": limit},
        )
        return summaries

    return _inner()


# ============================================================================
# Public API: search_certificates
# ============================================================================


def search_certificates(
    session: requests.Session,
    venafi_cfg: JsonDict,
    *,
    common_name: str | None = None,
    san_dns: str | None = None,
    serial_number: str | None = None,
    thumbprint: str | None = None,
    issuer: str | None = None,
    key_size: int | None = None,
    valid_to_less_than: str | None = None,
    valid_to_greater_than: str | None = None,
    managed_by: str | None = None,
    stage: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[VenafiCertificateSummary]:
    """Search certificates via ``GET /vedsdk/Certificates/`` with filters.

    Spec reference: ``GET /vedsdk/Certificates/``
    Required token scope: ``certificate`` (read access implied)

    The spec defines all filter fields as query parameters for GET requests.
    This implementation sends them as a JSON POST body, which Venafi TPP also
    accepts.  Only non-``None`` filter parameters are included.

    Available filters per spec: ``CN``, ``SAN-DNS``, ``Serial``,
    ``Thumbprint``, ``Issuer``, ``KeySize``, ``ValidToLess``,
    ``ValidToGreater``, ``ManagedBy``, ``Stage``, and many more.
    """
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> list[VenafiCertificateSummary]:
        url = f"{base}/vedsdk/certificates/"

        payload: JsonDict = {
            "Limit": limit,
            "Offset": offset,
        }

        if common_name is not None:
            payload["CN"] = common_name
        if san_dns is not None:
            payload["SAN-DNS"] = san_dns
        if serial_number is not None:
            payload["Serial"] = serial_number
        if thumbprint is not None:
            payload["Thumbprint"] = thumbprint
        if issuer is not None:
            payload["Issuer"] = issuer
        if key_size is not None:
            payload["KeySize"] = key_size
        if valid_to_less_than is not None:
            payload["ValidToLess"] = valid_to_less_than
        if valid_to_greater_than is not None:
            payload["ValidToGreater"] = valid_to_greater_than
        if managed_by is not None:
            payload["ManagedBy"] = managed_by
        if stage is not None:
            payload["Stage"] = stage

        resp = session.post(url, json=payload, timeout=timeout)
        _raise_for_status(resp, "Search certificates")

        data: JsonDict = resp.json()
        raw_certs: list[JsonDict] = data.get("Certificates", data.get("certificates", []))
        summaries = [_parse_certificate_summary(entry) for entry in raw_certs]

        logger.info(
            "Venafi: search returned certificates.",
            extra={"count": len(summaries)},
        )
        return summaries

    return _inner()


# ============================================================================
# Public API: describe_certificate
# ============================================================================


def describe_certificate(
    session: requests.Session,
    venafi_cfg: JsonDict,
    *,
    certificate_guid: str,
) -> VenafiCertificateDetail:
    """Retrieve detailed information for a single certificate by GUID.

    Spec reference: ``GET /vedsdk/Certificates/{guid}``
    Required token scope: ``certificate`` (read access implied)

    Returns the full certificate object including ``CertificateDetails``
    (CN, KeyAlgorithm, KeySize, Serial, Thumbprint, ValidFrom, ValidTo,
    Subject, SubjectAltNameDNS, Issuer, SignatureAlgorithm) and
    ``ProcessingDetails`` (InError, InProcess, Stage, Status).
    """
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> VenafiCertificateDetail:
        url = f"{base}/vedsdk/certificates/{certificate_guid}"

        resp = session.get(url, timeout=timeout)
        _raise_for_status(resp, f"Describe certificate GUID='{certificate_guid}'")

        d: JsonDict = resp.json()

        san_entries: list[str] = []
        raw_sans = d.get("SubjectAltNameDNS", d.get("X509.SubjectAltName.DNS", []))
        if isinstance(raw_sans, list):
            san_entries = raw_sans
        elif isinstance(raw_sans, str) and raw_sans:
            san_entries = [s.strip() for s in raw_sans.split(",")]

        detail = VenafiCertificateDetail(
            guid=d.get("Guid") or d.get("guid") or certificate_guid,
            dn=d.get("DN") or d.get("dn") or "",
            name=d.get("Name") or d.get("name") or "",
            created_on=d.get("CreatedOn") or d.get("created_on") or "",
            serial_number=d.get("Serial") or d.get("serial") or "",
            thumbprint=d.get("Thumbprint") or d.get("thumbprint") or "",
            valid_from=d.get("ValidFrom") or d.get("valid_from") or "",
            valid_to=d.get("ValidTo") or d.get("valid_to") or "",
            issuer=d.get("Issuer") or d.get("issuer") or "",
            subject=d.get("Subject") or d.get("subject") or "",
            key_algorithm=d.get("KeyAlgorithm") or d.get("key_algorithm") or "",
            key_size=int(d.get("KeySize") or d.get("key_size") or 0),
            san_dns_names=san_entries,
            stage=int(d.get("Stage") or d.get("stage") or 0),
            status=d.get("Status") or d.get("status") or "",
            in_error=bool(d.get("InError") or d.get("in_error") or False),
        )

        logger.info(
            "Venafi: described certificate.",
            extra={
                "certificate_guid": certificate_guid,
                "subject": detail.subject[:80] if detail.subject else "(empty)",
            },
        )
        return detail

    return _inner()


# ============================================================================
# Public API: revoke_certificate
# ============================================================================


def revoke_certificate(
    session: requests.Session,
    venafi_cfg: JsonDict,
    *,
    certificate_dn: str | None = None,
    thumbprint: str | None = None,
    reason: int = 0,
    comments: str = "",
    disable: bool = False,
) -> JsonDict:
    """Revoke a certificate in Venafi TPP.

    Spec reference: ``POST /vedsdk/Certificates/Revoke``

    Provide either ``certificate_dn`` or ``thumbprint`` to identify the
    certificate.  Revocation reason codes follow RFC 5280 CRLReason:
    0=Unspecified, 1=KeyCompromise, 2=CACompromise, 3=AffiliationChanged,
    4=Superseded, 5=CessationOfOperation.

    Required token scope: ``certificate:revoke``.

    Args:
        session: An authenticated Venafi session.
        venafi_cfg: The ``venafi`` configuration section.
        certificate_dn: The distinguished name of the certificate object.
        thumbprint: The SHA-1 thumbprint of the certificate.
        reason: Revocation reason code (0-5 per RFC 5280).
        comments: Human-readable comment (max 250 chars for Entrust CAs).
        disable: If ``True``, disable the cert object (no replacement).
            ``False`` allows re-enrollment.

    Returns:
        The JSON response body from the revocation endpoint.
        On success: ``{"Requested": true, "Success": true}``.

    Raises:
        VenafiAPIError: On unexpected API errors.
        ConfigurationError: If neither ``certificate_dn`` nor ``thumbprint``
            is provided.
    """
    if not certificate_dn and not thumbprint:
        raise ConfigurationError(
            "Either certificate_dn or thumbprint must be provided for revocation."
        )

    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> JsonDict:
        url = f"{base}/vedsdk/certificates/revoke"

        payload: JsonDict = {"Reason": reason}

        if certificate_dn:
            payload["CertificateDN"] = certificate_dn
        if thumbprint:
            payload["Thumbprint"] = thumbprint
        if comments:
            payload["Comments"] = comments
        if disable:
            # Spec: field name is "Disable" (not "Disabled").
            # true = disable cert (no replacement), false = allow re-enrollment.
            payload["Disable"] = True

        resp = session.post(url, json=payload, timeout=timeout)
        _raise_for_status(resp, "Revoke certificate")

        result: JsonDict = resp.json()
        success: bool = result.get("Success", result.get("success", False))
        if not success:
            error_msg = result.get("Error", result.get("error", "unknown"))
            raise VenafiAPIError(
                f"Revocation rejected: {error_msg}",
                status_code=resp.status_code,
                body=resp.text[:300],
            )

        identifier = certificate_dn or thumbprint
        logger.info(
            "Venafi: revoked certificate.",
            extra={"identifier": identifier, "reason": reason},
        )
        return result

    return _inner()


# ============================================================================
# Public API: request_certificate
# ============================================================================


def request_certificate(
    session: requests.Session,
    venafi_cfg: JsonDict,
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
    *,
    policy_dn: str,
    subject: SubjectInfo,
    use_csr: bool = False,
) -> CertificateBundle:
    """Request a new certificate from Venafi TPP.

    Spec reference: ``POST /vedsdk/Certificates/Request``
    Required token scope: ``certificate:manage``
    Required permissions: Create permission to PolicyDN + Private Key Read

    Submits a new enrollment request and, after issuance, downloads and
    returns the material as a ``CertificateBundle``.

    Two modes are supported:

    * **Server-side key** (``use_csr=False``): Venafi generates the key pair.
      After issuance the PKCS#12 bundle is downloaded via
      ``POST /vedsdk/Certificates/Retrieve`` and the key is extracted locally.
    * **Client-side CSR** (``use_csr=True``): The client generates an RSA key
      pair and CSR, submits the CSR via the ``PKCS10`` field, and downloads
      only the signed certificate.

    v25.3 additions: ``SidExtensionIdentity`` and ``SidExtensionValue``
    fields are available for AD Security Identifier certificate extensions
    but are not currently used by this function.

    Args:
        session: An authenticated Venafi session.
        venafi_cfg: The ``venafi`` configuration section.
        vault_cfg: The ``vault`` configuration section.
        vault_cl: An authenticated hvac.Client (or ``None``).
        policy_dn: The policy folder DN (e.g. ``\\VED\\Policy\\Certificates``).
        subject: X.509 subject information for the certificate.
        use_csr: If ``True``, generate the key locally and submit a CSR.

    Returns:
        A ``CertificateBundle`` with all material.
    """
    base = _base_url(venafi_cfg)
    timeout = _timeout(venafi_cfg)
    cert_cfg: JsonDict = venafi_cfg.get("certificate", {})
    key_size: int = int(cert_cfg.get("key_size", 4096))

    retry_dec = _build_retry_decorator(venafi_cfg)
    cb_dec = _build_circuit_breaker(venafi_cfg)

    @cb_dec
    @retry_dec
    def _inner() -> CertificateBundle:
        # Build the request payload
        payload: JsonDict = {
            "PolicyDN": policy_dn,
            "Subject": subject.common_name,
            "OrganizationalUnit": subject.organisational_unit or None,
            "Organization": subject.organisation or None,
            "Country": subject.country,
            "State": subject.state or None,
            "City": subject.locality or None,
        }

        # SAN DNS entries
        # Spec: SubjectAltNames accepts both numeric Type and string TypeName.
        # Valid TypeName values: "DNS", "IPAddress", "Email", "URI", "OtherName"
        # Equivalent numeric Type values: 2 (DNS), 7 (IP), 1 (Email), 6 (URI), 0 (Other)
        # Using string "DNS" for clarity per spec examples.
        if subject.san_dns_names:
            payload["SubjectAltNames"] = [
                {"TypeName": "DNS", "Name": name} for name in subject.san_dns_names
            ]

        # Client-side CSR path
        private_key_pem_bytes: bytes | None = None
        if use_csr:
            private_key = cu.generate_rsa_private_key(key_size)
            private_key_pem_bytes = cu.private_key_to_pem(private_key)
            csr = cu.build_csr(private_key, subject)
            csr_pem = cu.csr_to_pem(csr)
            payload["PKCS10"] = csr_pem
            logger.debug(
                "Request certificate: using client-side CSR.",
                extra={"common_name": subject.common_name},
            )
        else:
            # Ask Venafi to generate the key server-side
            payload["KeyBitSize"] = key_size
            logger.debug(
                "Request certificate: server-side key generation.",
                extra={"common_name": subject.common_name},
            )

        # ----- Submit the request -----
        url = f"{base}/vedsdk/certificates/request"
        resp = session.post(url, json=payload, timeout=timeout)
        _raise_for_status(resp, f"Request certificate CN='{subject.common_name}'")

        request_data: JsonDict = resp.json()
        certificate_dn: str = request_data.get(
            "CertificateDN",
            request_data.get("DN", ""),
        )

        if not certificate_dn:
            raise VenafiAPIError(
                f"Certificate request for CN='{subject.common_name}' returned no CertificateDN.",
                status_code=resp.status_code,
                body=resp.text[:300],
            )

        certificate_guid: str = request_data.get("Guid", request_data.get("guid", ""))
        logger.info(
            "Venafi: certificate request submitted.",
            extra={"certificate_dn": certificate_dn, "certificate_guid": certificate_guid},
        )

        # ----- Approve workflow tickets -----
        try:
            _approve_workflow_tickets(
                session,
                base,
                certificate_dn,
                venafi_cfg,
                timeout=timeout,
            )
        except VenafiWorkflowApprovalError:
            logger.warning(
                "Workflow approval failed; may not require approval.",
                extra={"certificate_dn": certificate_dn},
            )

        # ----- Poll for completion -----
        _poll_certificate_ready(
            session,
            base,
            certificate_dn,
            venafi_cfg,
            timeout=timeout,
        )

        # ----- Download -----
        source_id = certificate_guid or certificate_dn

        if use_csr:
            # Client-side key — download only the signed certificate
            if private_key_pem_bytes is None:
                raise VenafiAPIError(
                    "Internal error: private key bytes were not generated for "
                    "client-side CSR request.",
                    status_code=0,
                )
            cert_pem_str = _download_base64_cert(
                session,
                base,
                certificate_dn,
                timeout=timeout,
            )
            cert_pem_bytes = cert_pem_str.encode("utf-8")

            # Separate leaf cert from chain if concatenated
            leaf_pem, chain_pem = _split_pem_chain(cert_pem_bytes)

            bundle = cu.assemble_bundle(
                cert_pem=leaf_pem,
                private_key_pem=private_key_pem_bytes,
                chain_pem=chain_pem,
                source_id=source_id,
            )
        else:
            # Server-side key — download PKCS#12
            passphrase = _resolve_pkcs12_passphrase(venafi_cfg)
            pkcs12_bytes = _download_pkcs12(
                session,
                base,
                certificate_dn,
                passphrase,
                timeout=timeout,
            )
            cert_pem, key_pem, chain_pem = cu.parse_pkcs12_bundle(
                pkcs12_bytes,
                passphrase,
            )
            bundle = cu.assemble_bundle(
                cert_pem=cert_pem,
                private_key_pem=key_pem,
                chain_pem=chain_pem,
                source_id=source_id,
            )

        logger.info(
            "Venafi: new certificate issued.",
            extra={
                "common_name": bundle.common_name,
                "serial": bundle.serial_number,
                "certificate_guid": certificate_guid,
            },
        )
        return bundle

    return _inner()


# ============================================================================
# Internal utilities
# ============================================================================


def _is_guid(value: str) -> bool:
    """Return ``True`` if ``value`` looks like a GUID / UUID (8-4-4-4-12)."""
    stripped = value.strip("{}")
    parts = stripped.split("-")
    if len(parts) != 5:
        return False
    expected_lengths = (8, 4, 4, 4, 12)
    return all(len(p) == expected_lengths[i] for i, p in enumerate(parts))


def _resolve_dn_from_guid(
    session: requests.Session,
    base: str,
    guid: str,
    *,
    timeout: int = 30,
) -> str:
    """Look up a certificate DN from a GUID via the describe endpoint."""
    url = f"{base}/vedsdk/certificates/{guid}"
    resp = session.get(url, timeout=timeout)
    _raise_for_status(resp, f"Resolve DN from GUID='{guid}'")

    data: JsonDict = resp.json()
    dn: str = data.get("DN", data.get("dn", ""))
    if not dn:
        raise VenafiCertificateNotFoundError(
            f"Could not resolve DN for GUID='{guid}'. The certificate may not exist."
        )
    logger.debug("Resolved GUID to DN.", extra={"guid": guid, "dn": dn})
    return dn


def _split_pem_chain(pem_data: bytes) -> tuple[bytes, bytes | None]:
    """Split concatenated PEM data into the leaf certificate and the chain.

    If only one certificate is present, ``chain`` is ``None``.
    """
    marker = b"-----BEGIN CERTIFICATE-----"
    parts = pem_data.split(marker)

    # First part is typically empty (before the first marker)
    certs: list[bytes] = []
    for part in parts:
        if part.strip():
            certs.append(marker + part)

    if len(certs) == 0:
        return pem_data, None
    if len(certs) == 1:
        return certs[0], None

    leaf = certs[0]
    chain = b"".join(certs[1:])
    return leaf, chain
