[![PyPI version](https://img.shields.io/pypi/v/certmesh)](https://pypi.org/project/certmesh/)
[![Python](https://img.shields.io/pypi/pyversions/certmesh)](https://pypi.org/project/certmesh/)
[![CI](https://github.com/SCGIS-Wales/certmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/certmesh/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# certmesh

Automated TLS certificate lifecycle management for Python 3.10+.

A unified CLI and Python API for managing certificates across **DigiCert CertCentral**, **Venafi Trust Protection Platform**, **HashiCorp Vault PKI**, and **AWS Certificate Manager** (public + private CA).

## Features

- **Multi-provider** -- single tool for DigiCert, Venafi TPP, Vault PKI, AWS ACM/ACM-PCA, and Let's Encrypt
- **Full lifecycle** -- request, list, search, describe, download, renew, revoke, and export certificates
- **REST API** -- production-grade FastAPI service with OAuth2 (ADFS / Azure Entra ID), API key exchange, rate limiting, GZip compression, Prometheus metrics, and full CRUD endpoints for all providers
- **Spec-compliant** -- all provider API calls validated against official API reference documentation (DigiCert CertCentral v2, Venafi TPP v23/v25.3, AWS ACM)
- **Credential security** -- secrets come from Vault (KV v1/v2) or environment variables, never from config files
- **Resilient** -- circuit breakers with TOCTOU-safe HALF_OPEN probing, exponential-backoff retry, monotonic-clock polling, and configurable timeouts on all HTTP calls
- **Automatic renewal** -- scheduled certificate renewal engine with configurable policy (before-expiry threshold, per-provider dispatch)
- **Configurable** -- layered config: built-in defaults < YAML file < `CM_*` environment variables
- **Cloud-native** -- Docker image, Helm chart for EKS with IRSA, NLB, HPA, Vault PKI TLS, and JSON Schema input validation
- **Typed** -- fully typed with `py.typed` marker; dataclass models for all API responses

## Installation

```bash
pip install certmesh
```

From source:

```bash
git clone https://github.com/SCGIS-Wales/certmesh.git
cd certmesh
pip install -e ".[dev]"
```

**Requires Python 3.10, 3.11, 3.12, 3.13, or 3.14.**

## Quick Start

```bash
# Show effective config
certmesh config show

# Issue a certificate from Vault PKI
certmesh vault-pki issue --cn myservice.example.com --ttl 720h

# Request a public ACM certificate
certmesh acm request --cn myapp.example.com --validation DNS

# List DigiCert certificates
certmesh digicert list --status issued

# Renew a Venafi TPP certificate
certmesh venafi renew --guid "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

## Configuration

Configuration is layered (lowest to highest precedence):

1. **Built-in defaults** -- sensible defaults for all settings
2. **YAML config file** -- `config/config.yaml` or `--config PATH`
3. **`CM_*` environment variables** -- override any setting

```bash
# Use a .env file
certmesh --env-file .env digicert list

# Override log level
certmesh --log-level DEBUG acm list
```

See [`config/config.yaml`](config/config.yaml) for the full annotated reference and [`.env.example`](.env.example) for all environment variables.

### Authentication

| Provider | Method |
|----------|--------|
| **Vault** | AppRole (default), LDAP, or AWS IAM |
| **DigiCert** | API key from `CM_DIGICERT_API_KEY` or Vault KV (keys do not expire but can be revoked) |
| **Venafi** | OAuth2 (TPP 20.1+, required 22.3+) or LDAP (pre-22.3 only); credentials from `CM_VENAFI_USERNAME`/`CM_VENAFI_PASSWORD` or Vault KV |
| **AWS ACM** | Standard boto3 credential chain (IAM role, env vars, `~/.aws/credentials`) |
| **Let's Encrypt** | ACME account key (auto-generated or provided) |

Credentials are resolved env-first, Vault-fallback. Vault is only contacted when needed.

## CLI Reference

Exit codes: `0` = success, `1` = config/auth error, `2` = cert operation error, `3` = unexpected error.

### DigiCert CertCentral

```bash
certmesh digicert list     [--status TEXT] [--limit INT]
certmesh digicert search   [--cn TEXT] [--serial TEXT] [--status TEXT] [--product TEXT]
certmesh digicert describe --cert-id INT
certmesh digicert order    --cn TEXT [--san TEXT ...]
certmesh digicert download --cert-id INT --key-file PATH
certmesh digicert revoke   --cert-id INT|--order-id INT [--reason CHOICE] [--comments TEXT]
certmesh digicert duplicate --order-id INT --csr-file PATH [--cn TEXT] [--san TEXT ...]
```

### Venafi TPP

```bash
certmesh venafi list       [--limit INT] [--offset INT]
certmesh venafi search     [--cn TEXT] [--san TEXT]
certmesh venafi describe   --guid TEXT
certmesh venafi request    --policy-dn TEXT --cn TEXT [--san TEXT ...] [--client-csr]
certmesh venafi renew      --guid TEXT
certmesh venafi renew-bulk --guid-file PATH
certmesh venafi revoke     --dn TEXT|--thumbprint TEXT [--reason INT] [--disable]
certmesh venafi download   --guid TEXT
```

### HashiCorp Vault PKI

```bash
certmesh vault-pki issue   --cn TEXT [--san TEXT ...] [--ip-san TEXT ...] [--ttl TEXT] [--output-dir PATH]
certmesh vault-pki sign    --cn TEXT --csr-file PATH [--san TEXT ...] [--ttl TEXT] [--output-dir PATH]
certmesh vault-pki list
certmesh vault-pki read    --serial TEXT
certmesh vault-pki revoke  --serial TEXT
```

### AWS ACM (Public Certificates)

```bash
certmesh acm request           --cn TEXT [--san TEXT ...] [--validation DNS|EMAIL] [--key-algorithm TEXT] [--region TEXT]
certmesh acm list              [--status TEXT ...] [--region TEXT]
certmesh acm describe          --arn TEXT [--region TEXT]
certmesh acm export            --arn TEXT --passphrase [--output-dir PATH] [--region TEXT]
certmesh acm renew             --arn TEXT [--region TEXT]
certmesh acm delete            --arn TEXT [--region TEXT]
certmesh acm validation-records --arn TEXT [--region TEXT]
certmesh acm wait              --arn TEXT [--region TEXT]
```

### AWS ACM Private CA

```bash
certmesh acm-pca issue   --ca-arn TEXT --csr-file PATH [--validity-days INT] [--signing-algorithm TEXT] [--region TEXT]
certmesh acm-pca get     --ca-arn TEXT --cert-arn TEXT [--region TEXT]
certmesh acm-pca revoke  --ca-arn TEXT --cert-arn TEXT --cert-serial TEXT [--reason CHOICE] [--region TEXT]
certmesh acm-pca list    --ca-arn TEXT [--region TEXT]
```

### Config Management

```bash
certmesh config show       # Display effective merged config (secrets redacted)
certmesh config validate   # Validate config; exits 0 on success, 1 on failure
```

## REST API

The REST API provides the same operations as the CLI over HTTP. Start the API server with:

```bash
uvicorn certmesh.api.app:create_app --factory --host 0.0.0.0 --port 8000
```

Base path: `/api/v1`. Health endpoints at `/healthz`, `/readyz`, `/livez`. Prometheus metrics at `/metrics`.

### DigiCert Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/digicert/certificates` | List issued certificates |
| `POST` | `/api/v1/digicert/certificates/search` | Search certificates by CN, status |
| `GET` | `/api/v1/digicert/certificates/{id}` | Describe a certificate |
| `POST` | `/api/v1/digicert/orders` | Order a new certificate |
| `POST` | `/api/v1/digicert/certificates/{id}/revoke` | Revoke a certificate |

### Venafi TPP Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/venafi/certificates` | List managed certificates |
| `POST` | `/api/v1/venafi/certificates/search` | Search by CN, SAN, thumbprint, serial, issuer |
| `GET` | `/api/v1/venafi/certificates/{guid}` | Describe a certificate by GUID |
| `POST` | `/api/v1/venafi/certificates/{guid}/renew` | Renew a certificate |
| `POST` | `/api/v1/venafi/certificates/{guid}/revoke` | Revoke a certificate |

### AWS ACM Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/acm/certificates` | List ACM certificates |
| `POST` | `/api/v1/acm/certificates` | Request a new certificate |
| `GET` | `/api/v1/acm/certificates/{arn}/detail` | Describe a certificate |
| `GET` | `/api/v1/acm/certificates/{arn}/validation-records` | Get DNS/email validation records |
| `POST` | `/api/v1/acm/certificates/{arn}/export` | Export certificate + private key (requires passphrase) |
| `DELETE` | `/api/v1/acm/certificates/{arn}` | Delete a certificate |
| `POST` | `/api/v1/acm/route53/sync` | Sync DNS validation records to Route53 |

### Vault PKI Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vault-pki/certificates` | List PKI certificates |
| `POST` | `/api/v1/vault-pki/certificates` | Issue a new certificate |
| `GET` | `/api/v1/vault-pki/certificates/{serial}` | Read a certificate by serial |
| `POST` | `/api/v1/vault-pki/sign` | Sign a CSR |

### Authentication Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/token` | Exchange JWT for short-lived API key |
| `POST` | `/api/v1/auth/token/refresh` | Refresh API key |
| `POST` | `/api/v1/auth/token/revoke` | Revoke API key |

## Architecture

```
certmesh/
  cli.py               -- Click CLI (entry point: certmesh.cli:cli)
  settings.py           -- Layered config: defaults -> YAML -> env vars
  credentials.py        -- Env-first, Vault-fallback secret resolution
  certificate_utils.py  -- Key gen, CSR, PKCS#12, bundle assembly, persistence
  circuit_breaker.py    -- Thread-safe CLOSED/OPEN/HALF_OPEN state machine
  renewal.py            -- Automatic certificate renewal engine
  exceptions.py         -- Full exception hierarchy
  providers/
    digicert_client.py  -- DigiCert CertCentral API v2 (spec-validated)
    venafi_client.py    -- Venafi TPP v23/v25.3 (OAuth2 + LDAP, spec-validated)
    acm_client.py       -- AWS ACM + ACM-PCA (boto3, spec-validated)
    letsencrypt_client.py -- Let's Encrypt / ACME (RFC 8555)
  backends/
    vault_client.py     -- Vault auth + KV v1/v2 + PKI engine
    secrets_manager_client.py -- AWS Secrets Manager
    route53_client.py   -- Route53 DNS record management
  api/
    app.py              -- FastAPI application factory
    auth.py             -- OAuth2 JWT Bearer validation (RS256 algorithm restriction)
    apikeys.py          -- Thread-safe API key exchange store
    rate_limiter.py     -- Configurable rate limiting (SlowAPI, RFC 7231)
    compression.py      -- GZip compression middleware
    routes/             -- REST API endpoints
    metrics.py          -- Prometheus metrics
```

### Certificate Output

Issued certificates can be persisted to:

- **Filesystem** -- PEM files with private keys written mode `0600`
- **Vault KV v1/v2** -- certificate material stored as a KV secret (versioned or unversioned)
- **AWS Secrets Manager** -- certificate bundle stored as a JSON secret
- **Multiple destinations** -- any combination of the above

Configured per-provider via `output.destination` (list or legacy string: `filesystem`, `vault`, `secrets_manager`, or `both`).

## Development

```bash
# Clone and install
git clone https://github.com/SCGIS-Wales/certmesh.git
cd certmesh
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v --cov=certmesh

# Lint and format
ruff check src/ tests/
ruff format src/ tests/
```

## Docker

```bash
docker build -t certmesh .
docker run --rm certmesh --help

# Run the REST API
docker run -p 8000:8000 -e CM_CONFIG_FILE=/app/config.yaml certmesh
```

## Helm Chart

```bash
helm install certmesh helm/certmesh \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/certmesh
```

See [`helm/certmesh/values.yaml`](helm/certmesh/values.yaml) for all configuration options. Helm values are validated at install time via [`values.schema.json`](helm/certmesh/values.schema.json).

### AWS IAM Permissions

When running on AWS (EKS with IRSA, EC2, or Lambda), the IAM role needs the following permissions depending on which features are enabled:

**AWS Certificate Manager (ACM)**

```json
{
  "Effect": "Allow",
  "Action": [
    "acm:RequestCertificate",
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "acm:DeleteCertificate",
    "acm:RenewCertificate",
    "acm:ExportCertificate",
    "acm:GetCertificate",
    "acm:ListTagsForCertificate",
    "acm:AddTagsToCertificate"
  ],
  "Resource": "*"
}
```

**AWS ACM Private CA (ACM-PCA)**

```json
{
  "Effect": "Allow",
  "Action": [
    "acm-pca:IssueCertificate",
    "acm-pca:GetCertificate",
    "acm-pca:RevokeCertificate",
    "acm-pca:ListCertificateAuthorities",
    "acm-pca:DescribeCertificateAuthority",
    "acm-pca:GetCertificateAuthorityCertificate"
  ],
  "Resource": "*"
}
```

**Route53 (ACM DNS Validation)**

```json
{
  "Effect": "Allow",
  "Action": [
    "route53:ChangeResourceRecordSets",
    "route53:ListHostedZones",
    "route53:GetHostedZone",
    "route53:ListResourceRecordSets"
  ],
  "Resource": [
    "arn:aws:route53:::hostedzone/*"
  ]
}
```

**AWS Secrets Manager (Certificate Storage)**

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
    "secretsmanager:UpdateSecret",
    "secretsmanager:TagResource"
  ],
  "Resource": "arn:aws:secretsmanager:*:*:secret:certmesh/*"
}
```

**Vault AWS IAM Auth (STS)**

```json
{
  "Effect": "Allow",
  "Action": [
    "sts:AssumeRole",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

> **Tip:** For EKS deployments with IRSA, create a single IAM role with only the permissions you need, then reference it in your Helm values: `serviceAccount.annotations."eks.amazonaws.com/role-arn"`.

### Test Suite

- **800+ tests** across the test suite (including provider route handler tests)
- **87%+ coverage** (80% minimum enforced in CI)
- Tests use `pytest`, `pytest-mock`, `responses`, `moto`, and `freezegun`

### CI

GitHub Actions runs on every push and PR:

| Job | Matrix | Description |
|-----|--------|-------------|
| **lint** | Python 3.10 - 3.14 | `ruff check` + `ruff format --check` |
| **test** | Python 3.10 - 3.14 | `pytest` with coverage |
| **build** | Python 3.14 | `python -m build` + `twine check` |
| **Integration - Helm + kind** | - | Full K8s deployment with Vault TLS, health probes, and capacity tests |
| **Integration - Vault PKI** | - | Vault PKI engine issue/sign/revoke against real Vault |
| **Integration - Venafi (VCert)** | - | VCert SDK tests against mock TPP |
| **CodeQL** | - | GitHub security analysis |
| **auto-tag** | - | Auto-version bump and tag on merge to main |
| **publish-pypi** | - | Publish to PyPI via trusted publisher |

## License

MIT -- see [LICENSE](LICENSE) for details.
