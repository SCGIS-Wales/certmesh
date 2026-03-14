# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]



## [3.0.6] - 2026-03-14

### Added
- **JWT → API key exchange**: Exchange valid JWT for short-lived API key (default 15min, max 8h) via `POST /api/v1/auth/token`. Expiry signaling via `X-CertMesh-Key-Expiring` header prompts programmatic clients to refresh ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **Rate limiting**: Configurable throttling returning HTTP 429 with `Retry-After` header. Default 1000 req/min (high — protection not restriction) ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **TLS 1.3 + 1.2 server config**: Configurable cipher suites with Mozilla Intermediate defaults, HTTP keep-alive (75s), session ticket control ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **GZip compression**: Enabled by default for responses ≥ 500 bytes, configurable level ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **RFC 7807 error responses**: All errors now return consistent JSON with `error`, `status`, `detail`, `request_id` fields and correct HTTP status codes (21 exception types mapped) ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **Auth audit logging**: All authentication/authorization failures logged with structured context (subject, scopes, issuer, client IP) ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **Capacity/performance integration test**: Rate limiting 429 verification, concurrent load testing, API key store capacity, response time baseline ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))
- **CI fix**: Set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to resolve Node.js 20 deprecation warning ([#6](https://github.com/SCGIS-Wales/certmesh/pull/6))

## [3.0.5] - 2026-03-14

### Fixed
- **Helm kubeVersion**: Updated from `>=1.28.0` to `>=1.34.0` per project requirements; appVersion updated to `3.2.0` ([#5](https://github.com/SCGIS-Wales/certmesh/pull/5))
- **k3d integration test**: Fixed silent pass — removed `continue-on-error: true` and `|| true` that allowed the entire job to succeed even when helm install or deployment failed. Added Kubernetes version verification step and deployment validation with error state detection ([#5](https://github.com/SCGIS-Wales/certmesh/pull/5))
- **All integration tests**: Added `set -e`, `--tb=long` for detailed tracebacks, readiness wait loops that fail on timeout (instead of silently proceeding), and success confirmation messages ([#5](https://github.com/SCGIS-Wales/certmesh/pull/5))
- **Error handling test coverage**: Added `TestVaultPKIErrorHandling` (unauthorized domain, nonexistent role, invalid serial, nonexistent cert), `TestACMErrorHandling` (nonexistent delete, invalid domain, error response structure), VCert PEM validation and empty CN tests ([#5](https://github.com/SCGIS-Wales/certmesh/pull/5))

## [3.0.0] - 2026-03-13

### Added
- Multi-provider TLS certificate lifecycle management (DigiCert, Venafi TPP, Vault PKI, AWS ACM)
- Full CLI with `certmesh` entry point and Click command groups
- Layered configuration: built-in defaults, YAML file, `CM_*` environment variables
- Credential resolution with env-first, Vault-fallback strategy
- Circuit breaker and exponential-backoff retry on all HTTP calls
- Typed dataclass models for all API responses
- Python 3.10, 3.11, 3.12, 3.13, and 3.14 support
- 400 tests with 87%+ coverage

### Security
- Atomic file writes for private keys (mode 0600)
- RSA_1024 removed from valid key algorithms
- Request timeouts enforced on all HTTP calls

[Unreleased]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.6...HEAD
[3.0.6]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.5...v3.0.6
[3.0.5]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.0...v3.0.5
[3.0.0]: https://github.com/SCGIS-Wales/certmesh/releases/tag/v3.0.0
