# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/SCGIS-Wales/certmesh/releases/tag/v3.0.0
