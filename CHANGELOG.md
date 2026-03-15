# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]




## [3.0.15] - 2026-03-15

### Fixed
- Comprehensive security and reliability audit addressing 11 issues found across the API layer, providers, backends, Helm chart, and CI pipeline. ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **X-Request-ID log injection** — Sanitize incoming header against `^[a-zA-Z0-9\-_.]{1,128}$` regex; generate fresh UUID if invalid ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **JWT error detail leakage** — Replace raw PyJWT exception messages and key IDs in HTTP 401 responses with generic messages (details remain in server logs) ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **Vault secret field enumeration** — Remove `Available fields: [...]` from error messages returned to clients; log at debug level only ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **Cert PEM file permissions** — Write certificate PEM via `os.open()` with explicit `0o644` mode instead of `Path.write_text()` (which inherits umask) ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **Vault PKI schema validation** — Add Pydantic `Field` constraints: `common_name` max 253 chars, TTL format pattern, serial_number bounds, alt_names/ip_sans list limits ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **NetworkPolicy open ingress** — Default config now restricts ingress to same-namespace pods via `podSelector: {}` instead of allowing all sources when no CIDRs configured ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **Init script private key on disk** — Write Vault TLS response to memory-backed volume (`${TLS_DIR}/.response.json`) instead of disk-backed `/tmp` ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **Venafi session leaks** — All 5 route handlers now use `try/finally: session.close()` to prevent connection pool exhaustion ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **LocalStack CI pinning** — Pin from `:latest` to `:3.8` for reproducible integration tests ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **kind node image** — Fix from nonexistent `v1.34.3` to `v1.33.0` ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **CLI `--config` validation** — Now uses `click.Path(exists=True)` consistent with `--env-file` ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))
- **CliRunner stderr** — Add `mix_stderr=False` to fix `result.stderr` access in Click test runner ([#16](https://github.com/SCGIS-Wales/certmesh/pull/16))

## [3.0.14] - 2026-03-15

### Changed
- Fix 4 ruff SIM114 violations — combine duplicate `if` branches returning the same value in `update_changelog.py` ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Simplify changelog category mapping: redundant `elif` chains collapsed to single `else` ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Update README to reflect current state: ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Test count 790+ → 800+ (809 tests) ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Add renewal engine, rate limiting, API key exchange, GZip compression features ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Add Helm `values.schema.json` input validation ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))
- Add `renewal.py`, `apikeys.py`, `rate_limiter.py`, `compression.py` to architecture section ([#15](https://github.com/SCGIS-Wales/certmesh/pull/15))

## [3.0.13] - 2026-03-15

### Fixed
- Comprehensive pass addressing 27 issues across security, reliability, and code quality — organized by severity from the code review findings. ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Circuit breaker TOCTOU race** — Added `probe_in_flight` flag to enforce single-probe semantics in HALF_OPEN state ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Renewal engine dead code** — Replaced stub `_check_provider()` with working ACM dispatch and full `_check_acm()` implementation ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **DigiCert session leak** — All 7 public functions wrapped with `try/finally session.close()` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Venafi session leak on auth failure** — Close session in except block before re-raising ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **APIKeyStore thread safety** — Added `threading.Lock` with guarded access on all 6 public methods ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **STS health cache race** — Double-check locking pattern with module-level `threading.Lock` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Venafi missing retry type** — Added `requests.exceptions.HTTPError` to retryable exceptions ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **DigiCert polling drift** — `order_and_await_certificate` uses `time.monotonic()` deadline ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Venafi polling drift** — `_poll_certificate_ready` uses monotonic deadline ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **ACM polling drift** — `wait_for_issuance` uses monotonic deadline ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Chain PEM file permissions** — `os.open()` with `0o600` instead of `write_text()` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **CORS wildcards** — Restricted to specific methods and headers via env vars ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **JWKS algorithm restriction** — Skip keys with `alg` != RS256 ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Route53 misleading region param** — Removed from `delete_validation_records()` (global service) ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Let's Encrypt RSA key size** — 2048 → 4096 ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Helm input validation** — Created `values.schema.json` with type constraints, enums, regex patterns, min/max ranges ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Venafi parse deduplication** — Extracted `_parse_certificate_summary()` helper ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Settings venafi validation** — Added vault_path_template and sm_secret_name_template checks ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Settings digicert double-normalize** — Removed redundant `normalize_destinations()` call ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **boto3 client caching** — `@functools.lru_cache(maxsize=16)` for ACM/PCA clients ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **CertificateBundle immutability** — `@dataclass(slots=True, frozen=True)` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **Renewal "week" unit** — Added to `_UNIT_SECONDS` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- **config_loader deprecation warning** — `warnings.warn()` with `DeprecationWarning` ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))
- Updated ACM tests to mock `time.monotonic` for deadline-based polling ([#14](https://github.com/SCGIS-Wales/certmesh/pull/14))

### Changed
- **README**: Add full REST API endpoint reference (DigiCert, Venafi, ACM, Vault PKI, Auth); update architecture section with spec-validated providers; add "Spec-compliant" feature bullet; update test count to 790+; update CI table with integration tests




## [3.0.9] - 2026-03-14

### Fixed
- **Venafi TPP**: Full API spec compliance audit and fixes for TPP v23/v25.3. Removes incorrect `grant_type` from OAuth, fixes SubjectAltNames `TypeName`, workflow ticket endpoint/payload, revocation field name, and adds LDAP deprecation warning. Rewrites all 5 Venafi route handlers from stubs to full implementations. ([#10](https://github.com/SCGIS-Wales/certmesh/pull/10))
- **AWS ACM**: Fixes 3 critical route handler bugs where every endpoint would crash at runtime (`request_certificate` called `.get()` on string ARN, `export_certificate` used wrong function signature, `get_validation_records` treated dataclass as dict). Adds `describe_certificate` and `delete_certificate` endpoints, new `ACMExportRequest` schema with required passphrase, and updates `ExportCertificate` docs for public cert export support (June 2025+). ([#10](https://github.com/SCGIS-Wales/certmesh/pull/10))
- **Tests**: 790 passed (29 new route handler tests across both providers) ([#10](https://github.com/SCGIS-Wales/certmesh/pull/10))

## [3.0.8] - 2026-03-14

### Fixed
- **Fix 5 critical runtime bugs** in `routes/digicert.py` — every route handler called `_build_session(cfg)` with wrong signatures, causing `TypeError` at runtime ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Align order body with CertCentral API v2 spec**: replace legacy `validity_years` with `order_validity` object, add `skip_approval`, `payment_method`, `dcv_method` ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Fix revocation compliance**: field `"reason"` → `"revocation_reason"`, remove invalid `ca_compromise` reason, fix `affiliation_changed` → `affiliation_change` ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Fix rate limit handling**: DigiCert doesn't return `Retry-After` headers — use fixed 60s backoff with documented limits (1000 req/3min, 100 req/5s) ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Fix auth error message**: API keys never expire — remove misleading "not expired" text ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Add comprehensive inline documentation** with spec references throughout all public functions ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))
- **Add new route handler tests** (`test_digicert_routes.py`) verifying correct function signatures ([#9](https://github.com/SCGIS-Wales/certmesh/pull/9))

## [3.0.7] - 2026-03-14

### Fixed
- **Refactor init container**: Move 100-line inline shell script from `deployment.yaml` into a ConfigMap-mounted `vault-tls-init.sh`. Cleaner, testable, runtime-configurable via env vars. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Vault 1.21**: Update from 1.15 to latest stable (1.21.4) in both init container and CI. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Token TTL fix**: Parse numeric TTL from `vault token lookup` JSON — now displays `3600s (1h 0m)` instead of `unknown`. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Performance tests in-cluster**: Move capacity/perf tests into the Helm+kind job so they run against the actual deployed pod. Tests: sequential throughput (100 req), concurrent (50 parallel), readiness, response headers. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Resilient probes**: Startup 90s max, liveness 30s restart threshold, readiness 15s unready with `successThreshold: 2` anti-flap. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **K8s 1.34 per-container restart policy**: Init container uses `restartPolicy: Never` — if TLS init fails, pod fails immediately (no CrashLoopBackOff). ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Gunicorn auto-detect workers**: `"auto" = 2 x CPU cores + 1` (respects cgroup quota). Overridable via `api.workers` in values.yaml. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Vault client warning fix**: Pass `vault.enabled=true` in CI, add KV v2 engine + policy, improve error logging with context. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Clean values.yaml**: Remove duplicate sections from bad merge, format TLS ciphers as YAML array, add `vaultImage` setting. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))
- **Fix CI**: Remove duplicate `integration-capacity` job, add `fix/**` to push triggers. ([#8](https://github.com/SCGIS-Wales/certmesh/pull/8))

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

[Unreleased]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.15...HEAD
[3.0.15]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.14...v3.0.15
[3.0.14]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.13...v3.0.14
[3.0.13]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.9...v3.0.13
[3.0.9]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.8...v3.0.9
[3.0.8]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.7...v3.0.8
[3.0.7]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.6...v3.0.7
[3.0.6]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.5...v3.0.6
[3.0.5]: https://github.com/SCGIS-Wales/certmesh/compare/v3.0.0...v3.0.5
[3.0.0]: https://github.com/SCGIS-Wales/certmesh/releases/tag/v3.0.0
