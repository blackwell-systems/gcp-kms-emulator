# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-04-03

### Added
- **Full asymmetric crypto**: `AsymmetricSign`, `AsymmetricDecrypt`, `GetPublicKey` with real RSA (2048/3072/4096) and ECDSA (P-256, P-384) key generation and operations
- **MAC operations**: `MacSign`, `MacVerify` using HMAC-SHA256 with constant-time comparison
- **Raw encryption**: `RawEncrypt`, `RawDecrypt` using AES-256-GCM without envelope wrapping
- **Random bytes**: `GenerateRandomBytes` via `crypto/rand` (1–1024 bytes)
- **Import jobs**: `CreateImportJob`, `GetImportJob`, `ListImportJobs`, `ImportCryptoKeyVersion` with RSA-2048 OAEP wrapping key generation and key material unwrapping
- **RestoreCryptoKeyVersion**: Restores `DESTROY_SCHEDULED` versions to `DISABLED` state
- Key material generation at version creation time based on `CryptoKeyVersionAlgorithm`
- 8 new IAM permission mappings for all new operations
- Integration tests for all new operations (asymmetric roundtrip, MAC sign/verify, raw encrypt/decrypt, import lifecycle)

### Changed
- KMS API coverage: **17 → 29 of 30 methods** implemented (97% — only `Decapsulate` KEM stub remains)
- Key versions now generate appropriate crypto material (RSA keypairs, ECDSA keypairs, HMAC keys, AES keys) based on algorithm

## [0.5.0] - 2026-04-03

### Changed
- **REST gateway migrated from hand-rolled HTTP to grpc-gateway v2** — HTTP handlers are now auto-generated from the KMS proto definitions, ensuring full API compatibility with real GCP
- **Refactor**: Replaced `strings.Contains` error matching with typed storage errors (`ErrNotFound`, `ErrAlreadyExists`, `ErrFailedPrecondition`)
- **Refactor**: Added `requireField()` and `storageErr()` helpers, reducing boilerplate in all 17 RPC methods
- Fixed root package declaration (`package main` → `package gcp_kms_emulator`) for library importability

### Added
- `Register()` composition hook for unified `gcp-emulator`
- `NewGatewayHandler()` for mounting KMS REST gateway in unified HTTP server
- `gateway.Handler()` method for embedding in parent HTTP multiplexer
- Env vars and IAM mode in `--help` output for all 3 server binaries
- IAM mode shown in startup banner
- gRPC request logging at debug level
- `/healthz`, `/readyz`, `/health` endpoints on REST gateway
- `jsonErrorHandler` returns clean 400 for malformed JSON bodies
- `buf.gen.yaml` for reproducible grpc-gateway stub generation
- `authz` package documentation

### Fixed
- REST gateway now returns correct HTTP status codes: NotFound→404, AlreadyExists→409, InvalidArgument→400, FailedPrecondition→400 (previously all mapped to 500)
- REST gateway now returns structured GCP-format error responses (`{"code":N,"message":"..."}`)
- Malformed JSON request bodies now return 400 instead of being silently accepted
- `IAM_HOST` → `IAM_EMULATOR_HOST` in README (matches actual env var)
- `Register()` no longer calls `reflection.Register`, preventing fatal duplicate registration when composing multiple emulators

### Removed
- Hand-rolled HTTP gateway (560 lines, replaced by ~80 lines of grpc-gateway wiring)
- `NewGatewayHandler()` for mounting KMS REST gateway in unified HTTP server
- `gateway.Handler()` method for embedding in parent HTTP multiplexer

## [0.3.0] - 2026-01-28

### Changed
- **Component Identification**: Pass "gcp-kms-emulator" to auth client
  - Enables trace analysis tools to identify calling service
  - Authorization traces now show both policy engine and requesting component
- Upgraded to gcp-emulator-auth v0.3.0 (requires component parameter)
- Enhanced README with hermetic seal narrative
  - Explains pre-flight IAM enforcement vs post-hoc observation
  - Clarifies control plane/data plane architecture
  - Positions KMS as data plane in Blackwell ecosystem

## [0.2.0] - 2026-01-26

### Added
- **IAM Integration**: Optional permission checks with GCP IAM Emulator
  - Three authorization modes: `off` (legacy), `permissive` (fail-open), `strict` (fail-closed)
  - Environment variables: `IAM_MODE` and `IAM_HOST`
  - Principal injection via `x-emulator-principal` (gRPC) and `X-Emulator-Principal` (HTTP)
  - Complete permission mapping for all 8 KMS operations
  - Integration with `gcp-emulator-auth` shared library
  - Resource normalization for key rings, crypto keys, and key versions
  - Integration tests covering all three IAM modes
- **Documentation**: IAM Integration section in README
  - Configuration guide
  - Usage examples for all three modes
  - Permission mapping table
  - Mode comparison table

### Changed
- `NewServer()` now returns `(*Server, error)` to handle IAM client initialization errors
- Server struct includes `iamClient` and `iamMode` fields
- All operations check permissions before storage calls (when IAM enabled)
- Backward compatible: IAM disabled by default (`IAM_MODE=off`)

### Fixed
- Go version compatibility in CI (fixed to 1.24)
- golangci-lint configuration issues
- gofmt formatting in storage.go

### Technical Details
- Uses `gcp-emulator-auth v0.1.0`
- Permission checks placed after validation, before storage operations
- Non-breaking change: existing deployments unaffected
- Fail-open vs fail-closed behavior configurable per environment

## [0.1.0] - 2026-01-20

### Added
- Initial release
- Core KMS API implementation:
  - CreateKeyRing
  - GetKeyRing
  - ListKeyRings
  - CreateCryptoKey
  - GetCryptoKey
  - Encrypt
  - Decrypt
  - UpdateCryptoKeyPrimaryVersion
- In-memory storage with thread-safe operations
- gRPC server implementation
- Simple XOR-based encryption (for testing only)
- Docker container support
- Comprehensive documentation (README, API Reference)
- Integration tests with real GCP SDK client
- CI/CD with multi-platform testing

### Features
- Full key lifecycle management
- Crypto key version management
- Primary version rotation
- Resource hierarchy (projects/locations/keyRings/cryptoKeys)
- Automatic key version creation

### Security
- Runs as non-root user in Docker
- No authentication by design (testing-only emulator)
- XOR encryption (not cryptographically secure - for testing only)

[Unreleased]: https://github.com/blackwell-systems/gcp-kms-emulator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/blackwell-systems/gcp-kms-emulator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/blackwell-systems/gcp-kms-emulator/releases/tag/v0.1.0
