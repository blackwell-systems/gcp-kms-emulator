# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
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
