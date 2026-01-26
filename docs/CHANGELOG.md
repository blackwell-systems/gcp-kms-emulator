# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-26

### Added
- **Initial Release**: Core KMS functionality with dual protocol support
- **Key Management**:
  - CreateKeyRing: Create keyrings
  - GetKeyRing: Retrieve keyring metadata
  - ListKeyRings: List all keyrings
  - CreateCryptoKey: Create crypto keys with automatic version creation
  - GetCryptoKey: Retrieve key metadata
- **Encryption Operations**:
  - Encrypt: AES-256-GCM symmetric encryption
  - Decrypt: AES-256-GCM symmetric decryption
  - Automatic nonce generation
  - Key version-aware decryption (tries all enabled versions)
- **Dual Protocol Support**:
  - Three server variants: `server` (gRPC), `server-rest` (REST), `server-dual` (both)
  - Native gRPC for SDK compatibility
  - REST/HTTP API for curl and scripts
  - Custom HTTP gateway with GCP-compatible endpoints
- **Infrastructure**:
  - Docker multi-variant builds
  - Makefile targets for all variants
  - In-memory storage with sync.RWMutex
  - Thread-safe concurrent operations
- **Documentation**:
  - Complete README with Quick Start
  - SDK integration examples (Go)
  - REST API examples (curl)
  - Docker usage and CI/CD examples

### Technical Details
- Real cryptographic operations (not mocked)
- AES-256-GCM with authenticated encryption
- Automatic primary key version creation
- Version-aware decryption (any enabled version works)
- Binary sizes: gRPC 17MB, REST/Dual 19MB

### Limitations
- Only symmetric encryption (ENCRYPT_DECRYPT purpose)
- No key versioning operations yet
- No asymmetric operations (Sign, Verify)
- No MAC operations
- No key import/export
- CRC32C checksums not implemented

[Unreleased]: https://github.com/blackwell-systems/gcp-kms-emulator/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blackwell-systems/gcp-kms-emulator/releases/tag/v0.1.0
