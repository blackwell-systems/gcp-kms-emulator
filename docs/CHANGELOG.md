# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-26

### Added
- **Initial Release**: Complete key management and lifecycle support with dual protocol
- **Key Management**:
  - CreateKeyRing: Create keyrings
  - GetKeyRing: Retrieve keyring metadata
  - ListKeyRings: List all keyrings
  - CreateCryptoKey: Create crypto keys with automatic version creation
  - GetCryptoKey: Retrieve key metadata
  - ListCryptoKeys: List all crypto keys in a keyring
  - UpdateCryptoKey: Update key metadata (labels)
- **Key Versioning**:
  - CreateCryptoKeyVersion: Create new versions for key rotation
  - GetCryptoKeyVersion: Get specific version details
  - ListCryptoKeyVersions: List all versions of a key
  - UpdateCryptoKeyPrimaryVersion: Switch active encryption key
  - UpdateCryptoKeyVersion: Update version state (enable/disable)
  - DestroyCryptoKeyVersion: Schedule version for destruction
- **Encryption Operations**:
  - Encrypt: AES-256-GCM symmetric encryption
  - Decrypt: AES-256-GCM symmetric decryption
  - Automatic nonce generation
  - Key version-aware decryption (tries all enabled versions)
- **Version State Management**:
  - State transitions: PENDING_GENERATION → ENABLED → DISABLED → DESTROY_SCHEDULED → DESTROYED
  - Enable/disable versions via UpdateCryptoKeyVersion
  - Prevent encryption with disabled/destroyed versions
  - Bidirectional ENABLED ↔ DISABLED transitions
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
- Key versions auto-increment (1, 2, 3, ...)
- Each version has independent AES-256 symmetric key
- Primary version used for encryption
- UpdatePrimaryVersion validates target version is ENABLED
- Binary sizes: gRPC 17MB, REST/Dual 19MB

### Limitations
- Only symmetric encryption (ENCRYPT_DECRYPT purpose)
- No key restoration (RestoreCryptoKeyVersion)
- No asymmetric operations (AsymmetricSign, AsymmetricDecrypt, GetPublicKey)
- No MAC operations (MacSign, MacVerify)
- No key import/export (ImportCryptoKeyVersion, CreateImportJob)
- No raw encryption operations (RawEncrypt, RawDecrypt)
- No random byte generation (GenerateRandomBytes)
- CRC32C checksums not implemented

**Coverage:** 14 of ~26 methods (54%) - complete key management + lifecycle

[Unreleased]: https://github.com/blackwell-systems/gcp-kms-emulator/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/blackwell-systems/gcp-kms-emulator/releases/tag/v0.1.0
