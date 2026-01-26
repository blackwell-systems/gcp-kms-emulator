# Features

## Complete Key Management

The KMS emulator provides complete key management and lifecycle operations with real cryptographic operations.

### Key Management
- **CreateKeyRing**: Create logical groupings for crypto keys
- **GetKeyRing**: Retrieve keyring metadata
- **ListKeyRings**: List all keyrings in a location
- **CreateCryptoKey**: Create crypto keys with automatic version creation
- **GetCryptoKey**: Retrieve key metadata
- **ListCryptoKeys**: List all keys in a keyring
- **UpdateCryptoKey**: Update key metadata (labels)

### Key Versioning
- **CreateCryptoKeyVersion**: Create new versions for key rotation
- **GetCryptoKeyVersion**: Get specific version details
- **ListCryptoKeyVersions**: List all versions of a key
- **UpdateCryptoKeyPrimaryVersion**: Switch active encryption key
- **UpdateCryptoKeyVersion**: Update version state (enable/disable)
- **DestroyCryptoKeyVersion**: Schedule version for destruction

### Encryption Operations
- **Encrypt**: AES-256-GCM symmetric encryption
- **Decrypt**: AES-256-GCM symmetric decryption with version-aware key selection

## IAM Integration

Optional permission checks with GCP IAM Emulator for testing authorization workflows.

### Authorization Modes

**Off (default):**
- No permission checks
- All requests succeed
- Legacy emulator behavior
- Use for simple testing

**Permissive (fail-open):**
- Check permissions when IAM emulator is available
- Allow requests if IAM emulator is unreachable
- Good for development where IAM might not be running
- Set with `IAM_MODE=permissive`

**Strict (fail-closed):**
- Require all permission checks to succeed
- Deny requests if IAM emulator is unreachable
- Recommended for CI/CD pipelines
- Set with `IAM_MODE=strict`

### Principal Injection

Specify the calling identity for permission checks:

**gRPC:**
```go
ctx := metadata.AppendToOutgoingContext(ctx, "x-emulator-principal", "user:alice@example.com")
```

**HTTP:**
```bash
curl -H "X-Emulator-Principal: user:alice@example.com" ...
```

### Permission Mapping

All operations map to real GCP IAM permissions:

| Operation | Permission | Resource Target |
|-----------|-----------|----------------|
| CreateKeyRing | `cloudkms.keyRings.create` | Parent location |
| GetKeyRing | `cloudkms.keyRings.get` | KeyRing |
| ListKeyRings | `cloudkms.keyRings.list` | Parent location |
| CreateCryptoKey | `cloudkms.cryptoKeys.create` | Parent keyring |
| GetCryptoKey | `cloudkms.cryptoKeys.get` | CryptoKey |
| UpdateCryptoKey | `cloudkms.cryptoKeys.update` | CryptoKey |
| ListCryptoKeys | `cloudkms.cryptoKeys.list` | Parent keyring |
| Encrypt | `cloudkms.cryptoKeys.encrypt` | CryptoKey |
| Decrypt | `cloudkms.cryptoKeys.decrypt` | CryptoKey |
| CreateCryptoKeyVersion | `cloudkms.cryptoKeyVersions.create` | Parent cryptokey |
| GetCryptoKeyVersion | `cloudkms.cryptoKeyVersions.get` | CryptoKeyVersion |
| UpdateCryptoKeyVersion | `cloudkms.cryptoKeyVersions.update` | CryptoKeyVersion |
| ListCryptoKeyVersions | `cloudkms.cryptoKeyVersions.list` | Parent cryptokey |
| UpdateCryptoKeyPrimaryVersion | `cloudkms.cryptoKeys.update` | CryptoKey |
| DestroyCryptoKeyVersion | `cloudkms.cryptoKeyVersions.destroy` | CryptoKeyVersion |

## Dual Protocol Support

Three server variants for different use cases:

**server (gRPC only):**
- Native gRPC for SDK compatibility
- Smallest binary size (17MB)
- Best performance
- Port: 9090 (default)

**server-rest (REST only):**
- HTTP/JSON gateway
- Test from any language or terminal
- curl-friendly
- Ports: 9090 (gRPC backend), 8080 (HTTP)

**server-dual (Both protocols):**
- Maximum flexibility
- Run both protocols simultaneously
- Ports: 9090 (gRPC), 8080 (HTTP)

## Real Cryptographic Operations

Not mocked - uses actual cryptography:

- **AES-256-GCM**: Authenticated encryption with associated data
- **Automatic nonce generation**: Unique per encryption
- **Key versioning**: Each version has independent AES-256 key
- **Version-aware decryption**: Tries all enabled versions automatically

## Thread-Safe Operations

- In-memory storage with `sync.RWMutex`
- Concurrent requests handled safely
- Read operations don't block each other
- Write operations properly synchronized

## Docker Support

Pre-built multi-variant images:

```bash
# gRPC only (default)
docker build --build-arg VARIANT=grpc -t kms:grpc .

# REST only
docker build --build-arg VARIANT=rest -t kms:rest .

# Both protocols
docker build --build-arg VARIANT=dual -t kms:dual .
```

## CI/CD Integration

Works in GitHub Actions, GitLab CI, and other CI/CD systems:

```yaml
services:
  kms:
    image: gcp-kms-emulator:dual
    ports:
      - "9090:9090"
      - "8080:8080"
    environment:
      IAM_MODE: strict  # Fail-closed for CI
      IAM_HOST: iam:8080
```

## Version State Management

Complete lifecycle with proper state transitions:

```
PENDING_GENERATION → ENABLED → DISABLED → DESTROY_SCHEDULED → DESTROYED
                        ↑          ↓
                        └──────────┘
```

- **ENABLED**: Active, can encrypt and decrypt
- **DISABLED**: Inactive, can only decrypt (not encrypt)
- **DESTROY_SCHEDULED**: Pending destruction, can only decrypt
- **DESTROYED**: Permanently destroyed, cannot decrypt

Bidirectional transitions between ENABLED and DISABLED supported.

## Not Yet Implemented

- Key restoration (RestoreCryptoKeyVersion)
- Asymmetric operations (AsymmetricSign, AsymmetricDecrypt, GetPublicKey)
- MAC operations (MacSign, MacVerify)
- Key import/export (ImportCryptoKeyVersion, CreateImportJob)
- Raw encryption operations (RawEncrypt, RawDecrypt)
- Random byte generation (GenerateRandomBytes)
- CRC32C checksums

**Current coverage:** 14 of ~26 methods (54%)

Covers all essential key management and lifecycle operations.
