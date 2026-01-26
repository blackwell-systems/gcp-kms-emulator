# GCP KMS Emulator

[![Blackwell Systems](https://raw.githubusercontent.com/blackwell-systems/blackwell-docs-theme/main/badge-trademark.svg)](https://github.com/blackwell-systems)
[![Go Reference](https://pkg.go.dev/badge/github.com/blackwell-systems/gcp-kms-emulator.svg)](https://pkg.go.dev/github.com/blackwell-systems/gcp-kms-emulator)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> The reference local implementation of the Google Cloud KMS API for development and CI

A production-grade implementation providing complete, behaviorally-accurate KMS semantics for local development and CI/CD. **Dual protocol support**: Native gRPC + REST/HTTP for maximum flexibility. No GCP credentials or network connectivity required.

## Features

- **Dual Protocol Support** - Native gRPC + REST/HTTP APIs (choose what fits your workflow)
- **SDK Compatible** - Drop-in replacement for official `cloud.google.com/go/kms` (gRPC)
- **curl Friendly** - Full REST API with JSON, test from any language or terminal
- **Real Encryption** - AES-256-GCM for symmetric encryption (not mocked)
- **IAM Integration** - Optional permission checks with GCP IAM Emulator
- **No GCP Credentials** - Works entirely offline without authentication
- **Fast & Lightweight** - In-memory storage, starts in milliseconds
- **Docker Support** - Pre-built containers (gRPC-only, REST-only, or dual)
- **Thread-Safe** - Concurrent access with proper synchronization

## Supported Operations

### Key Management
- `CreateKeyRing` - Create new keyrings
- `GetKeyRing` - Retrieve keyring metadata
- `ListKeyRings` - List all keyrings
- `CreateCryptoKey` - Create encryption/decryption keys
- `GetCryptoKey` - Retrieve key metadata
- `ListCryptoKeys` - List all keys in a keyring
- `UpdateCryptoKey` - Update key metadata (labels)

### Key Versioning
- `CreateCryptoKeyVersion` - Create new key versions for rotation
- `GetCryptoKeyVersion` - Get specific version details
- `ListCryptoKeyVersions` - List all versions of a key
- `UpdateCryptoKeyPrimaryVersion` - Switch to a different key version
- `UpdateCryptoKeyVersion` - Update version state (enable/disable)
- `DestroyCryptoKeyVersion` - Schedule version for destruction

### Encryption
- `Encrypt` - Encrypt data with a crypto key (AES-256-GCM)
- `Decrypt` - Decrypt data with a crypto key (works with any enabled version)

### Version State Transitions
```
PENDING_GENERATION → ENABLED → DISABLED → DESTROY_SCHEDULED → DESTROYED
                        ↑          ↓
                        └──────────┘
```

### Not Yet Implemented
- Key lifecycle (RestoreCryptoKeyVersion)
- Asymmetric operations (AsymmetricSign, AsymmetricDecrypt, GetPublicKey)
- MAC operations (MacSign, MacVerify)
- Import/Export (ImportCryptoKeyVersion, CreateImportJob, etc.)
- Raw operations (RawEncrypt, RawDecrypt, Decapsulate)
- Random generation (GenerateRandomBytes)

**Current coverage:** 14 of ~26 methods (54%) - complete key management + lifecycle

## Quick Start

### Choose Your Protocol

**Three server variants available:**

| Variant | Protocols | Use Case | Install Command |
|---------|-----------|----------|-----------------|
| `server` | gRPC only | SDK users, fastest startup | `go install .../cmd/server@latest` |
| `server-rest` | REST/HTTP | curl, scripts, any language | `go install .../cmd/server-rest@latest` |
| `server-dual` | Both gRPC + REST | Maximum flexibility | `go install .../cmd/server-dual@latest` |

### Install

```bash
# gRPC only (recommended for SDK users)
go install github.com/blackwell-systems/gcp-kms-emulator/cmd/server@latest

# REST API only
go install github.com/blackwell-systems/gcp-kms-emulator/cmd/server-rest@latest

# Both protocols
go install github.com/blackwell-systems/gcp-kms-emulator/cmd/server-dual@latest
```

### Run Server

**gRPC server:**
```bash
# Start on default port 9090
server

# Custom port
server --port 8080
```

**REST server:**
```bash
# Start on default ports (gRPC: 9090, HTTP: 8080)
server-rest

# Custom ports
server-rest --grpc-port 9090 --http-port 8080
```

**Dual protocol server:**
```bash
# Start both protocols (gRPC: 9090, HTTP: 8080)
server-dual

# Custom ports
server-dual --grpc-port 9090 --http-port 8080
```

### Use with GCP SDK

```go
package main

import (
    "context"
    "fmt"

    kms "cloud.google.com/go/kms/apiv1"
    "google.golang.org/api/option"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    ctx := context.Background()

    // Connect to emulator instead of real GCP
    conn, _ := grpc.NewClient(
        "localhost:9090",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )

    client, _ := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
    defer client.Close()

    // Use client normally - API is identical to real GCP
    // ...
}
```

### Use with REST API

**Start REST server:**
```bash
server-rest
# HTTP gateway listening at :8080
```

**Create a keyring:**
```bash
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings?keyRingId=my-keyring"
```

**Create a crypto key:**
```bash
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys?cryptoKeyId=my-key" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"ENCRYPT_DECRYPT"}'
```

**Encrypt data:**
```bash
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key:encrypt" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"'$(echo -n "my-secret-data" | base64)'"}'
```

**Decrypt data:**
```bash
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key:decrypt" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"<base64-ciphertext>"}'
```

**REST API matches GCP's official REST endpoints** - same paths, same JSON format, same behavior.

## IAM Integration

The KMS emulator supports optional permission checks using the [GCP IAM Emulator](https://github.com/blackwell-systems/gcp-iam-emulator).

### Configuration

**Environment Variables:**

- `IAM_MODE` - Controls permission enforcement (default: `off`)
  - `off` - No permission checks (legacy behavior)
  - `permissive` - Check permissions, fail-open on connectivity errors
  - `strict` - Check permissions, fail-closed on connectivity errors (for CI)
- `IAM_HOST` - IAM emulator address (default: `localhost:8080`)

### Usage

**Without IAM (default):**
```bash
# No permission checks - all operations succeed
server
```

**With IAM (permissive mode):**
```bash
# Start IAM emulator first
iam-emulator

# Start KMS with IAM checks (fail-open)
IAM_MODE=permissive IAM_HOST=localhost:8080 server
```

**With IAM (strict mode for CI):**
```bash
# All operations require valid permissions
IAM_MODE=strict IAM_HOST=localhost:8080 server
```

### Principal Injection

Specify the calling principal for permission checks:

**gRPC:**
```go
ctx := metadata.AppendToOutgoingContext(ctx, "x-emulator-principal", "user:admin@example.com")
resp, err := client.CreateKeyRing(ctx, req)
```

**REST:**
```bash
curl -H "X-Emulator-Principal: user:admin@example.com" \
  -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings?keyRingId=my-keyring"
```

### Permissions

KMS operations map to GCP IAM permissions:

| Operation | Permission | Resource |
|-----------|-----------|----------|
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

### Mode Differences

| Scenario | `off` | `permissive` | `strict` |
|----------|-------|--------------|----------|
| No IAM emulator | Allow | Allow | Deny |
| IAM unavailable | Allow | Allow | Deny |
| No principal | Allow | Deny | Deny |
| Permission denied | Allow | Deny | Deny |

**Use `off` for local dev, `permissive` for integration tests, `strict` for CI.**

## Docker

### Build Docker Images

```bash
# Build all variants
make docker

# Or build individually
docker build --build-arg VARIANT=grpc -t kms-emulator:grpc .  # gRPC only (default)
docker build --build-arg VARIANT=rest -t kms-emulator:rest .  # REST only
docker build --build-arg VARIANT=dual -t kms-emulator:dual .  # Both protocols
```

### Run Docker Containers

**gRPC only:**
```bash
docker run -p 9090:9090 gcp-kms-emulator:grpc
```

**REST only:**
```bash
docker run -p 8080:8080 gcp-kms-emulator:rest
```

**Dual protocol:**
```bash
docker run -p 9090:9090 -p 8080:8080 gcp-kms-emulator:dual
```

### In CI/CD

**GitHub Actions:**
```yaml
services:
  gcp-kms:
    image: gcp-kms-emulator:dual
    ports:
      - 9090:9090
      - 8080:8080
```

**Docker Compose:**
```yaml
services:
  gcp-kms:
    image: gcp-kms-emulator:dual
    ports:
      - "9090:9090"  # gRPC
      - "8080:8080"  # REST
```

## Use Cases

- **Local Development** - Test KMS encryption without cloud access
- **CI/CD Pipelines** - Fast integration tests without GCP credentials
- **Unit Testing** - Deterministic encryption behavior
- **Security Testing** - Validate encryption workflows
- **Cost Reduction** - Avoid GCP API charges during development

## Maintained By

Maintained by **Dayna Blackwell** — founder of Blackwell Systems, building reference infrastructure for cloud-native development.

[GitHub](https://github.com/blackwell-systems) · [LinkedIn](https://linkedin.com/in/daynablackwell) · [Blog](https://blog.blackwell-systems.com)

## Related Projects

- [GCP Secret Manager Emulator](https://github.com/blackwell-systems/gcp-secret-manager-emulator) - Reference implementation for Secret Manager API
- [GCP IAM Emulator](https://github.com/blackwell-systems/gcp-iam-emulator) - Local IAM policy enforcement for emulators
- [gcp-emulator-auth](https://github.com/blackwell-systems/gcp-emulator-auth) - Shared authentication library for GCP emulators

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
