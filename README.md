# GCP KMS Emulator

[![Blackwell Systems](https://raw.githubusercontent.com/blackwell-systems/blackwell-docs-theme/main/badge-trademark.svg)](https://github.com/blackwell-systems)
[![Go Reference](https://pkg.go.dev/badge/github.com/blackwell-systems/gcp-kms-emulator.svg)](https://pkg.go.dev/github.com/blackwell-systems/gcp-kms-emulator)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> **IAM-enforced KMS emulator** — Test encryption AND permissions locally, fail like production would.

A production-grade KMS implementation with optional **pre-flight IAM enforcement**. Unlike standard emulators that allow everything, this can deny unauthorized cryptographic operations using production-style IAM authorization policies.

**Dual protocol support**: Native gRPC + REST/HTTP. **Real encryption**: AES-256-GCM (not mocked). No GCP credentials required.

**Used by** the [Akash Network console](https://github.com/akash-network/console) (263 stars) in its development environment.

## Why This Emulator Is Different

Most KMS emulators skip authorization. This one can **enforce production-style IAM authorization policies** using the [IAM Emulator](https://github.com/blackwell-systems/gcp-iam-emulator) as a control plane.

| Approach | Example | When | Behavior |
|----------|---------|------|----------|
| Mock | Standard emulators | Never | Always allows |
| Observer | Post-execution analysis | After | Records what you used |
| **Control Plane** | **Blackwell (this)** | **Before** | **Denies unauthorized** |

Pre-flight enforcement catches permission bugs in development/CI, not production.

### The Hermetic Seal

Before Blackwell, **"GCP Hermetic Testing" was essentially impossible.**

Google's official emulators have a critical flaw: they ignore authorization. Your tests pass locally because the emulator allows everything, then fail in production when IAM denies the request.

**The two bad options:**

1. **Fake Auth** - Emulator ignores permissions (fast, but catches zero IAM bugs)
2. **Staging Leak** - Call real GCP IAM API (hermetic seal broken, tests become flaky)

**Blackwell closes the hermetic seal:**

With IAM enforcement enabled, your tests:
- **Fail for the same authorization reasons production would** (`PermissionDenied` errors)
- **Run completely offline** (no network, no GCP credentials)
- **Execute deterministically** (0ms IAM propagation delay vs 1-60s in real GCP)

This is **true hermetic testing** - all dependencies sealed inside the boundary, no external leaks.

### Enforcement Modes

**Scope note:** IAM enforcement in this emulator is scoped for CI authorization testing. It validates authorization intent and high-risk KMS operations (encrypt, decrypt, destroy, policy changes), not full GCP IAM semantic parity.

- **Off** (default) - No IAM checks, fast iteration
- **Permissive** - Enforce when IAM available, allow on connectivity errors (fail-open)
- **Strict** - Always enforce, deny on connectivity errors (fail-closed, CI-ready)

**The Security Paradox:**
> "A test that cannot fail due to a permission error is a test that has not fully validated the code's production readiness."

Use strict mode in CI to catch IAM bugs before deployment, not during Friday night incidents.

---

## Usage Modes

**Standalone** - Run independently for KMS-only testing:
```bash
server-dual
# Single service, no IAM enforcement (mode=off)
```

**With IAM Enforcement** - Run standalone with IAM checks:
```bash
# Start IAM emulator first
cd ../gcp-iam-emulator && ./bin/server --config policy.yaml

# Start KMS with enforcement
IAM_MODE=strict IAM_EMULATOR_HOST=localhost:8080 server-dual
# Now requires valid permissions for encrypt/decrypt operations
```

**Orchestrated Ecosystem** - Use with [GCP IAM Control Plane](https://github.com/blackwell-systems/gcp-iam-control-plane) for multi-service testing:
```bash
gcp-emulator start
# KMS + Secret Manager + IAM emulator
# Single policy file, unified authorization
```

**Choose standalone for simple workflows, IAM-enforced for production-like testing.**

---

## Features

### Core Functionality
- **Dual Protocol Support** - Native gRPC + REST/HTTP APIs (choose what fits your workflow)
- **SDK Compatible** - Drop-in replacement for official `cloud.google.com/go/kms` (gRPC)
- **curl Friendly** - Full REST API with JSON, test from any language or terminal
- **Real Encryption** - AES-256-GCM for symmetric encryption (not mocked)
- **Key Versioning** - Rotation, primary version switching, state transitions

### IAM Enforcement (Optional)
- **Pre-Flight Authorization** - Checks permissions before cryptographic operations
- **Deterministic Policy Evaluation** - Uses IAM Emulator control plane for decisions
- **Three Modes** - Off (default), Permissive (fail-open), Strict (fail-closed)
- **Production Semantics** - Same permission names as real GCP (`cloudkms.cryptoKeys.encrypt`)
- **Fail Like Production** - Catch permission bugs in CI, not production

### Operations
- **No GCP Credentials** - Works entirely offline without authentication
- **Fast & Lightweight** - In-memory storage, starts in milliseconds
- **Optional Persistence** - Set `GCP_KMS_DATA_DIR` to keep keys across restarts
- **Docker Support** - Pre-built containers (gRPC-only, REST-only, or dual)
- **Thread-Safe** - Concurrent access with proper synchronization

## Supported Operations

28 of the 33 Cloud KMS v1 methods are implemented, over both gRPC and REST, with real cryptography (Go standard library, plus `dcrd/secp256k1` for secp256k1).

### Key management
- `CreateKeyRing`, `GetKeyRing`, `ListKeyRings`
- `CreateCryptoKey`, `GetCryptoKey`, `ListCryptoKeys`, `UpdateCryptoKey`, `UpdateCryptoKeyPrimaryVersion`
- List methods support `page_size` and `page_token`

### Key versions
- `CreateCryptoKeyVersion`, `GetCryptoKeyVersion`, `ListCryptoKeyVersions`
- `UpdateCryptoKeyVersion` (enable/disable), `DestroyCryptoKeyVersion`, `RestoreCryptoKeyVersion`

### Cryptographic operations

| Methods | Algorithms |
|---------|------------|
| `Encrypt`, `Decrypt` | `GOOGLE_SYMMETRIC_ENCRYPTION` (AES-256-GCM, with AAD) |
| `RawEncrypt`, `RawDecrypt` | `AES_128_GCM`, `AES_256_GCM` |
| `AsymmetricSign`, `GetPublicKey` | `RSA_SIGN_PKCS1_2048_SHA256`, `RSA_SIGN_PKCS1_3072_SHA256`, `RSA_SIGN_PKCS1_4096_SHA256`, `RSA_SIGN_PKCS1_4096_SHA512`, `EC_SIGN_P256_SHA256`, `EC_SIGN_P384_SHA384`, `EC_SIGN_SECP256K1_SHA256`, `EC_SIGN_ED25519` |
| `AsymmetricDecrypt`, `GetPublicKey` | `RSA_DECRYPT_OAEP_2048_SHA256`, `RSA_DECRYPT_OAEP_3072_SHA256`, `RSA_DECRYPT_OAEP_4096_SHA256`, `RSA_DECRYPT_OAEP_4096_SHA512`, and the `_SHA1` variants |
| `MacSign`, `MacVerify` | `HMAC_SHA1`, `HMAC_SHA224`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` (constant-time verification) |
| `GenerateRandomBytes` | 1 to 1024 bytes |

`AsymmetricSign` accepts either a `digest` or raw `data` (hashed by the emulator); Ed25519 takes `data` only. Using a key for the wrong purpose returns `FAILED_PRECONDITION`.

### Key import
- `CreateImportJob`, `GetImportJob`, `ListImportJobs`, `ImportCryptoKeyVersion` (RSA-OAEP key wrapping)

### Data integrity (CRC32C)
Every cryptographic method follows Google's [data integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines):
- Request checksums (`plaintext_crc32c`, `ciphertext_crc32c`, `additional_authenticated_data_crc32c`, `digest_crc32c`, `data_crc32c`, `mac_crc32c`, and the raw-operation fields) are verified; a mismatch returns `INVALID_ARGUMENT`.
- Responses carry CRC32C checksums of their outputs (`ciphertext_crc32c`, `plaintext_crc32c`, `signature_crc32c`, `mac_crc32c`, `pem_crc32c`, ...) and set the `verified_*_crc32c` flags for each checksum that was checked. `MacVerify` sets `verified_success_integrity`.

### Error codes
Errors a caller can cause return the status code Cloud KMS uses for them, so a client can tell a bad request from a fault:
- `NOT_FOUND` and `ALREADY_EXISTS` for missing or duplicate resources
- `FAILED_PRECONDITION` for a disabled or destroyed version, a key with no enabled primary version, or the wrong key purpose
- `INVALID_ARGUMENT` for an invalid ciphertext or AAD, a CRC32C mismatch, an invalid page token, or an out-of-range length

`INTERNAL` is reserved for faults inside the emulator.

### secp256k1 signing

- **`EC_SIGN_SECP256K1_SHA256`** — secp256k1 ECDSA signing via `AsymmetricSign` (SHA-256 digest) and `GetPublicKey` (PEM)

```bash
# Create the keyring first, then:
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys?cryptoKeyId=secp256k1-signer" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "ASYMMETRIC_SIGN",
    "versionTemplate": {
      "algorithm": "EC_SIGN_SECP256K1_SHA256",
      "protectionLevel": "SOFTWARE"
    }
  }'
```

### Ed25519 signing

- **`EC_SIGN_ED25519`** - Ed25519 (pure EdDSA) signing via `AsymmetricSign` and `GetPublicKey` (SPKI `PUBLIC KEY` PEM). Software protection only, as in Cloud KMS.
- Ed25519 signs the raw message: supply `data`. A request with `digest`, or with neither `data` nor `digest`, returns `INVALID_ARGUMENT` (HTTP 400).
- Google does not document a maximum `data` size for Ed25519 `AsymmetricSign`, so the emulator does not enforce one.
- For every asymmetric signing algorithm, a request that sets both `data` and `digest` returns `INVALID_ARGUMENT`.

```bash
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys?cryptoKeyId=ed25519-signer" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "ASYMMETRIC_SIGN",
    "versionTemplate": {
      "algorithm": "EC_SIGN_ED25519",
      "protectionLevel": "SOFTWARE"
    }
  }'

# data is base64-encoded
curl -X POST "http://localhost:8080/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/ed25519-signer/cryptoKeyVersions/1:asymmetricSign" \
  -H "Content-Type: application/json" \
  -d '{"data": "aGVsbG8="}'
```

### Version State Transitions
```
PENDING_GENERATION → ENABLED → DISABLED → DESTROY_SCHEDULED → DESTROYED
                        ↑          ↓
                        └──────────┘
```

### Not Yet Implemented
- `Decapsulate` (key encapsulation) returns `UNIMPLEMENTED`
- `DeleteCryptoKey`, `DeleteCryptoKeyVersion`, `GetRetiredResource`, `ListRetiredResources`
- RSA-PSS, raw PKCS#1 and post-quantum signing algorithms
- `HSM` and `EXTERNAL` protection levels: every key is `SOFTWARE`

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
- `IAM_EMULATOR_HOST` - IAM emulator address (default: `localhost:8080`)

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
IAM_MODE=permissive IAM_EMULATOR_HOST=localhost:8080 server
```

**With IAM (strict mode for CI):**
```bash
# All operations require valid permissions
IAM_MODE=strict IAM_EMULATOR_HOST=localhost:8080 server
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

---

### Why IAM Enforcement Uses Curated Permissions (On Purpose)

IAM enforcement in this emulator is deliberately scoped for **authorization testing**, not comprehensive permission modeling. The underlying IAM emulator checks a small set of built-in roles (primitives + Secret Manager + KMS) plus unlimited custom role definitions to catch the bugs that actually break production: missing permissions, wrong role assignments, and unauthorized destructive operations (destroy, setIamPolicy, disable). This curated-first approach catches 95% of real-world authorization bugs while maintaining hermetic execution (no GCP credentials required), deterministic behavior (0ms propagation delay vs 1-60s in real GCP), and zero maintenance burden from tracking GCP's evolving role catalog. If you need to test additional permissions, define them explicitly in the IAM emulator's `policy.yaml` as custom roles — this explicit approach is simpler, more reliable, and avoids the catalog staleness problem that plagues comprehensive IAM emulation. We optimize for **authorization failures that matter**, not theoretical IAM completeness.

---

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

### Persist State Across Restarts

By default, key rings, keys and key material live in memory and are gone when the container stops. Every restart then creates new keys, and anything encrypted under the old ones can no longer be decrypted.

Set `GCP_KMS_DATA_DIR` to keep the state on disk. On startup the server restores what the directory holds, and it rewrites `state.json` there after every change. The image creates `/data` for this, so you can mount a volume on it:

```bash
docker run -p 9090:9090 -p 8080:8080 \
  -e GCP_KMS_DATA_DIR=/data -v kms-data:/data \
  gcp-kms-emulator:dual
```

With Docker Compose:

```yaml
services:
  gcp-kms:
    image: gcp-kms-emulator:dual
    environment:
      GCP_KMS_DATA_DIR: /data
    volumes:
      - kms-data:/data

volumes:
  kms-data:
```

`state.json` holds private key material in plaintext, with mode `0600`. Only use it for development keys. If the file exists but can't be read, the server refuses to start rather than overwrite it. Delete the file (or the volume) to start from scratch.

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

- [**GCP IAM Control Plane**](https://github.com/blackwell-systems/gcp-iam-control-plane) - CLI to orchestrate the Local IAM Control Plane (this emulator + IAM + others)
- [GCP IAM Emulator](https://github.com/blackwell-systems/gcp-iam-emulator) - Policy engine (the brain) for IAM enforcement
- [GCP Secret Manager Emulator](https://github.com/blackwell-systems/gcp-secret-manager-emulator) - IAM-enforced Secret Manager data plane
- [gcp-emulator-auth](https://github.com/blackwell-systems/gcp-emulator-auth) - Enforcement proxy library (the guard)

---

## Who's Using This?

If you're using this KMS emulator — in CI, locally, or in a test harness — I'd love to hear how you're using it.

- **What crypto bugs did you catch?** (unauthorized encrypt/decrypt, key version issues, IAM policy problems)
- **Are you using real cryptographic operations?** (testing with actual key material, or mocking crypto)
- **How are you managing keys?** (versioning, rotation, destruction workflows)
- **What's still friction?** (missing algorithms, IAM integration complexity, key import limitations)

Open an issue, start a discussion, or reach out directly:

📬 dayna@blackwell-systems.com

This helps shape the roadmap and ensures the project stays aligned with real-world needs.

---

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
