# Docker Compose Examples

This directory contains examples for running the KMS emulator with IAM integration using Docker Compose.

## Quick Start

### Development Setup (Permissive Mode)

Start KMS + IAM emulators with fail-open permission checks:

```bash
docker-compose up
```

**Services:**
- IAM Emulator: `localhost:8080` (gRPC)
- KMS Emulator (permissive): `localhost:9090` (gRPC), `localhost:8081` (REST)

### CI Setup (Strict Mode)

Start with fail-closed permission checks for CI:

```bash
docker-compose --profile ci up
```

**Services:**
- IAM Emulator: `localhost:8080` (gRPC)
- KMS Emulator (strict): `localhost:9091` (gRPC), `localhost:8082` (REST)

### Legacy Setup (No IAM)

Start KMS without permission checks:

```bash
docker-compose --profile legacy up
```

**Services:**
- KMS Emulator (no IAM): `localhost:9092` (gRPC), `localhost:8083` (REST)

## Usage Examples

### gRPC with Principal

```go
package main

import (
    "context"
    kms "cloud.google.com/go/kms/apiv1"
    "google.golang.org/api/option"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/metadata"
)

func main() {
    ctx := context.Background()

    // Connect to KMS emulator
    conn, _ := grpc.NewClient(
        "localhost:9090",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )

    client, _ := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
    defer client.Close()

    // Add principal to context
    ctx = metadata.AppendToOutgoingContext(ctx, 
        "x-emulator-principal", "user:admin@example.com")

    // Operations will check permissions
    // ...
}
```

### REST with Principal

```bash
# Set up IAM policy first (against IAM emulator on port 8080)
curl -X POST "http://localhost:8080/v1/projects/my-project/serviceAccounts/admin@example.com:setIamPolicy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "bindings": [{
        "role": "roles/cloudkms.admin",
        "members": ["user:admin@example.com"]
      }]
    }
  }'

# Create keyring with principal (against KMS emulator on port 8081)
curl -H "X-Emulator-Principal: user:admin@example.com" \
  -X POST "http://localhost:8081/v1/projects/my-project/locations/global/keyRings?keyRingId=my-keyring"

# Create crypto key
curl -H "X-Emulator-Principal: user:admin@example.com" \
  -X POST "http://localhost:8081/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys?cryptoKeyId=my-key" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"ENCRYPT_DECRYPT"}'

# Encrypt data
curl -H "X-Emulator-Principal: user:admin@example.com" \
  -X POST "http://localhost:8081/v1/projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key:encrypt" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"'$(echo -n "my-secret-data" | base64)'"}'
```

## Mode Comparison

| Mode | Port | IAM Checks | Connectivity Error | Use Case |
|------|------|------------|-------------------|----------|
| Permissive | 9090/8081 | Yes | Allow (fail-open) | Development |
| Strict | 9091/8082 | Yes | Deny (fail-closed) | CI/CD |
| Legacy | 9092/8083 | No | N/A | Local testing |

## Testing

### Test Permissive Mode

```bash
# Start services
docker-compose up -d

# Should succeed (fail-open)
curl -X POST "http://localhost:8081/v1/projects/test/locations/global/keyRings?keyRingId=test-ring"
```

### Test Strict Mode

```bash
# Start services
docker-compose --profile ci up -d

# Should fail without principal
curl -X POST "http://localhost:8082/v1/projects/test/locations/global/keyRings?keyRingId=test-ring"

# Should succeed with authorized principal (after setting up IAM policy)
curl -H "X-Emulator-Principal: user:admin@example.com" \
  -X POST "http://localhost:8082/v1/projects/test/locations/global/keyRings?keyRingId=test-ring"
```

### Test Legacy Mode

```bash
# Start services
docker-compose --profile legacy up -d

# Should succeed without principal or IAM
curl -X POST "http://localhost:8083/v1/projects/test/locations/global/keyRings?keyRingId=test-ring"
```

## Cleanup

```bash
# Stop and remove all containers
docker-compose down

# Stop specific profile
docker-compose --profile ci down
docker-compose --profile legacy down
```
