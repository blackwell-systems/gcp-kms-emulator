# Cold-Start UX Audit Prompt

**Metadata:**
- Audit Date: 2026-04-02
- Tool: gcp-kms-emulator (three server binaries: `/tmp/gcp-kms-server`, `/tmp/gcp-kms-server-grpc`, `/tmp/gcp-kms-server-rest`)
- Tool Version: 0.1.0 (embedded in startup banner; no `--version` flag)
- Sandbox mode: local
- Sandbox: Local mode. The tool is a gRPC/REST KMS emulator server. Use flags `-port 19090` (gRPC server), `-grpc-port 19091 -http-port 18080` (dual/rest) to avoid port conflicts. The server binaries are at /tmp/gcp-kms-server (dual), /tmp/gcp-kms-server-grpc (gRPC only), /tmp/gcp-kms-server-rest (REST only).
- Exec prefix: (none — run directly on host)

---

You are performing a UX audit of gcp-kms-emulator — a tool that provides a production-grade local KMS emulator with real AES-256-GCM encryption, dual gRPC and REST protocol support, and optional pre-flight IAM enforcement for hermetic authorization testing.

You are acting as a **new user** encountering this tool for the first time.

Sandbox: Local mode. Binaries at `/tmp/gcp-kms-server` (dual), `/tmp/gcp-kms-server-grpc` (gRPC only), `/tmp/gcp-kms-server-rest` (REST only). Use non-standard ports throughout to avoid conflicts.

Run all commands directly on the host (no exec prefix needed).

## Server Lifecycle Pattern

All areas that require a running server must follow this pattern:

```bash
# Start server in background
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
# Wait briefly for startup
sleep 0.5
# ... run test commands ...
# Tear down
kill $SERVER_PID
```

Use a fresh server instance (killed and restarted) for each area that needs a clean state, unless state carryover across areas is intentional.

## Audit Areas

### 1. Discovery

Run `--help` for all three binaries. Note: there is no `--version` flag; version is only visible in the startup banner.

```bash
/tmp/gcp-kms-server --help
/tmp/gcp-kms-server-grpc --help
/tmp/gcp-kms-server-rest --help
```

Evaluate:
- Are all supported flags documented?
- Are environment variables (`IAM_MODE`, `IAM_HOST`, `GCP_KMS_PORT`, `GCP_KMS_LOG_LEVEL`, `GCP_KMS_GRPC_PORT`, `GCP_KMS_HTTP_PORT`, `IAM_EMULATOR_HOST`) mentioned anywhere in `--help` output?
- Is there any usage example or hint about what the server does?
- Is there a `--version` flag? If not, is there any way to confirm the version without starting the server?
- Do the three binaries document how they differ from each other?

Also try an unknown flag to see the error message:
```bash
/tmp/gcp-kms-server --version 2>&1; echo "exit:$?"
/tmp/gcp-kms-server-grpc --version 2>&1; echo "exit:$?"
/tmp/gcp-kms-server-rest --version 2>&1; echo "exit:$?"
/tmp/gcp-kms-server --unknown-flag 2>&1; echo "exit:$?"
```

---

### 2. Startup and Banner

Start each binary on non-standard ports and capture its startup output.

**Dual server:**
```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 1
kill $SERVER_PID
```

**gRPC-only server:**
```bash
/tmp/gcp-kms-server-grpc -port 19090 &
SERVER_PID=$!
sleep 1
kill $SERVER_PID
```

**REST-only server:**
```bash
/tmp/gcp-kms-server-rest -grpc-port 19092 -http-port 18081 &
SERVER_PID=$!
sleep 1
kill $SERVER_PID
```

Evaluate:
- Does the startup banner show which port(s) the server is listening on?
- Does it show the version?
- Does it show the IAM mode?
- Does it show the protocol (gRPC, REST, or dual)?
- Is it immediately clear to a new user that the server is ready to accept connections?
- Is there any guidance on how to connect (e.g., "Connect your SDK to localhost:19091")?

Also test startup with debug log level:
```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 -log-level debug &
SERVER_PID=$!
sleep 1
kill $SERVER_PID
```

---

### 3. Health and Readiness Endpoints

Start the dual server and probe well-known health endpoints.

```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/health; echo ""
curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/healthz; echo ""
curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/readyz; echo ""
curl -s http://localhost:18080/health 2>&1
curl -s http://localhost:18080/healthz 2>&1
curl -s http://localhost:18080/readyz 2>&1

kill $SERVER_PID
```

Evaluate:
- Do any health endpoints exist?
- If not, what HTTP status does the server return for these standard paths?
- Would a new user know how to verify the server started successfully before sending requests?

---

### 4. REST API — Core Key Management Workflow

Start the dual server and walk through the full key management lifecycle via REST.

```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

# 4a. Create a keyring
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=audit-ring" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

# 4b. Get the keyring
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring" \
  -w "\nHTTP:%{http_code}\n"

# 4c. List keyrings
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings" \
  -w "\nHTTP:%{http_code}\n"

# 4d. Create a crypto key
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys?cryptoKeyId=audit-key" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"ENCRYPT_DECRYPT"}' \
  -w "\nHTTP:%{http_code}\n"

# 4e. Get the crypto key
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys/audit-key" \
  -w "\nHTTP:%{http_code}\n"

# 4f. List crypto keys
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys" \
  -w "\nHTTP:%{http_code}\n"

# 4g. Encrypt
PLAINTEXT=$(echo -n "hello audit world" | base64)
ENCRYPT_RESP=$(curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys/audit-key:encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT}\"}" \
  -w "\nHTTP:%{http_code}\n")
echo "$ENCRYPT_RESP"

# 4h. Decrypt (extract ciphertext from previous response and decrypt)
CIPHERTEXT=$(echo "$ENCRYPT_RESP" | grep -o '"ciphertext":"[^"]*"' | cut -d'"' -f4)
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys/audit-key:decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext\":\"${CIPHERTEXT}\"}" \
  -w "\nHTTP:%{http_code}\n"

kill $SERVER_PID
```

Evaluate:
- Are response bodies well-formed JSON matching GCP's API format?
- Are field names consistent with GCP KMS API documentation?
- Are HTTP status codes correct (201 for creates? 200 for gets?)?
- Is the decrypted plaintext correct and clearly labeled in the response?
- Is there any response envelope or metadata that might confuse a user?

---

### 5. REST API — Key Versioning

```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

# Setup: create keyring and key
curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=ver-ring" -H "Content-Type: application/json" > /dev/null
curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys?cryptoKeyId=ver-key" -H "Content-Type: application/json" -d '{"purpose":"ENCRYPT_DECRYPT"}' > /dev/null

# 5a. Create a new key version
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key/cryptoKeyVersions" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP:%{http_code}\n"

# 5b. List key versions
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key/cryptoKeyVersions" \
  -w "\nHTTP:%{http_code}\n"

# 5c. Get a specific version
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key/cryptoKeyVersions/1" \
  -w "\nHTTP:%{http_code}\n"

# 5d. Update primary version to version 2
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key:updatePrimaryVersion" \
  -H "Content-Type: application/json" \
  -d '{"cryptoKeyVersionId":"2"}' \
  -w "\nHTTP:%{http_code}\n"

# 5e. Destroy a key version
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key/cryptoKeyVersions/1:destroy" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP:%{http_code}\n"

# 5f. Try to update primary version to the destroyed version (should fail)
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/ver-ring/cryptoKeys/ver-key:updatePrimaryVersion" \
  -H "Content-Type: application/json" \
  -d '{"cryptoKeyVersionId":"1"}' \
  -w "\nHTTP:%{http_code}\n"

kill $SERVER_PID
```

Evaluate:
- Is version state (ENABLED, DISABLED, DESTROY_SCHEDULED, DESTROYED) clearly visible in responses?
- Is the error message for using a destroyed version helpful?
- Does the version numbering start at 1 and increment as expected?

---

### 6. gRPC API — Core Workflow via grpcurl

Requires `grpcurl` to be installed. Check first:

```bash
which grpcurl || echo "grpcurl not found — skip gRPC area or install with: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
```

If grpcurl is available:

```bash
/tmp/gcp-kms-server-grpc -port 19090 &
SERVER_PID=$!
sleep 0.5

# 6a. List available services (server reflection)
grpcurl -plaintext localhost:19090 list 2>&1

# 6b. List methods on the KMS service
grpcurl -plaintext localhost:19090 list google.cloud.kms.v1.KeyManagementService 2>&1

# 6c. Describe the service
grpcurl -plaintext localhost:19090 describe google.cloud.kms.v1.KeyManagementService 2>&1

# 6d. Create a keyring
grpcurl -plaintext \
  -d '{"parent":"projects/audit-project/locations/global","key_ring_id":"grpc-ring","key_ring":{}}' \
  localhost:19090 google.cloud.kms.v1.KeyManagementService/CreateKeyRing 2>&1

# 6e. Get the keyring
grpcurl -plaintext \
  -d '{"name":"projects/audit-project/locations/global/keyRings/grpc-ring"}' \
  localhost:19090 google.cloud.kms.v1.KeyManagementService/GetKeyRing 2>&1

# 6f. List keyrings
grpcurl -plaintext \
  -d '{"parent":"projects/audit-project/locations/global"}' \
  localhost:19090 google.cloud.kms.v1.KeyManagementService/ListKeyRings 2>&1

# 6g. Create a crypto key
grpcurl -plaintext \
  -d '{"parent":"projects/audit-project/locations/global/keyRings/grpc-ring","crypto_key_id":"grpc-key","crypto_key":{"purpose":"ENCRYPT_DECRYPT"}}' \
  localhost:19090 google.cloud.kms.v1.KeyManagementService/CreateCryptoKey 2>&1

# 6h. Encrypt
PLAINTEXT_B64=$(echo -n "grpc audit data" | base64)
grpcurl -plaintext \
  -d "{\"name\":\"projects/audit-project/locations/global/keyRings/grpc-ring/cryptoKeys/grpc-key\",\"plaintext\":\"${PLAINTEXT_B64}\"}" \
  localhost:19090 google.cloud.kms.v1.KeyManagementService/Encrypt 2>&1

# 6i. Try reflection on gRPC-only server — does it support reflection?
grpcurl -plaintext localhost:19090 list 2>&1

kill $SERVER_PID
```

Evaluate:
- Does the server support gRPC server reflection (critical for discoverability)?
- Are error messages from gRPC operations helpful (proper gRPC status codes)?
- Do field names match GCP's proto field names (snake_case)?

---

### 7. Error Handling — REST

```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

# 7a. Get a keyring that does not exist
curl -s \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/nonexistent" \
  -w "\nHTTP:%{http_code}\n"

# 7b. Create a keyring, then try to create it again (duplicate)
curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=dup-ring" -H "Content-Type: application/json" > /dev/null
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=dup-ring" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

# 7c. Create a crypto key with a missing 'purpose' field
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/dup-ring/cryptoKeys?cryptoKeyId=no-purpose-key" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP:%{http_code}\n"

# 7d. Create a crypto key with an invalid 'purpose' value
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/dup-ring/cryptoKeys?cryptoKeyId=bad-purpose-key" \
  -H "Content-Type: application/json" \
  -d '{"purpose":"NOT_A_REAL_PURPOSE"}' \
  -w "\nHTTP:%{http_code}\n"

# 7e. Encrypt with a key that does not exist
PLAINTEXT=$(echo -n "test" | base64)
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/dup-ring/cryptoKeys/ghost-key:encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT}\"}" \
  -w "\nHTTP:%{http_code}\n"

# 7f. Encrypt with an empty body
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/dup-ring/cryptoKeys/ghost-key:encrypt" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -w "\nHTTP:%{http_code}\n"

# 7g. Decrypt with a corrupted/invalid ciphertext
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/dup-ring/cryptoKeys/ghost-key:decrypt" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"dGhpcyBpcyBub3QgcmVhbCBjaXBoZXJ0ZXh0"}' \
  -w "\nHTTP:%{http_code}\n"

# 7h. Send malformed JSON
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=json-test" \
  -H "Content-Type: application/json" \
  -d '{not valid json' \
  -w "\nHTTP:%{http_code}\n"

# 7i. Missing keyRingId query param
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

kill $SERVER_PID
```

Evaluate:
- Are error responses well-formed JSON with a `code`, `message`, and/or `status` field?
- Do error messages tell the user what went wrong and what to do?
- Are HTTP status codes correct (404 for not-found, 409 for duplicate, 400 for bad input)?
- Does the error format match GCP's error format (`{"error": {"code": ..., "message": ..., "status": ...}}`)?

---

### 8. IAM Integration — Strict Mode Without IAM Emulator

Start the server with `IAM_MODE=strict` but no IAM emulator running. This tests fail-closed behavior and the quality of error messages.

```bash
IAM_MODE=strict /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

# 8a. Startup banner — does it mention IAM_MODE=strict?
# (already captured from startup output)

# 8b. Try creating a keyring (should fail: IAM enforced, no principal)
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=iam-ring" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

# 8c. Try with an X-Emulator-Principal header (should still fail: no IAM emulator running)
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=iam-ring" \
  -H "Content-Type: application/json" \
  -H "X-Emulator-Principal: user:admin@example.com" \
  -w "\nHTTP:%{http_code}\n"

kill $SERVER_PID

# 8d. Start with IAM_MODE=permissive and no IAM emulator — should fail-open
IAM_MODE=permissive /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=permissive-ring" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

kill $SERVER_PID

# 8e. Check what IAM_HOST env var the README calls vs what the server actually uses
# README says IAM_HOST; IAM section also mentions IAM_EMULATOR_HOST
# Confirm which one works by checking startup logs
IAM_MODE=strict IAM_HOST=localhost:19999 /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=iam-host-test" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"
kill $SERVER_PID

IAM_MODE=strict IAM_EMULATOR_HOST=localhost:19999 /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=iam-emulator-host-test" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"
kill $SERVER_PID
```

Evaluate:
- Does the startup banner confirm that IAM enforcement is active and which mode?
- Are the IAM-related error messages meaningful (do they mention permissions, the missing IAM emulator, or the mode)?
- Is the env var name consistent? The README shows both `IAM_HOST` and `IAM_EMULATOR_HOST` — which actually works?
- Does strict mode correctly deny all operations when no IAM emulator is available?
- Does permissive mode correctly allow operations when no IAM emulator is available?

---

### 9. Edge Cases

```bash
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
SERVER_PID=$!
sleep 0.5

# 9a. Root path — what does the HTTP server return?
curl -s http://localhost:18080/ -w "\nHTTP:%{http_code}\n"

# 9b. Completely unknown path
curl -s http://localhost:18080/v1/unknown/endpoint -w "\nHTTP:%{http_code}\n"

# 9c. Wrong HTTP method (GET on an encrypt endpoint)
curl -s -X GET \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/test-ring/cryptoKeys/test-key:encrypt" \
  -w "\nHTTP:%{http_code}\n"

# 9d. Very long resource name (256-character keyring ID)
LONG_NAME=$(python3 -c "print('a' * 256)" 2>/dev/null || printf '%0.sa' {1..256})
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=${LONG_NAME}" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

# 9e. Resource name with special characters
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=ring-with-@-symbol" \
  -H "Content-Type: application/json" \
  -w "\nHTTP:%{http_code}\n"

# 9f. Empty plaintext for encrypt (base64 of empty string)
EMPTY_B64=$(echo -n "" | base64)
# Setup a key first
curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings?keyRingId=edge-ring" -H "Content-Type: application/json" > /dev/null
curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/edge-ring/cryptoKeys?cryptoKeyId=edge-key" -H "Content-Type: application/json" -d '{"purpose":"ENCRYPT_DECRYPT"}' > /dev/null
curl -s -X POST \
  "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/edge-ring/cryptoKeys/edge-key:encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${EMPTY_B64}\"}" \
  -w "\nHTTP:%{http_code}\n"

# 9g. Start with no flags (default ports) — confirm it starts
/tmp/gcp-kms-server &
SERVER_PID2=$!
sleep 0.5
curl -s -X POST "http://localhost:8080/v1/projects/p/locations/global/keyRings?keyRingId=default-test" -H "Content-Type: application/json" -w "\nHTTP:%{http_code}\n"
kill $SERVER_PID2

kill $SERVER_PID
```

Evaluate:
- Does the server return a helpful 404/405 for unknown paths and wrong methods?
- Does the root path give any guidance (e.g., "GCP KMS Emulator running")?
- Are invalid resource names validated with a clear error?
- Can the server encrypt empty plaintext?

---

### 10. Output and Logging Quality

Start the server with different log levels and perform operations to evaluate log output.

```bash
# 10a. Default log level (info)
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 2>&1 &
SERVER_PID=$!
sleep 0.5

curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings?keyRingId=log-ring" -H "Content-Type: application/json" > /dev/null
PLAINTEXT=$(echo -n "log test" | base64)
curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings/log-ring/cryptoKeys?cryptoKeyId=log-key" -H "Content-Type: application/json" -d '{"purpose":"ENCRYPT_DECRYPT"}' > /dev/null
curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings/log-ring/cryptoKeys/log-key:encrypt" -H "Content-Type: application/json" -d "{\"plaintext\":\"${PLAINTEXT}\"}" > /dev/null
curl -s "http://localhost:18080/v1/projects/p/locations/global/keyRings/nonexistent" > /dev/null

kill $SERVER_PID
sleep 0.5

# 10b. Debug log level
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 -log-level debug 2>&1 &
SERVER_PID=$!
sleep 0.5

curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings?keyRingId=debug-ring" -H "Content-Type: application/json" > /dev/null
curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings/debug-ring/cryptoKeys?cryptoKeyId=debug-key" -H "Content-Type: application/json" -d '{"purpose":"ENCRYPT_DECRYPT"}' > /dev/null
PLAINTEXT=$(echo -n "debug test" | base64)
curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings/debug-ring/cryptoKeys/debug-key:encrypt" -H "Content-Type: application/json" -d "{\"plaintext\":\"${PLAINTEXT}\"}" > /dev/null

kill $SERVER_PID
sleep 0.5

# 10c. Invalid log level
/tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 -log-level bogus 2>&1 &
SERVER_PID=$!
sleep 0.5
kill $SERVER_PID
```

Evaluate:
- Does each request produce a log line? Does it include method, path, status code?
- Does debug mode produce meaningfully more output than info mode?
- Does an invalid `-log-level` value produce a helpful error or silently fall back?
- Is log output structured (JSON) or human-readable? Is the format consistent?
- Do error responses (404, 409, etc.) produce log lines at warn/error level?

---

## Findings Format

For each issue found, use:

### [AREA] Finding Title
- **Severity**: UX-critical / UX-improvement / UX-polish
- **What happens**: What the user actually sees
- **Expected**: What better behavior looks like
- **Repro**: Exact command(s)

Severity guide:
- **UX-critical**: Broken, misleading, or completely missing behavior that blocks the user
- **UX-improvement**: Confusing or unhelpful behavior that a user would notice and dislike
- **UX-polish**: Minor friction, inconsistency, or missed opportunity for clarity

## Report

- Group findings by area
- Include a summary table at the top: total count by severity
- Write the complete report to docs/cold-start-audit.md using the Write tool

IMPORTANT: Run ALL commands directly on the host (no exec prefix needed).
Do not use ports 9090 or 8080 — always use 19090/19091/18080/18081 to avoid conflicts with other services.
Do not run gcp-kms-server against production state — all state is in-memory and discarded on server exit.
