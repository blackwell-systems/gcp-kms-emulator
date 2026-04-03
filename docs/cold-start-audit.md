# Cold-Start UX Audit — gcp-kms-emulator

**Date:** 2026-04-03
**Version:** 0.1.0
**Auditor:** Automated cold-start agent
**Binaries audited:** `/tmp/gcp-kms-server` (dual), `/tmp/gcp-kms-server-grpc` (gRPC-only), `/tmp/gcp-kms-server-rest` (REST-only)

---

## Summary

| Severity | Count |
|---|---|
| UX-critical | 8 |
| UX-improvement | 11 |
| UX-polish | 6 |
| **Total** | **25** |

---

## Area 1: Discovery

### [Discovery] No environment variables documented in `--help` output
- **Severity**: UX-critical
- **What happens**: Running `--help` on any of the three binaries shows only the CLI flags. None of the supported environment variables (`IAM_MODE`, `IAM_EMULATOR_HOST`, `GCP_KMS_PORT`, `GCP_KMS_LOG_LEVEL`, `GCP_KMS_GRPC_PORT`, `GCP_KMS_HTTP_PORT`) appear anywhere in the help text. A new user has no way to discover these from the CLI.
- **Expected**: Help text should include an "Environment Variables" section listing each var, its default, and a one-line description — or at minimum a note like "Flags can also be set via GCP_KMS_* environment variables. See README for full list."
- **Repro**:
  ```
  /tmp/gcp-kms-server --help
  /tmp/gcp-kms-server-grpc --help
  /tmp/gcp-kms-server-rest --help
  ```

### [Discovery] No `--version` flag; version only visible at startup
- **Severity**: UX-improvement
- **What happens**: `--version` is not a recognized flag. Running `/tmp/gcp-kms-server --version` exits with code 2 and prints the full `--help` output prefixed with "flag provided but not defined: -version". There is no way to check the version without starting the server.
- **Expected**: A `--version` flag that prints "gcp-kms-emulator v0.1.0" and exits 0. As a minimum, a note in `--help` that says "Version: 0.1.0" would help.
- **Repro**:
  ```
  /tmp/gcp-kms-server --version 2>&1; echo "exit:$?"
  ```
  Output: `flag provided but not defined: -version` ... `exit:2`

### [Discovery] Unknown flag error message is Go stdlib default — unhelpful
- **Severity**: UX-polish
- **What happens**: `--unknown-flag` produces `flag provided but not defined: -unknown-flag` followed by the full usage block. The prefix uses a single dash (`-unknown-flag`) even though the user typed double-dash (`--unknown-flag`), which is visually confusing.
- **Expected**: Either normalize the error to match user input (`--unknown-flag not recognized`) or keep the stdlib message but ensure the usage block below is clearly separated.
- **Repro**:
  ```
  /tmp/gcp-kms-server --unknown-flag 2>&1
  ```

### [Discovery] Three binaries do not explain their differences to each other
- **Severity**: UX-improvement
- **What happens**: Each binary's `--help` only describes its own flags. There is no cross-reference or note explaining what the other binaries do. A new user who runs `/tmp/gcp-kms-server-grpc --help` has no idea that a REST-only or dual-protocol variant also exists.
- **Expected**: A one-line description in each binary's help text, e.g. "Dual-protocol server (gRPC + REST). For gRPC-only see gcp-kms-server-grpc. For REST-only see gcp-kms-server-rest."
- **Repro**:
  ```
  /tmp/gcp-kms-server --help
  /tmp/gcp-kms-server-grpc --help
  /tmp/gcp-kms-server-rest --help
  ```

### [Discovery] No usage example or description of what the server does in `--help`
- **Severity**: UX-improvement
- **What happens**: All three help outputs show only a flag list. There is no sentence explaining what the tool is, what API it emulates, or how to connect to it.
- **Expected**: A one-line summary at the top: "GCP KMS Emulator — local implementation of the Google Cloud KMS API for testing. Point your SDK at grpc://localhost:9090."
- **Repro**:
  ```
  /tmp/gcp-kms-server --help
  ```

---

## Area 2: Startup and Banner

### [Startup] IAM mode not shown in startup banner when `IAM_MODE` is not set
- **Severity**: UX-improvement
- **What happens**: The startup banner for all three binaries never mentions the IAM mode. When `IAM_MODE` is unset (the default, which means "off"/"disabled"), there is no line confirming IAM enforcement is inactive. A user who is unsure whether they set the variable correctly has no feedback.
- **Expected**: A line like "IAM mode: off (set IAM_MODE=strict to enforce permissions)" at startup, regardless of mode.
- **Repro**:
  ```
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  ```
  Observed banner has no IAM-related line.

### [Startup] `gRPC server listening` log line appears after the `Ready` line for dual server (non-deterministic ordering)
- **Severity**: UX-polish
- **What happens**: On one run of the dual server, the banner printed in this order:
  ```
  HTTP gateway listening at :18080
  Ready to accept both gRPC and REST requests
  gRPC: localhost:19091
  REST: http://localhost:18080/...
  gRPC server listening at [::]:19091
  ```
  The "Ready" message appears before the gRPC listener is confirmed up, because the `Ready` log is inside the HTTP goroutine and the gRPC listener logs from a separate goroutine. On another run the order was different.
- **Expected**: "Ready" should appear only after both listeners are confirmed started, giving the user confidence the server is fully up.
- **Repro**:
  ```
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  ```

### [Startup] REST-only binary prints a helpful curl example; dual server does not
- **Severity**: UX-polish
- **What happens**: The REST-only server (`gcp-kms-server-rest`) prints:
  ```
  Example: curl http://localhost:18081/v1/projects/test/locations/global/keyRings
  ```
  The dual server prints the URL template `REST: http://localhost:18080/v1/projects/{project}/locations/{location}/keyRings` (with literal `{project}` placeholders). The gRPC-only server prints no example at all.
- **Expected**: All binaries should either include a runnable example command (like the REST binary) or none should. The `{project}` placeholder is not a runnable curl command. Consistency and utility are both improved by a real example.
- **Repro**:
  ```
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &; sleep 0.5; kill $!
  /tmp/gcp-kms-server-rest -grpc-port 19092 -http-port 18081 &; sleep 0.5; kill $!
  ```

### [Startup] Shutdown error `Failed to serve HTTP: http: Server closed` printed to user
- **Severity**: UX-polish
- **What happens**: Every graceful shutdown of the dual or REST server prints:
  ```
  Failed to serve HTTP: http: Server closed
  ```
  This message looks like an error even though it is the expected behavior during a graceful stop.
- **Expected**: Suppress this log line or reclassify it as a debug-level message. The server already prints "Shutting down servers..." so the user has confirmation of intent. Seeing "Failed to serve" creates alarm.
- **Repro**:
  ```
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &; SERVER_PID=$!; sleep 0.5; kill $SERVER_PID
  ```

### [Startup] `gcp-kms-server-dual` binary is not named consistently with the other two
- **Severity**: UX-polish
- **What happens**: The three binaries are named `gcp-kms-server`, `gcp-kms-server-grpc`, and `gcp-kms-server-rest`. The first is actually the dual-protocol server, but its name does not reflect that. The README and startup banner call it "Dual Protocol" but the binary name is just `server`.
- **Expected**: Rename to `gcp-kms-server-dual` to make the naming scheme consistent and self-explanatory, or document the naming scheme prominently.
- **Repro**: Compare binary names vs banner output.

---

## Area 3: Health and Readiness Endpoints

### [Health] `/healthz` and `/readyz` return plain-text 404, not JSON
- **Severity**: UX-improvement
- **What happens**: Only `/health` is registered and returns `{"status":"healthy"}` with HTTP 200. `/healthz` and `/readyz` — both common Kubernetes standards — return plain-text `404 page not found\n` with HTTP 404. The 404 responses are not JSON, inconsistent with all other error responses.
- **Expected**: Either register `/healthz` and `/readyz` as aliases for `/health`, or return a consistent JSON 404: `{"error": "Not found"}`. Users deploying in Kubernetes will configure liveness/readiness probes against `/healthz` or `/readyz` and silently get 404s.
- **Repro**:
  ```bash
  curl -s http://localhost:18080/healthz
  # Output: 404 page not found
  curl -s http://localhost:18080/readyz
  # Output: 404 page not found
  curl -s http://localhost:18080/health
  # Output: {"status":"healthy"}
  ```

### [Health] Startup banner gives no hint about the health endpoint
- **Severity**: UX-improvement
- **What happens**: The startup banner shows the gRPC and REST API URLs but does not mention that `/health` exists. A new user has no way to know how to verify the server is ready without reading the README.
- **Expected**: Add a line to the startup banner: "Health: http://localhost:18080/health"
- **Repro**: Observe startup banner output — no mention of `/health`.

---

## Area 4: REST API — Core Key Management Workflow

### [REST-Core] Encrypt response returns HTTP 200 instead of matching GCP's HTTP 200 — acceptable, but `name` field in encrypt response is unexpected
- **Severity**: UX-improvement
- **What happens**: The encrypt response body includes a `"name"` field containing the crypto key resource name. GCP's real KMS Encrypt response does not include `name` at the top level — the `name` field is part of the `EncryptResponse` proto only for the resource that was used. More notably, the response includes many null/empty fields:
  ```json
  {
    "ciphertext_crc32c": null,
    "verified_plaintext_crc32c": false,
    "verified_additional_authenticated_data_crc32c": false,
    "protection_level": "PROTECTION_LEVEL_UNSPECIFIED"
  }
  ```
  These null fields and `PROTECTION_LEVEL_UNSPECIFIED` may confuse users who copy the response to compare with real GCP output.
- **Expected**: Null fields should be omitted from JSON output (`omitempty`). `protection_level` should either show a real value (e.g. `SOFTWARE`) or not appear if unset.
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/projects/audit-project/locations/global/keyRings/audit-ring/cryptoKeys/audit-key:encrypt" \
    -H "Content-Type: application/json" -d '{"plaintext":"aGVsbG8="}'
  ```

### [REST-Core] Decrypt response `plaintext` field is base64-encoded but not labeled
- **Severity**: UX-improvement
- **What happens**: The decrypt response is:
  ```json
  {"plaintext":"aGVsbG8gYXVkaXQgd29ybGQ=","plaintext_crc32c":null,"used_primary":false,"protection_level":"PROTECTION_LEVEL_UNSPECIFIED"}
  ```
  The plaintext is base64-encoded (as required by the GCP API), but there is no documentation in help or startup output noting this. A new user who decrypts for the first time will see `aGVsbG8gYXVkaXQgd29ybGQ=` and not immediately know to base64-decode it.
- **Expected**: This is correct GCP API behavior, but startup output or help text should include a note: "Plaintext is returned as base64. Decode with: echo '<value>' | base64 -d"
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/.../cryptoKeys/audit-key:decrypt" \
    -H "Content-Type: application/json" -d '{"ciphertext":"..."}'
  ```

### [REST-Core] CryptoKey response body is extremely verbose with null fields
- **Severity**: UX-improvement
- **What happens**: A CreateCryptoKey or GetCryptoKey response contains many null/empty fields that would not appear in a real GCP API response:
  ```json
  "attestation": null,
  "generate_time": null,
  "destroy_time": null,
  "destroy_event_time": null,
  "import_job": "",
  "import_time": null,
  "import_failure_reason": "",
  "generation_failure_reason": "",
  "external_destruction_failure_reason": "",
  "external_protection_level_options": null,
  "reimport_eligible": false,
  "next_rotation_time": null,
  "version_template": null,
  "destroy_scheduled_duration": null,
  "crypto_key_backend": "",
  "key_access_justifications_policy": null
  ```
  This noise makes it hard to read responses and compare them to the real GCP API, where `omitempty` removes unset proto fields.
- **Expected**: Apply `omitempty` (or grpc-gateway JSON marshaling options) to suppress zero-value and null fields. The response should only contain fields that have meaningful values.
- **Repro**: Any CreateCryptoKey or GetCryptoKey call.

---

## Area 5: REST API — Key Versioning

### [Versioning] Destroying a key version returns `DESTROY_SCHEDULED`, not `DESTROYED`
- **Severity**: UX-improvement
- **What happens**: Calling `:destroy` on a key version returns state `DESTROY_SCHEDULED`. In real GCP KMS, a 24-hour scheduled window exists before a key is destroyed. The emulator correctly models this state name. However, the version is never actually moved to `DESTROYED` state — there is no background job or `destroy_event_time` set. A user testing a flow that requires a key to be in `DESTROYED` state cannot reach that state.
- **Expected**: Document in README or help text that `DESTROY_SCHEDULED` is the terminal destroy state in this emulator (unlike real GCP which eventually transitions to `DESTROYED`). Or implement a way to force-complete the destruction.
- **Repro**:
  ```bash
  curl -s -X POST ".../cryptoKeyVersions/1:destroy" -H "Content-Type: application/json" -d '{}'
  # Response: "state":"DESTROY_SCHEDULED"  (destroy_time and destroy_event_time remain null)
  ```

### [Versioning] Error for using a destroyed/scheduled version leaks gRPC internals into HTTP response
- **Severity**: UX-critical
- **What happens**: When trying to set a `DESTROY_SCHEDULED` version as primary, the error response is:
  ```json
  {"error":"rpc error: code = FailedPrecondition desc = crypto key version is not enabled: ..."}
  ```
  with HTTP 500. This is a gRPC status error string leaking through the REST translation layer. HTTP 500 is also wrong — this is a client precondition failure, not a server error.
- **Expected**: The error should be HTTP 400 (or 409), and the body should follow GCP's error format:
  ```json
  {"error": {"code": 400, "message": "CryptoKeyVersion ... is not enabled.", "status": "FAILED_PRECONDITION"}}
  ```
- **Repro**:
  ```bash
  # After destroying version 1:
  curl -s -X POST ".../ver-key:updatePrimaryVersion" \
    -H "Content-Type: application/json" -d '{"cryptoKeyVersionId":"1"}'
  # Returns: HTTP 500, body contains "rpc error: code = FailedPrecondition desc = ..."
  ```

---

## Area 6: gRPC API — Core Workflow

### [gRPC] gRPC-only binary does not show the protocol in its startup banner
- **Severity**: UX-polish
- **What happens**: The gRPC-only server banner says `GCP KMS Emulator v0.1.0` (no protocol label). The dual server says `(Dual Protocol)` and the REST server says `(REST API)`. The gRPC-only binary is the only one without a parenthetical.
- **Expected**: `GCP KMS Emulator v0.1.0 (gRPC)` for consistency.
- **Repro**: `/tmp/gcp-kms-server-grpc -port 19090 &`

### [gRPC] gRPC reflect shows all proto methods including unimplemented stubs
- **Severity**: UX-improvement
- **What happens**: `grpcurl list google.cloud.kms.v1.KeyManagementService` shows 30 methods including `AsymmetricDecrypt`, `AsymmetricSign`, `MacSign`, `MacVerify`, `RawDecrypt`, `RawEncrypt`, `GenerateRandomBytes`, `Decapsulate`, `CreateImportJob`, `GetImportJob`, `ListImportJobs`, `ImportCryptoKeyVersion`, etc. These are almost certainly stubs that return "unimplemented" errors. A new user will try them and get confusing failures.
- **Expected**: Either implement the stubs with helpful "not implemented in emulator" errors, or document clearly (in help text and README) which methods are actually implemented. The README's "Supported Methods" section in the server.go comment already lists the subset — surface this somewhere visible.
- **Repro**:
  ```bash
  grpcurl -plaintext localhost:19090 list google.cloud.kms.v1.KeyManagementService
  ```

---

## Area 7: Error Handling — REST

### [Errors] Duplicate resource returns HTTP 500 instead of HTTP 409
- **Severity**: UX-critical
- **What happens**: Creating a keyring that already exists returns:
  ```json
  {"error":"rpc error: code = AlreadyExists desc = ...already exists"}
  ```
  with HTTP 500. The gRPC status code is correctly `AlreadyExists`, but the REST gateway maps it to 500 instead of 409 Conflict.
- **Expected**: HTTP 409 with a clean error body:
  ```json
  {"error": {"code": 409, "message": "... already exists", "status": "ALREADY_EXISTS"}}
  ```
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/projects/.../keyRings?keyRingId=dup-ring" -H "Content-Type: application/json"
  curl -s -X POST "http://localhost:18080/v1/projects/.../keyRings?keyRingId=dup-ring" -H "Content-Type: application/json"
  # Second returns HTTP 500
  ```

### [Errors] NotFound for nonexistent key returns HTTP 500 instead of HTTP 404
- **Severity**: UX-critical
- **What happens**: Calling encrypt on a key that does not exist returns HTTP 500 with:
  ```json
  {"error":"rpc error: code = NotFound desc = ...not found"}
  ```
  This is inconsistent: calling GET on a nonexistent keyring correctly returns HTTP 404, but encrypt on a nonexistent key returns 500.
- **Expected**: HTTP 404 for all not-found errors, not just GET operations. The gRPC status `NotFound` should always map to HTTP 404.
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/.../ghost-key:encrypt" \
    -H "Content-Type: application/json" -d '{"plaintext":"dGVzdA=="}'
  # Returns HTTP 500
  ```

### [Errors] Error response body format is not GCP-compatible (`{"error": "rpc error string"}` vs `{"error": {"code": N, ...}}`)
- **Severity**: UX-critical
- **What happens**: All error responses use the format `{"error": "rpc error: code = X desc = message"}`. The GCP Cloud KMS API returns errors in the format:
  ```json
  {"error": {"code": 404, "message": "...", "status": "NOT_FOUND"}}
  ```
  The emulator's format is a flat string, not a nested object. Any code that parses real GCP error responses will break against this emulator.
- **Expected**: Error responses should match GCP's error envelope with `code`, `message`, and `status` fields.
- **Repro**: Any error-producing request, e.g.:
  ```bash
  curl -s "http://localhost:18080/v1/projects/p/locations/global/keyRings/nonexistent"
  # Returns: {"error":"rpc error: code = NotFound desc = ..."}
  ```

### [Errors] `InvalidArgument` gRPC error returns HTTP 500 instead of HTTP 400
- **Severity**: UX-critical
- **What happens**: Encrypting with an empty body returns HTTP 500 with `"rpc error: code = InvalidArgument desc = plaintext is required"`. Similarly, encrypting with empty plaintext (base64 of "") returns HTTP 500. The gRPC status `InvalidArgument` should map to HTTP 400.
- **Expected**: HTTP 400 for all `InvalidArgument` gRPC status codes.
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/.../edge-key:encrypt" \
    -H "Content-Type: application/json" -d '{"plaintext":""}'
  # Returns HTTP 500
  ```

### [Errors] `FailedPrecondition` gRPC error returns HTTP 500 instead of HTTP 400
- **Severity**: UX-critical
- **What happens**: UpdatePrimaryVersion for a non-enabled version returns HTTP 500 (see also Area 5 finding). This maps `FailedPrecondition` to 500.
- **Expected**: HTTP 400 for `FailedPrecondition`.
- **Repro**: (See Area 5 repro above.)

### [Errors] Malformed JSON request body is silently accepted
- **Severity**: UX-critical
- **What happens**: Sending `{not valid json` as the request body to CreateKeyRing succeeds with HTTP 201 and creates the keyring:
  ```json
  {"name":"projects/.../keyRings/json-test","create_time":"..."}
  ```
  The malformed body is ignored entirely.
- **Expected**: HTTP 400 with a message like "Invalid JSON in request body".
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/projects/p/locations/global/keyRings?keyRingId=json-test" \
    -H "Content-Type: application/json" -d '{not valid json'
  # Returns HTTP 201 — keyring is created
  ```

### [Errors] Missing `purpose` field silently defaults to `ENCRYPT_DECRYPT`
- **Severity**: UX-improvement
- **What happens**: Creating a CryptoKey with body `{}` (no `purpose`) succeeds with HTTP 201, defaulting to `purpose: ENCRYPT_DECRYPT`. Real GCP KMS requires `purpose` and returns an error if it is missing.
- **Expected**: HTTP 400 with "purpose is required" or similar message to match GCP behavior.
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/.../cryptoKeys?cryptoKeyId=no-purpose-key" \
    -H "Content-Type: application/json" -d '{}'
  # Returns HTTP 201 with purpose: ENCRYPT_DECRYPT
  ```

---

## Area 8: IAM Integration

### [IAM] `IAM_HOST` documented in README but `IAM_EMULATOR_HOST` is what the code reads
- **Severity**: UX-critical
- **What happens**: The README documents `IAM_HOST` as the environment variable for the IAM emulator address:
  ```
  IAM_HOST - IAM emulator address (default: localhost:8080)
  ```
  But the underlying `emulatorauth.LoadFromEnv()` reads `IAM_EMULATOR_HOST`. Setting `IAM_HOST=localhost:19999` has no effect — the server still tries to connect to `localhost:8080` (the default). Setting `IAM_EMULATOR_HOST=localhost:19999` does work correctly (the error shows `dial tcp 127.0.0.1:19999` instead of `127.0.0.1:8080`).
  The README also uses `IAM_EMULATOR_HOST` in a code example on line 75, contradicting the table on line 286.
- **Expected**: The README should consistently document `IAM_EMULATOR_HOST`. The incorrect `IAM_HOST` reference should be removed.
- **Repro**:
  ```bash
  IAM_MODE=strict IAM_HOST=localhost:19999 /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  # Errors show: dial tcp 127.0.0.1:8080  (IAM_HOST was ignored)

  IAM_MODE=strict IAM_EMULATOR_HOST=localhost:19999 /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  # Errors show: dial tcp 127.0.0.1:19999  (IAM_EMULATOR_HOST was respected)
  ```

### [IAM] IAM mode not shown in startup banner
- **Severity**: UX-improvement
- **What happens**: When the server starts with `IAM_MODE=strict`, the startup banner is identical to starting without it — no line confirms that IAM enforcement is active or which mode is selected. A user cannot tell from the logs whether IAM enforcement is active.
- **Expected**: The banner should include a line like: "IAM mode: strict (host: localhost:8080)"
- **Repro**:
  ```bash
  IAM_MODE=strict /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  # Banner shows no IAM-related lines
  ```

### [IAM] Strict mode error message exposes gRPC transport internals
- **Severity**: UX-improvement
- **What happens**: When strict mode cannot reach the IAM emulator, the REST error is:
  ```json
  {"error":"rpc error: code = Internal desc = IAM check failed: rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial tcp 127.0.0.1:8080: connect: connection refused\""}
  ```
  This is a deeply nested gRPC error chain. A new user will not understand why their KMS request failed.
- **Expected**: A cleaner message: "IAM enforcement is enabled (strict mode) but the IAM emulator is unreachable at localhost:8080. Start the IAM emulator or set IAM_MODE=off."
- **Repro**:
  ```bash
  IAM_MODE=strict /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 &
  curl -s -X POST "http://localhost:18080/v1/.../keyRings?keyRingId=test" -H "Content-Type: application/json"
  ```

---

## Area 9: Edge Cases

### [Edge] Root path `/` returns plain-text 404, not JSON
- **Severity**: UX-polish
- **What happens**: `GET /` returns `404 page not found\n` as plain text. All other unrecognized paths under `/v1/` return JSON `{"error":"Not found"}`. The root path is inconsistent.
- **Expected**: `GET /` should return JSON `{"error":"Not found"}` or a useful landing message like `{"service":"gcp-kms-emulator","version":"0.1.0","health":"/health"}`.
- **Repro**:
  ```bash
  curl -s http://localhost:18080/
  # Output: 404 page not found
  ```

### [Edge] Wrong HTTP method returns misleading error about JSON parsing
- **Severity**: UX-improvement
- **What happens**: `GET .../cryptoKeys/test-key:encrypt` returns HTTP 400 with:
  ```json
  {"error":"Invalid JSON: unexpected end of JSON input"}
  ```
  The actual problem is that GET is the wrong method (encrypt requires POST). The user is told about a JSON parsing error when there was never a request body — a GET has no body to parse.
- **Expected**: HTTP 405 Method Not Allowed, or at minimum a message that says "POST is required for this endpoint" rather than a JSON parse error.
- **Repro**:
  ```bash
  curl -s -X GET "http://localhost:18080/v1/projects/p/locations/global/keyRings/r/cryptoKeys/k:encrypt"
  # Returns: {"error":"Invalid JSON: unexpected end of JSON input"} HTTP 400
  ```

### [Edge] No validation of resource name length or characters
- **Severity**: UX-improvement
- **What happens**: A 256-character keyring ID is accepted and created successfully. A keyring ID containing `@` is also accepted. Real GCP KMS validates that resource IDs are 1-63 characters and match `[a-zA-Z0-9_-]`.
- **Expected**: Return HTTP 400 with a validation message for names exceeding 63 characters or containing invalid characters.
- **Repro**:
  ```bash
  # 256-char name succeeds:
  curl -s -X POST "http://localhost:18080/v1/.../keyRings?keyRingId=aaa...256chars" -H "Content-Type: application/json"
  # Returns HTTP 201

  # @ symbol succeeds:
  curl -s -X POST "http://localhost:18080/v1/.../keyRings?keyRingId=ring-with-@-symbol" -H "Content-Type: application/json"
  # Returns HTTP 201
  ```

### [Edge] Empty plaintext returns HTTP 500 with `InvalidArgument` rather than HTTP 400
- **Severity**: UX-improvement
- **What happens**: Sending `{"plaintext": ""}` (base64 of empty string) to encrypt returns:
  ```json
  {"error":"rpc error: code = InvalidArgument desc = plaintext is required"}
  ```
  with HTTP 500. This is the same HTTP-status mapping bug from Area 7, but also noteworthy that encrypting a truly empty plaintext is rejected. Real GCP KMS does allow encrypting empty plaintext.
- **Expected**: If empty plaintext should be rejected, return HTTP 400. If it should be allowed (to match GCP), allow it.
- **Repro**:
  ```bash
  curl -s -X POST "http://localhost:18080/v1/.../edge-key:encrypt" \
    -H "Content-Type: application/json" -d '{"plaintext":""}'
  # Returns HTTP 500
  ```

---

## Area 10: Output and Logging Quality

### [Logging] No per-request log lines at info level — requests are invisible in logs
- **Severity**: UX-critical
- **What happens**: At the default `info` log level, no log line is produced when a request is handled. Creating a keyring, encrypting data, and hitting a 404 all produce zero log output. The only server log lines are the startup banner and shutdown message.
- **Expected**: Each request should produce at least one log line at info level containing the method, path, and HTTP status code, e.g.:
  ```
  2026/04/03 ... POST /v1/projects/p/.../keyRings 201 1.2ms
  ```
  Without request logging, operators and developers have no visibility into what the server is doing.
- **Repro**:
  ```bash
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 2>&1 &
  curl -s -X POST "http://localhost:18080/v1/.../keyRings?keyRingId=log-ring" -H "Content-Type: application/json"
  # No log output for the request
  ```

### [Logging] Debug log level produces identical output to info level
- **Severity**: UX-critical
- **What happens**: Running with `-log-level debug` produces exactly the same log lines as `-log-level info`. There is no additional debug output even when requests are processed. The `debug` log level flag has no visible effect.
- **Expected**: Debug mode should produce significantly more output — at minimum per-request logs, and ideally request/response payloads (with plaintext redacted), IAM decision details, and storage operation traces.
- **Repro**:
  ```bash
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 -log-level debug 2>&1 &
  curl -s -X POST "http://localhost:18080/v1/.../keyRings?keyRingId=debug-ring" -H "Content-Type: application/json"
  # No debug log lines for the request
  ```

### [Logging] Invalid `-log-level` value is silently accepted and echoed in banner
- **Severity**: UX-improvement
- **What happens**: Running with `-log-level bogus` starts the server successfully and prints `Log level: bogus` in the banner. No warning is issued. The level is unrecognized so the actual behavior is undefined (presumably defaults to some internal level silently).
- **Expected**: The server should either reject the invalid value at startup (`invalid log level "bogus", valid values: debug, info, warn, error`) or print a warning and fall back to `info`.
- **Repro**:
  ```bash
  /tmp/gcp-kms-server -grpc-port 19091 -http-port 18080 -log-level bogus
  # Starts successfully, prints "Log level: bogus"
  ```

### [Logging] Log output uses Go stdlib `log` (not structured JSON) with no timestamp precision
- **Severity**: UX-polish
- **What happens**: All log output uses Go's standard `log.Printf` which produces lines like:
  ```
  2026/04/02 23:57:18 GCP KMS Emulator v0.1.0 (Dual Protocol)
  ```
  The format is human-readable but not machine-parseable (not JSON). The timestamp has second precision with no timezone (displays local time). In production or CI log aggregation systems, structured JSON logs (e.g. `{"time":"...","level":"info","msg":"..."}`) are strongly preferred.
- **Expected**: Use a structured logger (e.g. `slog`, `zap`, or `zerolog`) that can emit JSON when desired, or at minimum add UTC timestamps with millisecond precision.
- **Repro**: Any server startup.
