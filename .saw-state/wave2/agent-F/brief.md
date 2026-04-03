---
saw_name: '[SAW:wave2:agent-F] ## Role'
---

# Agent F Brief - Wave 2

**IMPL Doc:** /Users/dayna.blackwell/code/gcp-kms-emulator/docs/IMPL/IMPL-kms-conformance-fixes.yaml

## Files Owned

- `internal/server/server.go`
- `internal/server/importjob.go`
- `conformance_test.go`


## Task

## Role
Server layer: server.go and importjob.go — wires all storage signature changes,
purpose validation, CRC32C, and integration tests.

## Prerequisites
Wave 1 has completed. The following storage signatures have changed:
- `storage.Encrypt(keyName, plaintext, aad) ([]byte, string, error)`
- `storage.Decrypt(keyName, ciphertext, aad) ([]byte, string, error)`
- `storage.CreateCryptoKeyVersion(keyName string, req *kmspb.CryptoKeyVersion) (*kmspb.CryptoKeyVersion, error)`
- `storage.UpdateCryptoKey(keyName string, key *kmspb.CryptoKey, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKey, error)`
- `storage.UpdateCryptoKeyVersion(versionName string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKeyVersion, error)`
- `storage.DestroyCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error)` (returns DestroyTime)
- `storage.AsymmetricSign(versionName string, digest []byte, digestType string, rawData []byte) ([]byte, error)`

## What to implement in internal/server/server.go

### 1. Encrypt — wire AAD + CRC32C + version name response
```go
func (s *Server) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
    // ... existing field checks ...
    if err := verifyCRC32C(req.Plaintext, req.PlaintextCrc32C); err != nil {
        return nil, err
    }
    if err := verifyCRC32C(req.AdditionalAuthenticatedData, req.AdditionalAuthenticatedDataCrc32C); err != nil {
        return nil, err
    }
    ciphertext, versionName, err := s.storage.Encrypt(req.Name, req.Plaintext, req.AdditionalAuthenticatedData)
    if err != nil {
        return nil, storageErr(err)
    }
    return &kmspb.EncryptResponse{
        Name:                    versionName,  // version name, not key name
        Ciphertext:              ciphertext,
        CiphertextCrc32C:        crc32cValue(ciphertext),
        VerifiedPlaintextCrc32C: req.PlaintextCrc32C != nil,
        VerifiedAdditionalAuthenticatedDataCrc32C: req.AdditionalAuthenticatedDataCrc32C != nil,
        ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
    }, nil
}
```

### 2. Decrypt — wire AAD + CRC32C + UsedPrimary
```go
func (s *Server) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
    // ... existing field checks ...
    if err := verifyCRC32C(req.Ciphertext, req.CiphertextCrc32C); err != nil {
        return nil, err
    }
    if err := verifyCRC32C(req.AdditionalAuthenticatedData, req.AdditionalAuthenticatedDataCrc32C); err != nil {
        return nil, err
    }
    plaintext, usedVersionName, err := s.storage.Decrypt(req.Name, req.Ciphertext, req.AdditionalAuthenticatedData)
    if err != nil {
        return nil, storageErr(err)
    }
    // Determine UsedPrimary: fetch the key to compare primary version
    cryptoKey, getErr := s.storage.GetCryptoKey(req.Name)
    usedPrimary := getErr == nil && cryptoKey.Primary != nil && cryptoKey.Primary.Name == usedVersionName
    return &kmspb.DecryptResponse{
        Plaintext:       plaintext,
        PlaintextCrc32C: crc32cValue(plaintext),
        UsedPrimary:     usedPrimary,
        ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
    }, nil
}
```

### 3. CreateCryptoKey — reject UNSPECIFIED purpose
Remove the fallback:
```go
// REMOVE: if purpose == UNSPECIFIED { purpose = ENCRYPT_DECRYPT }
// ADD:
if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
    return nil, status.Error(codes.InvalidArgument, "crypto_key.purpose is required")
}
```
Note: storage.CreateCryptoKey (Agent A) will also return ErrFailedPrecondition
for UNSPECIFIED — the server now rejects first with InvalidArgument, which is
the correct gRPC code per spec.

### 4. CreateCryptoKeyVersion — pass request proto to storage
Change:
```go
version, err := s.storage.CreateCryptoKeyVersion(req.Parent, req.CryptoKeyVersion)
```

### 5. UpdateCryptoKey — wire update_mask
Change:
```go
cryptoKey, err := s.storage.UpdateCryptoKey(req.CryptoKey.Name, req.CryptoKey, req.UpdateMask)
```
Validate that `req.UpdateMask` is not nil or empty (return InvalidArgument if so):
```go
if req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0 {
    return nil, status.Error(codes.InvalidArgument, "update_mask is required")
}
```

### 6. UpdateCryptoKeyVersion — wire update_mask + state validation
Change:
```go
version, err := s.storage.UpdateCryptoKeyVersion(
    req.CryptoKeyVersion.Name,
    req.CryptoKeyVersion.State,
    req.UpdateMask,
)
```
Remove the existing `if req.CryptoKeyVersion.State == UNSPECIFIED` guard; the
storage layer now validates via mask.

## What to implement in internal/server/importjob.go

### 7. ImportCryptoKeyVersion — validate algorithm
Add before calling storage:
```go
if req.Algorithm == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
    return nil, status.Error(codes.InvalidArgument, "algorithm is required")
}
```
(Storage layer also validates, but server should return InvalidArgument, not
FailedPrecondition, for a missing required field.)

## Integration tests — conformance_test.go
Create `conformance_test.go` in the root package (`package gcp_kms_emulator_test`)
with the following test functions. Each test creates its own keyring with a unique
name to avoid collisions with existing tests.

- `TestConformance_Encrypt_AAD`: create ENCRYPT_DECRYPT key; encrypt with AAD;
  decrypt with same AAD succeeds; decrypt with different AAD fails.
- `TestConformance_Encrypt_CRC32C_Mismatch`: encrypt with wrong PlaintextCrc32C,
  expect codes.InvalidArgument.
- `TestConformance_Encrypt_ResponseName_IsVersion`: verify EncryptResponse.Name
  contains "cryptoKeyVersions/".
- `TestConformance_Encrypt_WrongPurpose`: create MAC key, call Encrypt, expect
  codes.FailedPrecondition.
- `TestConformance_Decrypt_WrongPurpose`: create ASYMMETRIC_SIGN key, call Decrypt,
  expect codes.FailedPrecondition.
- `TestConformance_Decrypt_UsedPrimary`: encrypt then decrypt; verify UsedPrimary=true.
- `TestConformance_CreateCryptoKey_UnspecifiedPurpose`: create key with UNSPECIFIED
  purpose, expect codes.InvalidArgument.
- `TestConformance_UpdateCryptoKey_MaskRespected`: update only "labels", verify
  version_template unchanged.
- `TestConformance_UpdateCryptoKeyVersion_InvalidTransition`: try to set
  state=DESTROY_SCHEDULED via UpdateCryptoKeyVersion, expect error.
- `TestConformance_DestroyCryptoKeyVersion_Idempotent`: destroy a version twice,
  second call should succeed.
- `TestConformance_DestroyCryptoKeyVersion_DestroyTime`: verify response has
  non-nil DestroyTime.
- `TestConformance_MacSign_WrongPurpose`: call MacSign on ENCRYPT_DECRYPT key,
  expect codes.FailedPrecondition.
- `TestConformance_MacSign_CRC32C_Mismatch`: call MacSign with wrong DataCrc32C,
  expect codes.InvalidArgument.
- `TestConformance_RawEncrypt_WrongPurpose`: call RawEncrypt on ENCRYPT_DECRYPT key,
  expect codes.FailedPrecondition.
- `TestConformance_ImportCryptoKeyVersion_UnspecifiedAlgorithm`: call
  ImportCryptoKeyVersion with UNSPECIFIED algorithm, expect codes.InvalidArgument.
- `TestConformance_AsymmetricSign_DataField`: create ASYMMETRIC_SIGN key, call
  AsymmetricSign with Data field instead of Digest, verify signature validates.
- `TestConformance_AsymmetricSign_WrongPurpose`: create ENCRYPT_DECRYPT key with
  EC material (workaround: use RSA_DECRYPT key), call AsymmetricSign, expect
  codes.FailedPrecondition.
- `TestConformance_AsymmetricDecrypt_SHA1OAEP`: create RSA_DECRYPT_OAEP_2048_SHA1
  key, get public key, encrypt locally with SHA-1 OAEP, call AsymmetricDecrypt —
  expect plaintext returned correctly.

Use `google.golang.org/grpc/status` and `google.golang.org/grpc/codes` for
error code assertions. Use the `setupTestServer`/`setupTestClient` helpers from
`integration_test.go` (same package).

## Verification gate
```
go build ./...
go vet ./...
go test ./...
```

## Constraints
- Do not modify any storage package files.
- Do not modify asymmetric.go, mac.go, raw.go, or crc32c.go in the server package.
- Import `fieldmaskpb` in server.go for UpdateCryptoKey.
- The `verifyCRC32C` helper is already in crc32c.go (same package) after Wave 1.
- When writing TestConformance_AsymmetricSign_WrongPurpose: the simplest approach
  is to create an ASYMMETRIC_DECRYPT key and call AsymmetricSign on it.


## Interface Contracts

### storage.Encrypt

Encrypt now accepts AdditionalAuthenticatedData (aad) and returns
both the ciphertext and the version name used, enabling server to
populate EncryptResponse.Name with the version name.

```
func (s *Storage) Encrypt(keyName string, plaintext []byte, aad []byte) (ciphertext []byte, versionName string, err error)
// Purpose validation: must be ENCRYPT_DECRYPT, else ErrFailedPrecondition
// Returns versionName = primary version resource name (e.g. ".../cryptoKeyVersions/1")
// aad is passed to gcm.Seal as the additionalData parameter
```

### storage.Decrypt

Decrypt now accepts AdditionalAuthenticatedData (aad) and returns
which version was used (to allow server to set UsedPrimary correctly).

```
func (s *Storage) Decrypt(keyName string, ciphertext []byte, aad []byte) (plaintext []byte, usedVersionName string, err error)
// Purpose validation: must be ENCRYPT_DECRYPT, else ErrFailedPrecondition
// aad is passed to gcm.Open as the additionalData parameter
// usedVersionName allows server to compare with PrimaryVersion
```

### storage.CreateCryptoKeyVersion

CreateCryptoKeyVersion now accepts the requested version proto so that
state and algorithm overrides from the request are honoured.

```
func (s *Storage) CreateCryptoKeyVersion(keyName string, req *kmspb.CryptoKeyVersion) (*kmspb.CryptoKeyVersion, error)
// req may be nil (backwards-compatible: falls back to key's VersionTemplate)
// If req.Algorithm is non-UNSPECIFIED, override the template algorithm
// Returns version proto with ProtectionLevel=SOFTWARE, GenerateTime=CreateTime
```

### storage.UpdateCryptoKey

UpdateCryptoKey now accepts the full CryptoKey and a FieldMask, applying
only the fields listed in the mask.

```
func (s *Storage) UpdateCryptoKey(keyName string, key *kmspb.CryptoKey, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKey, error)
// Supported mask paths: "labels", "rotation_period", "next_rotation_time",
//   "version_template", "destroy_scheduled_duration"
// Unrecognised paths are silently ignored (match real API behaviour)
```

### storage.UpdateCryptoKeyVersion

UpdateCryptoKeyVersion now validates the update_mask and enforces state
transition rules: only ENABLED<->DISABLED transitions permitted.

```
func (s *Storage) UpdateCryptoKeyVersion(versionName string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKeyVersion, error)
// Validates mask contains "state" before applying
// Enforces: source must be ENABLED or DISABLED
//           target must be ENABLED or DISABLED
//           no other state transitions permitted via this method
```

### storage.DestroyCryptoKeyVersion

DestroyCryptoKeyVersion is now idempotent for DESTROY_SCHEDULED versions
and sets DestroyTime on the returned proto.

```
func (s *Storage) DestroyCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error)
// If state == DESTROY_SCHEDULED: return version as-is (idempotent, no error)
// If state == DESTROYED: return ErrFailedPrecondition (unchanged)
// On transition: set DestroyTime = now + 30 days; persist on StoredCryptoKeyVersion
// StoredCryptoKeyVersion gains DestroyTime time.Time field
```

### storage.AsymmetricDecrypt

AsymmetricDecrypt now selects the OAEP hash based on the version algorithm.

```
func (s *Storage) AsymmetricDecrypt(versionName string, ciphertext []byte) ([]byte, error)
// Signature unchanged; internal change: select hash from algorithm
// RSA_DECRYPT_OAEP_*_SHA1   -> sha1.New()
// RSA_DECRYPT_OAEP_*_SHA256 -> sha256.New()
// RSA_DECRYPT_OAEP_*_SHA512 -> sha512.New()
```

### storage.AsymmetricSign

AsymmetricSign now accepts optional rawData for direct signing
(hashing internally) in addition to pre-hashed digest.

```
func (s *Storage) AsymmetricSign(versionName string, digest []byte, digestType string, rawData []byte) ([]byte, error)
// rawData: if non-nil, hash with algorithm's hash then sign (data field support)
// digest/digestType: used when rawData is nil (existing behaviour)
// Purpose validation: parent key must be ASYMMETRIC_SIGN
```

### storage.MacSign

MacSign now selects the HMAC hash based on the key version algorithm.

```
func (s *Storage) MacSign(versionName string, data []byte) ([]byte, error)
// Signature unchanged; internal change: select hash from version.Algorithm
// HMAC_SHA1   -> sha1.New
// HMAC_SHA224 -> sha256.New (sha224 via sha256.New224)
// HMAC_SHA256 -> sha256.New  (existing)
// HMAC_SHA384 -> sha512.New384
// HMAC_SHA512 -> sha512.New
// Purpose validation: parent key must be MAC
```

### storage.MacVerify

MacVerify now selects the HMAC hash based on the key version algorithm.

```
func (s *Storage) MacVerify(versionName string, data []byte, mac []byte) (bool, error)
// Signature unchanged; internal change: same hash selection as MacSign
// Purpose validation: parent key must be MAC
```

### storage.findKeyAndVersion

New helper that returns both the parent StoredCryptoKey and the
StoredCryptoKeyVersion for a version resource name. Required by all
purpose-validation paths (asymmetric, mac, raw ops).

```
func (s *Storage) findKeyAndVersion(versionName string) (*StoredCryptoKey, *StoredCryptoKeyVersion)
// Caller must hold at least s.mu.RLock
// Returns (nil, nil) if not found
```

### verifyCRC32C (server-layer helper)

New server-layer helper for CRC32C input verification. Returns
codes.DataLoss (for Encrypt/Decrypt/Raw) or codes.InvalidArgument
per-method. Using DataLoss matches the real API for encrypted data
integrity checks; server methods use appropriate code per-context.

```
func verifyCRC32C(data []byte, provided *wrapperspb.Int64Value) error
// If provided is nil: return nil (no verification requested)
// Compute crc32c(data); compare to provided.Value
// On mismatch: return status.Error(codes.InvalidArgument, "request corrupted in transit")
// Located in internal/server/crc32c.go (extend existing file)
```



## Quality Gates

Level: standard

- **build**: `go build ./...` (required: true)
- **lint**: `go vet ./...` (required: true)
- **test**: `go test ./...` (required: true)

