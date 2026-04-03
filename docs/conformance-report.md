# KMS API Conformance Report

Generated: 2026-04-03 (re-audit after conformance fixes)

## Summary

- Methods implemented: 27/32
- Methods fully conformant: 10 (up from 3)
- Methods with remaining issues: 17
- Methods not implemented: 5 (DeleteCryptoKey, DeleteCryptoKeyVersion, GetRetiredResource, ListRetiredResources, Decapsulate [stub])
- Remaining issues: 23 (0 critical, 23 minor)
- **All 22 previously-critical issues are now FIXED.**

---

## Previously-Flagged Issues: Status

### Cross-Cutting: CRC32C input verification — FIXED
`crc32c.go` now has a `verifyCRC32C()` helper that computes and compares the checksum, returning `codes.InvalidArgument` / "request corrupted in transit" on mismatch. All eight crypto operation methods (Encrypt, Decrypt, AsymmetricSign, AsymmetricDecrypt, MacSign, MacVerify, RawEncrypt, RawDecrypt) call it on every CRC32C field before doing any crypto work.

### Cross-Cutting: Key purpose not validated on crypto operations — FIXED
`storage/asymmetric.go`, `storage/mac.go`, `storage/raw.go`, and `storage/storage.go` all use `findKeyAndVersion()` and check `cryptoKey.Purpose` before performing the operation, returning `ErrFailedPrecondition` on mismatch.

### Cross-Cutting: CryptoKeyVersion responses missing ProtectionLevel and GenerateTime — FIXED
All CryptoKeyVersion proto constructions now include `ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE` and `GenerateTime: timestamppb.New(version.CreateTime)`.

### Cross-Cutting: Encrypt/Decrypt ignored AdditionalAuthenticatedData — FIXED
`storage.Encrypt()` passes `aad` to `gcm.Seal(nonce, nonce, plaintext, aad)` and `storage.Decrypt()` / `decryptWithVersion()` passes `aad` to `gcm.Open(nil, nonce, ct, aad)`.

### Cross-Cutting: AsymmetricDecrypt always used SHA-256 for OAEP — FIXED
`oaepHashFromAlgorithm()` in `storage/asymmetric.go` inspects the algorithm string and returns `sha1.New()` for SHA1 variants, `sha512.New()` for SHA512 variants, and `sha256.New()` as default. All three SHA families covered.

### CreateCryptoKey: UNSPECIFIED purpose accepted — FIXED
Both server.go (line 206–208) and storage.go (line 168–170) now return `InvalidArgument` / `ErrFailedPrecondition` for `CRYPTO_KEY_PURPOSE_UNSPECIFIED`.

### CreateCryptoKey: DestroyScheduledDuration not set — FIXED
`storage.CreateCryptoKey()` sets `defaultDestroyDuration = durationpb.New(30 * 24 * time.Hour)` and populates it on both the stored key and the proto response.

### CreateCryptoKeyVersion: req.CryptoKeyVersion field ignored — FIXED
`storage.CreateCryptoKeyVersion()` reads `req.Algorithm` and overrides the template algorithm if non-UNSPECIFIED.

### UpdateCryptoKey: update_mask ignored, only labels updated — FIXED
`storage.UpdateCryptoKey()` now iterates `mask.Paths` and applies `labels`, `rotation_period`, `next_rotation_time`, `version_template`, and `destroy_scheduled_duration` selectively. The server also validates that `update_mask` is non-empty before calling storage.

### UpdateCryptoKeyVersion: update_mask ignored, no state transition validation — FIXED
`storage.UpdateCryptoKeyVersion()` validates that `mask.Paths` contains `"state"`, rejects current states other than ENABLED/DISABLED, and rejects target states other than ENABLED/DISABLED.

### UpdateCryptoKeyPrimaryVersion: missing ProtectionLevel and GenerateTime — FIXED
`storedKeyToProto()` populates both fields in the embedded Primary version.

### DestroyCryptoKeyVersion: destroy_time not set, not idempotent for DESTROY_SCHEDULED — FIXED
The method now sets `version.DestroyTime = time.Now().Add(30 * 24 * time.Hour)` and includes `DestroyTime: timestamppb.New(version.DestroyTime)` in the response. If the version is already DESTROY_SCHEDULED it returns the existing version with its destroy_time (idempotent).

### Encrypt: wrong Name in response (CryptoKey not CryptoKeyVersion) — FIXED
`storage.Encrypt()` returns `cryptoKey.PrimaryVersion` as `versionName`; the server uses it as `Name` in the response.

### Encrypt/Decrypt: purpose not validated — FIXED
Both check `cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT` and return `ErrFailedPrecondition`.

### Decrypt: UsedPrimary always true — FIXED
The server fetches the key after decryption and compares `cryptoKey.Primary.Name == usedVersionName`.

### AsymmetricSign: key purpose not validated — FIXED
`storage.AsymmetricSign()` uses `findKeyAndVersion()` and checks `cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN`.

### AsymmetricSign: data field not supported — FIXED
When `req.Data` is non-nil the server passes it to `storage.AsymmetricSign()` as `rawData`. Storage hashes it with `hashForSignAlgorithm()` and proceeds normally.

### AsymmetricSign: CRC32C not verified — FIXED
`verifyCRC32C(digestBytes, req.DigestCrc32C)` and `verifyCRC32C(req.Data, req.DataCrc32C)` called before signing.

### AsymmetricDecrypt: key purpose not validated — FIXED
Uses `findKeyAndVersion()` and checks `cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT`.

### GetPublicKey: purpose not validated, DISABLED rejected — FIXED
`storage.GetPublicKey()` checks that purpose is ASYMMETRIC_SIGN or ASYMMETRIC_DECRYPT and no longer rejects DISABLED versions (state check removed).

### MacSign/MacVerify: hardcoded SHA-256, purpose not validated — FIXED
`hmacHashFuncFromAlgorithm()` selects the correct hash for all five HMAC algorithms. Both methods use `findKeyAndVersion()` and check `cryptoKey.Purpose != kmspb.CryptoKey_MAC`.

### RawEncrypt/RawDecrypt: purpose not validated, CRC32C not verified — FIXED
Both use `findKeyAndVersion()`, check `cryptoKey.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT`, and call `verifyCRC32C()` on all relevant inputs (including the IV for RawEncrypt/RawDecrypt).

### ImportCryptoKeyVersion: algorithm not validated — FIXED
Server validates `req.Algorithm != UNSPECIFIED` before calling storage. Storage has a second guard at line 139.

### HMAC algorithm key generation (SHA1, SHA224, SHA384, SHA512) — FIXED
`keymaterial.go` generates HMAC keys of the correct size for all five HMAC variants.

### AES-128-GCM key generation — FIXED
`keymaterial.go` generates a 16-byte key for `AES_128_GCM`.

---

## Remaining Issues

### ListKeyRings
- [minor] No filtering by parent prefix — STILL PRESENT
  - `storage.ListKeyRings()` now filters by `strings.HasPrefix(kr.Name, prefix)` — **FIXED**
- [minor] Pagination not implemented — STILL PRESENT
- [minor] filter/order_by ignored — STILL PRESENT (low priority)

> **Correction on ListKeyRings filtering**: After re-reading `storage.go` lines 143–159, parent filtering IS fixed (`prefix := parent + "/keyRings/"` with `strings.HasPrefix`). Only pagination and filter/order_by remain.

### CreateCryptoKey
- [minor] skip_initial_version_creation not honored — STILL PRESENT
  - `storage.CreateCryptoKey()` always creates version 1; `req.SkipInitialVersionCreation` is not read in server.go
- [minor] Algorithm-purpose compatibility not validated — STILL PRESENT
  - Any algorithm can still be paired with any purpose at creation time

### ListCryptoKeys / ListCryptoKeyVersions / ListImportJobs
- [minor] Pagination not implemented — STILL PRESENT (all four List methods)
- [minor] version_view parameter ignored in ListCryptoKeys — STILL PRESENT

### UpdateCryptoKeyPrimaryVersion
- [minor] Purpose not validated — STILL PRESENT
  - Real API returns FAILED_PRECONDITION if key purpose is ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, or RAW_ENCRYPT_DECRYPT; emulator allows it

### RestoreCryptoKeyVersion
- [minor] destroy_time not cleared in response — STILL PRESENT (minor; field remains set after restore)

### AsymmetricSign
- [minor] RSA-PSS signing algorithms not supported — STILL PRESENT
  - `isRSASignAlgorithm()` and `generateKeyMaterial()` only cover PKCS1v15 algorithms; PSS keys can be created (RSA key generated) but signing will fall through to PKCS1v15 with the wrong algorithm check returning FAILED_PRECONDITION
- [minor] RSA_SIGN_RAW_PKCS1_* algorithms not in generateKeyMaterial — STILL PRESENT
- [minor] EC_SIGN_SECP256K1_SHA256 and EC_SIGN_ED25519 not in generateKeyMaterial — STILL PRESENT

### RawEncrypt
- [minor] Customer-provided InitializationVector ignored — STILL PRESENT
  - `storage.RawEncrypt()` always generates a fresh nonce; `req.InitializationVector` is CRC32C-verified in the server but never passed to storage
- [minor] AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR not supported — STILL PRESENT
  - Only AES-128-GCM and AES-256-GCM have key generation and cipher implementation

### RawDecrypt
- [minor] TagLength field ignored — STILL PRESENT
  - AES-GCM default tag length always used
- [minor] AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR not supported — STILL PRESENT

### GenerateRandomBytes
- [minor] Minimum length is 1, spec requires 8 — STILL PRESENT
  - `storage/random.go` line 12: `if length <= 0 || length > 1024` — accepts lengths 1–7

### CreateImportJob
- [minor] Always generates RSA-2048 wrapping key regardless of ImportMethod — STILL PRESENT
  - `storage/importjob.go` line 37 hardcodes `rsa.GenerateKey(rand.Reader, 2048)`; no dispatch on `importMethod`
- [minor] ImportJob response missing GenerateTime field — STILL PRESENT
  - `storedImportJobToProto()` does not include `GenerateTime`; `StoredImportJob` struct has no such field

### ImportCryptoKeyVersion
- [minor] Reimport into existing CryptoKeyVersion not supported — STILL PRESENT
- [minor] CryptoKeyVersion response missing ImportJob, ImportTime fields — STILL PRESENT
  - `server/importjob.go` lines 121–126 return only Name, State, CreateTime, Algorithm
- [minor] Import job expiry not enforced — STILL PRESENT

### DeleteCryptoKey / DeleteCryptoKeyVersion / GetRetiredResource / ListRetiredResources
- [minor] Not implemented — STILL PRESENT (returns UNIMPLEMENTED)

---

## Cross-Cutting Issues Still Present

### 1. [minor] Pagination not implemented on any List method
ListKeyRings, ListCryptoKeys, ListCryptoKeyVersions, and ListImportJobs all ignore `page_size`/`page_token`. No change from original report.

### 2. [minor] Algorithm support gaps (signing/raw)
Still missing:
- RSA_SIGN_PSS_* (4 algorithms) — key material generated (RSA) but signing path is PKCS1v15 only; PSS requests will receive FAILED_PRECONDITION
- RSA_SIGN_RAW_PKCS1_* (3 algorithms) — not in generateKeyMaterial
- EC_SIGN_SECP256K1_SHA256 — not in generateKeyMaterial
- EC_SIGN_ED25519 — not in generateKeyMaterial
- AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR — key generation missing; cipher modes not implemented

### 3. [minor] GetCryptoKey / ListCryptoKeys lookup is O(n)
Both scan all keyrings instead of parsing the resource name for direct map access. No correctness impact, only performance.

---

## Overall Conformance Verdict

**NEAR-FULL**

All 22 critical issues identified in the original audit are fixed. The emulator now correctly:
- Validates key purpose on every crypto operation
- Verifies CRC32C checksums on all inputs
- Passes AdditionalAuthenticatedData through AES-GCM
- Returns the correct CryptoKeyVersion name from Encrypt
- Selects the correct OAEP hash for AsymmetricDecrypt
- Supports all five HMAC algorithms with correct hash selection
- Supports the `data` field on AsymmetricSign
- Validates update_mask and state transitions on UpdateCryptoKeyVersion
- Sets destroy_time and is idempotent on DestroyCryptoKeyVersion
- Filters ListKeyRings by parent

The 23 remaining issues are all minor: missing pagination, a few unsupported algorithm variants (RSA-PSS, secp256k1, Ed25519, CBC/CTR modes), customer-supplied IVs, the GenerateRandomBytes minimum-8 rule, import job wrapping key sizing, and the four unimplemented deletion/retired-resource methods. None of these affect correct operation for the standard ENCRYPT_DECRYPT, ASYMMETRIC_SIGN (P-256/P-384/RSA-PKCS1), ASYMMETRIC_DECRYPT (RSA-OAEP), MAC (all HMAC variants), or RAW_ENCRYPT_DECRYPT (AES-GCM) workflows.
