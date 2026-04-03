# KMS API Conformance Report

Generated: 2026-04-03

## Summary
- Methods implemented: 27/32
- Methods fully conformant: 3
- Methods with issues: 24
- Methods not implemented: 5 (DeleteCryptoKey, DeleteCryptoKeyVersion, GetRetiredResource, ListRetiredResources, Decapsulate [stub only])
- Total issues: 52 (22 critical, 30 minor)

## Method-by-Method Analysis

---

### CreateKeyRing
**Status**: CONFORMANT
**Issues**: None

Request validation is correct (parent and key_ring_id required). Returns ALREADY_EXISTS for duplicates. Response includes Name and CreateTime. The KeyRing proto only has Name and CreateTime fields, both populated correctly.

---

### GetKeyRing
**Status**: CONFORMANT
**Issues**: None

Validates name field. Returns NOT_FOUND correctly. Response fields (Name, CreateTime) are complete.

---

### ListKeyRings
**Status**: ISSUES
**Issues**:
- [minor] No filtering by parent prefix; returns all keyrings regardless of parent
  - Expected: Only keyrings whose name starts with `{parent}/keyRings/` are returned
  - Actual: All keyrings in storage are returned
  - Fix: Filter keyrings by prefix match on `parent`
- [minor] Pagination not implemented (page_size, page_token ignored)
  - Expected: Pagination support via page_size/page_token
  - Actual: All results returned in one response, NextPageToken always empty
  - Fix: Implement cursor-based pagination
- [minor] Filter and order_by fields ignored
  - Expected: Support for filter expressions and ordering
  - Actual: Ignored
  - Fix: Low priority for emulator; document as unsupported

---

### CreateCryptoKey
**Status**: ISSUES
**Issues**:
- [critical] Defaults UNSPECIFIED purpose to ENCRYPT_DECRYPT instead of rejecting
  - Expected: Per the API spec, purpose is required ("Immutable"). UNSPECIFIED should be rejected with INVALID_ARGUMENT
  - Actual: Falls back to ENCRYPT_DECRYPT silently
  - Fix: Return `status.Error(codes.InvalidArgument, "crypto_key.purpose is required")` when purpose is UNSPECIFIED
- [minor] Does not validate that algorithm in version_template matches the purpose
  - Expected: RSA_SIGN_* algorithms only valid with ASYMMETRIC_SIGN purpose, HMAC_* only with MAC, etc.
  - Actual: Any algorithm can be combined with any purpose
  - Fix: Add purpose-algorithm compatibility validation
- [minor] Does not honor skip_initial_version_creation from the request
  - Expected: If skip_initial_version_creation is true, do not create version 1 automatically
  - Actual: Always creates version 1
  - Fix: Check `req.SkipInitialVersionCreation` before auto-creating
- [minor] CryptoKey response missing DestroyScheduledDuration field (should default to 30 days)
  - Expected: destroy_scheduled_duration populated with default 30 days
  - Actual: Field is zero/nil
  - Fix: Set default duration on CryptoKey creation
- [minor] CryptoKeyVersion in Primary response missing ProtectionLevel and GenerateTime
  - Expected: ProtectionLevel=SOFTWARE, GenerateTime=CreateTime for instantly generated keys
  - Actual: Both fields are zero-valued
  - Fix: Populate these fields when constructing the CryptoKeyVersion proto

---

### GetCryptoKey
**Status**: ISSUES
**Issues**:
- [minor] CryptoKeyVersion in Primary response missing ProtectionLevel and GenerateTime
  - Expected: ProtectionLevel=SOFTWARE, GenerateTime set
  - Actual: Both zero-valued
  - Fix: Populate when building the proto response
- [minor] Scan-all-keyrings lookup is O(n) instead of parsing the resource name
  - Expected: Parse keyring name from the resource path for direct lookup
  - Actual: Iterates all keyrings
  - Fix: Parse resource name components for direct map access

---

### ListCryptoKeys
**Status**: ISSUES
**Issues**:
- [minor] CryptoKeyVersion in Primary missing ProtectionLevel and GenerateTime (same as GetCryptoKey)
- [minor] Pagination not implemented (page_size, page_token ignored)
- [minor] version_view parameter not respected; always returns full primary version
  - Expected: CRYPTO_KEY_VERSION_VIEW_UNSPECIFIED should omit algorithm
  - Actual: Always includes full version info

---

### UpdateCryptoKey
**Status**: ISSUES
**Issues**:
- [critical] update_mask field is completely ignored
  - Expected: Only fields specified in update_mask should be updated
  - Actual: Always replaces labels unconditionally; ignores mask paths
  - Fix: Parse update_mask.paths and only apply matching field updates
- [critical] Only labels can be updated; version_template, next_rotation_time, rotation_period, and destroy_scheduled_duration updates are not supported
  - Expected: All mutable CryptoKey fields can be updated
  - Actual: Only labels
  - Fix: Implement update logic for all mutable fields
- [minor] CryptoKeyVersion in Primary missing ProtectionLevel and GenerateTime

---

### CreateCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [critical] The crypto_key_version field from the request is completely ignored
  - Expected: `req.CryptoKeyVersion` can specify initial state and external_protection_level_options
  - Actual: The field is not read at all; only parent is used
  - Fix: Read `req.CryptoKeyVersion.State` if provided, and pass it through
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime
  - Expected: ProtectionLevel=SOFTWARE, GenerateTime=CreateTime
  - Actual: Zero-valued
  - Fix: Populate these fields

---

### GetCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime
  - Expected: ProtectionLevel=SOFTWARE, GenerateTime=CreateTime
  - Actual: Zero-valued
  - Fix: Populate when constructing the proto

---

### ListCryptoKeyVersions
**Status**: ISSUES
**Issues**:
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime
- [minor] Pagination not implemented
- [minor] view, filter, order_by parameters ignored

---

### UpdateCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [critical] update_mask field is completely ignored
  - Expected: Only fields specified in update_mask are applied
  - Actual: State is always updated regardless of mask
  - Fix: Parse update_mask and only update specified fields
- [critical] No state transition validation
  - Expected: Only valid transitions allowed: ENABLED<->DISABLED. Cannot set DESTROYED, DESTROY_SCHEDULED, etc. via UpdateCryptoKeyVersion
  - Actual: Any state can be set to any other state, including DESTROYED, PENDING_GENERATION, etc.
  - Fix: Validate that the target state is ENABLED or DISABLED, and that the current state allows the transition
- [critical] external_protection_level_options updates are not handled
  - Expected: Can update ExternalProtectionLevelOptions for EXTERNAL keys
  - Actual: Only state is updated
  - Fix: Add support for external protection level options updates
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime

---

### UpdateCryptoKeyPrimaryVersion
**Status**: ISSUES
**Issues**:
- [minor] CryptoKeyVersion in Primary response missing ProtectionLevel and GenerateTime
- [minor] Does not validate that key purpose supports a primary (only ENCRYPT_DECRYPT and MAC should have primary)
  - Expected: FAILED_PRECONDITION if key purpose is ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, or RAW_ENCRYPT_DECRYPT
  - Actual: Allows setting primary on any key purpose
  - Fix: Check key purpose before updating primary

---

### DestroyCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [critical] Does not set DestroyTime on the response
  - Expected: CryptoKeyVersion.destroy_time should be set to the scheduled destruction time (now + destroy_scheduled_duration)
  - Actual: destroy_time is nil
  - Fix: Set `DestroyTime: timestamppb.New(time.Now().Add(destroyScheduledDuration))`
- [critical] Rejects DESTROY_SCHEDULED versions (double-destroy), but the real API is idempotent for already DESTROY_SCHEDULED versions
  - Expected: Calling Destroy on an already DESTROY_SCHEDULED version returns the version as-is (idempotent)
  - Actual: Returns FAILED_PRECONDITION
  - Fix: If state is DESTROY_SCHEDULED, return the version without error
- [minor] Does not reject PENDING_GENERATION or PENDING_IMPORT states
  - Expected: Only ENABLED, DISABLED, and DESTROY_SCHEDULED versions can be destroyed
  - Actual: Accepts any state except DESTROYED and DESTROY_SCHEDULED
  - Fix: Add explicit state check for allowed source states
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime

---

### RestoreCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [minor] Restores to DISABLED state, which is correct per spec
- [minor] CryptoKeyVersion response missing ProtectionLevel and GenerateTime
- [minor] Does not clear destroy_time in response (but since destroy_time is never set, this is moot until DestroyCryptoKeyVersion is fixed)

---

### Encrypt
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose
  - Expected: Only ENCRYPT_DECRYPT keys should be usable; returns FAILED_PRECONDITION for wrong purpose
  - Actual: Any key with a symmetric key can encrypt (including RAW_ENCRYPT_DECRYPT keys)
  - Fix: Check `cryptoKey.Purpose == CryptoKey_ENCRYPT_DECRYPT` before encrypting
- [critical] Does not pass AdditionalAuthenticatedData to the encryption operation
  - Expected: AAD is incorporated into AES-GCM seal operation
  - Actual: `gcm.Seal(nonce, nonce, plaintext, nil)` -- AAD is always nil
  - Fix: Pass `req.AdditionalAuthenticatedData` through to `storage.Encrypt()` and use it as GCM AAD
- [critical] Response Name should be the CryptoKeyVersion name, not the CryptoKey name
  - Expected: `Name` field contains the full CryptoKeyVersion resource name that was used
  - Actual: Returns `req.Name` which is the CryptoKey name from the request
  - Fix: Resolve the primary version name and return that
- [critical] Does not verify CRC32C checksums on input when provided
  - Expected: If PlaintextCrc32C is set, server verifies CRC32C(plaintext) matches; returns INVALID_ARGUMENT on mismatch
  - Actual: CRC32C presence is only used to set the verified_ flag; actual verification is never performed
  - Fix: When CRC32C is provided, compute and compare; return INVALID_ARGUMENT on mismatch
- [minor] Does not validate plaintext size (max 64KiB for SOFTWARE keys)
  - Expected: INVALID_ARGUMENT if plaintext exceeds size limit
  - Actual: No size check
  - Fix: Add size validation

---

### Decrypt
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose
  - Expected: Only ENCRYPT_DECRYPT keys should be usable
  - Actual: Any key with a symmetric key can decrypt
  - Fix: Check purpose before decrypting
- [critical] Does not pass AdditionalAuthenticatedData to the decryption operation
  - Expected: AAD must match what was used during encryption
  - Actual: `gcm.Open(nil, nonce, ciphertext, nil)` -- AAD is always nil
  - Fix: Pass `req.AdditionalAuthenticatedData` through to `storage.Decrypt()`
- [critical] Does not verify CRC32C checksums on input when provided
  - Expected: If CiphertextCrc32C is set, verify integrity; INVALID_ARGUMENT on mismatch
  - Actual: CRC32C presence only used for verified_ flag
  - Fix: Compute and verify CRC32C when provided
- [minor] UsedPrimary is always true
  - Expected: Should be true only if the primary version was used for decryption
  - Actual: Always hardcoded to true, even when a non-primary version decrypted the data
  - Fix: Track which version succeeded and compare to primary

---

### AsymmetricSign
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is ASYMMETRIC_SIGN
  - Expected: Returns FAILED_PRECONDITION if key purpose is not ASYMMETRIC_SIGN
  - Actual: Only checks that the key version has asymmetric key material and algorithm matches sign type; does not check the parent CryptoKey purpose
  - Fix: Look up parent CryptoKey and verify purpose
- [critical] Does not support the `data` field (direct data signing without pre-hashing)
  - Expected: If `data` is provided (instead of `digest`), the server should hash the data using the algorithm's digest and then sign
  - Actual: Only `digest` is accepted; `data` is ignored. Returns INVALID_ARGUMENT "digest is required" even when data is provided
  - Fix: Accept data field, hash it with the appropriate algorithm, then sign
- [critical] Does not verify CRC32C checksums on input
  - Expected: Verify DigestCrc32C/DataCrc32C if provided
  - Actual: Only used for verified_ flag
  - Fix: Compute and verify
- [minor] Missing RSA-PSS signing algorithms (RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PSS_3072_SHA256, RSA_SIGN_PSS_4096_SHA256, RSA_SIGN_PSS_4096_SHA512)
  - Expected: PSS signing supported
  - Actual: Only PKCS1v15 signing implemented; PSS algorithms can be created but signing will fail
  - Fix: Add `rsa.SignPSS()` path when algorithm is RSA_SIGN_PSS_*
- [minor] Missing RSA raw signing algorithms (RSA_SIGN_RAW_PKCS1_2048, RSA_SIGN_RAW_PKCS1_3072, RSA_SIGN_RAW_PKCS1_4096)
  - Expected: Raw PKCS1 signing (no hash OID prefix)
  - Actual: Not supported in key generation or signing
  - Fix: Add generateKeyMaterial and signing support for raw RSA algorithms
- [minor] Missing EC_SIGN_SECP256K1_SHA256 and EC_SIGN_ED25519 algorithms
  - Expected: secp256k1 and Ed25519 signing supported
  - Actual: Only P-256 and P-384 supported
  - Fix: Add key generation and signing for these curves
- [minor] VerifiedDataCrc32C response field never set since data field is not handled
  - Expected: Set when DataCrc32C was provided on input
  - Actual: Always false

---

### AsymmetricDecrypt
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is ASYMMETRIC_DECRYPT
  - Expected: FAILED_PRECONDITION if purpose is not ASYMMETRIC_DECRYPT
  - Actual: Only checks algorithm type, not parent key purpose
  - Fix: Look up parent CryptoKey and verify purpose
- [critical] Always uses SHA-256 for OAEP hash, regardless of algorithm
  - Expected: RSA_DECRYPT_OAEP_*_SHA256 uses SHA-256, RSA_DECRYPT_OAEP_*_SHA512 uses SHA-512, RSA_DECRYPT_OAEP_*_SHA1 uses SHA-1
  - Actual: `rsa.DecryptOAEP(sha256.New(), ...)` is hardcoded for all algorithms
  - Fix: Select hash function based on `version.Algorithm`
- [critical] Does not verify CRC32C checksums on input
  - Expected: Verify CiphertextCrc32C if provided
  - Actual: Only used for verified_ flag
  - Fix: Compute and verify

---

### GetPublicKey
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is ASYMMETRIC_SIGN or ASYMMETRIC_DECRYPT
  - Expected: FAILED_PRECONDITION if purpose is not ASYMMETRIC_SIGN or ASYMMETRIC_DECRYPT
  - Actual: Only checks that asymmetric key material exists
  - Fix: Look up parent CryptoKey and verify purpose
- [minor] Does not check for DISABLED state (should only return public key for ENABLED versions, or DISABLED per some implementations)
  - Expected: GetPublicKey works for ENABLED and DISABLED versions (real GCP allows DISABLED)
  - Actual: Rejects DISABLED with FAILED_PRECONDITION
  - Fix: Allow DISABLED versions to return their public key

---

### MacSign
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is MAC
  - Expected: FAILED_PRECONDITION if purpose is not MAC
  - Actual: Only checks that HMAC key material exists
  - Fix: Look up parent CryptoKey and verify purpose
- [critical] Always uses HMAC-SHA256 regardless of algorithm
  - Expected: HMAC_SHA1 uses SHA-1, HMAC_SHA224 uses SHA-224, HMAC_SHA384 uses SHA-384, HMAC_SHA512 uses SHA-512
  - Actual: `hmac.New(sha256.New, ...)` hardcoded
  - Fix: Select hash function based on version.Algorithm
- [critical] Does not verify CRC32C checksums on input
  - Expected: Verify DataCrc32C if provided
  - Actual: Only used for verified_ flag
- [minor] Missing HMAC_SHA1, HMAC_SHA224, HMAC_SHA384, HMAC_SHA512 algorithm support in key generation
  - Expected: All HMAC algorithms supported
  - Actual: Only HMAC_SHA256 generates key material
  - Fix: Add key generation for all HMAC variants with appropriate key sizes

---

### MacVerify
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is MAC
  - Expected: FAILED_PRECONDITION if purpose is not MAC
  - Actual: Only checks that HMAC key material exists
- [critical] Always uses HMAC-SHA256 regardless of algorithm (same as MacSign)
- [critical] Does not verify CRC32C checksums on input
  - Expected: Verify DataCrc32C and MacCrc32C if provided
  - Actual: Only used for verified_ flags

---

### RawEncrypt
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is RAW_ENCRYPT_DECRYPT
  - Expected: FAILED_PRECONDITION if purpose is not RAW_ENCRYPT_DECRYPT
  - Actual: Only checks that symmetric key material exists
  - Fix: Look up parent CryptoKey and verify purpose
- [critical] Does not verify CRC32C checksums on input
  - Expected: Verify checksums if provided; INVALID_ARGUMENT on mismatch
  - Actual: Only used for verified_ flags
- [minor] Missing AES_128_GCM, AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR algorithm support
  - Expected: All raw encryption algorithms supported
  - Actual: Only AES_256_GCM
  - Fix: Add key generation and encrypt/decrypt for CBC and CTR modes
- [minor] Does not support customer-provided initialization vector
  - Expected: If InitializationVector is provided in the request, use it instead of generating one
  - Actual: Always generates a random nonce; ignores request IV
  - Fix: Check req.InitializationVector and use it if provided

---

### RawDecrypt
**Status**: ISSUES
**Issues**:
- [critical] Does not validate key purpose is RAW_ENCRYPT_DECRYPT
  - Expected: FAILED_PRECONDITION if purpose is not RAW_ENCRYPT_DECRYPT
  - Actual: Only checks that symmetric key material exists
- [critical] Does not verify CRC32C checksums on input
- [minor] Missing AES_128_GCM, AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR algorithm support
- [minor] TagLength field from request is ignored
  - Expected: If tag_length is specified and differs from default, validate/use it
  - Actual: Ignored; AES-GCM default tag length always used

---

### GenerateRandomBytes
**Status**: ISSUES
**Issues**:
- [minor] Minimum length is 1, but spec says minimum is 8 bytes
  - Expected: INVALID_ARGUMENT if length_bytes < 8
  - Actual: Accepts lengths 1-7
  - Fix: Change minimum from 1 to 8
- [minor] ProtectionLevel from request is ignored
  - Expected: Response could reflect the protection_level used (not critical for emulator)
  - Actual: Ignored

---

### CreateImportJob
**Status**: ISSUES
**Issues**:
- [minor] ImportJob response missing GenerateTime field
  - Expected: generate_time is set to the time the wrapping key was generated
  - Actual: Not set
  - Fix: Add GenerateTime to StoredImportJob and include in proto conversion
- [minor] Always generates RSA-2048 wrapping key regardless of ImportMethod
  - Expected: RSA_OAEP_3072_* methods should use 3072-bit key; RSA_OAEP_4096_* should use 4096-bit key
  - Actual: Always 2048-bit
  - Fix: Select key size based on ImportMethod

---

### GetImportJob
**Status**: CONFORMANT
**Issues**: None

Validates name, returns NOT_FOUND correctly, response fields are populated.

---

### ListImportJobs
**Status**: ISSUES
**Issues**:
- [minor] Pagination not implemented (page_size, page_token ignored)
- [minor] Filter and order_by ignored

---

### ImportCryptoKeyVersion
**Status**: ISSUES
**Issues**:
- [critical] Does not validate algorithm field is required
  - Expected: INVALID_ARGUMENT if algorithm is UNSPECIFIED
  - Actual: Accepts unspecified algorithm
  - Fix: Check that req.Algorithm is not CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED
- [minor] Does not support reimport into existing CryptoKeyVersion (req.CryptoKeyVersion field ignored)
  - Expected: If crypto_key_version is specified, import into that existing version
  - Actual: Always creates a new version
  - Fix: Add reimport path
- [minor] CryptoKeyVersion response missing ProtectionLevel, GenerateTime, ImportJob, ImportTime fields
  - Expected: ImportJob and ImportTime should be populated for imported versions
  - Actual: Only Name, State, CreateTime, Algorithm returned
  - Fix: Add these fields to the response
- [minor] Does not validate import job state expiry (time-based expiration)
  - Expected: Import jobs that have passed expire_time should be in EXPIRED state
  - Actual: Import job never transitions to EXPIRED

---

### DeleteCryptoKey
**Status**: NOT IMPLEMENTED
**Issues**:
- [critical] Method not implemented; falls through to UnimplementedKeyManagementServiceServer returning UNIMPLEMENTED
  - Expected: Permanently deletes a CryptoKey (returns long-running Operation)
  - Fix: Implement method with state validation (all versions must be DESTROYED)

---

### DeleteCryptoKeyVersion
**Status**: NOT IMPLEMENTED
**Issues**:
- [critical] Method not implemented; returns UNIMPLEMENTED
  - Expected: Permanently deletes a CryptoKeyVersion in DESTROYED/IMPORT_FAILED/GENERATION_FAILED state
  - Fix: Implement method

---

### GetRetiredResource
**Status**: NOT IMPLEMENTED
**Issues**:
- [minor] Method not implemented; returns UNIMPLEMENTED
  - Expected: Retrieves record of a deleted CryptoKey
  - Fix: Implement if DeleteCryptoKey is added

---

### ListRetiredResources
**Status**: NOT IMPLEMENTED
**Issues**:
- [minor] Method not implemented; returns UNIMPLEMENTED
  - Expected: Lists deleted CryptoKey records
  - Fix: Implement if DeleteCryptoKey is added

---

### Decapsulate
**Status**: NOT IMPLEMENTED (STUB)
**Issues**:
- [minor] Returns UNIMPLEMENTED; documented as a stub in the code
  - Expected: KEM decapsulation for ML-KEM/X-Wing keys
  - Fix: Implement when KEM support is needed

---

## Cross-Cutting Issues

### 1. [critical] CRC32C input verification is never performed
All methods that accept CRC32C checksums on input (Encrypt, Decrypt, AsymmetricSign, AsymmetricDecrypt, MacSign, MacVerify, RawEncrypt, RawDecrypt) set the `verified_*` response flags based on whether the CRC32C field was present in the request, but **never actually compute and verify** the checksum. The real API verifies the checksum and returns INVALID_ARGUMENT on mismatch. This means data corruption in transit would go undetected.

**Affects**: Encrypt, Decrypt, AsymmetricSign, AsymmetricDecrypt, MacSign, MacVerify, RawEncrypt, RawDecrypt (8 methods)

**Fix**: In each method, when a CRC32C field is non-nil, compute `crc32c(data)` and compare to the provided value. Return `codes.InvalidArgument` with message "request corrupted in transit" on mismatch.

### 2. [critical] Key purpose is never validated on crypto operations
No crypto operation method checks the parent CryptoKey's purpose before performing the operation. This means:
- A MAC key can be used for symmetric encryption
- An ASYMMETRIC_SIGN key's symmetric material (if any) could be used for Encrypt/Decrypt
- A RAW_ENCRYPT_DECRYPT key could be used for Encrypt/Decrypt (should require RawEncrypt/RawDecrypt)

**Affects**: Encrypt, Decrypt, AsymmetricSign, AsymmetricDecrypt, GetPublicKey, MacSign, MacVerify, RawEncrypt, RawDecrypt (9 methods)

**Fix**: Each operation method needs to resolve the parent CryptoKey and verify its purpose matches the expected purpose for that operation. This requires either:
- Passing the purpose along with the version in storage lookups, or
- Adding a `findKeyAndVersion()` helper that returns both the CryptoKey and version

### 3. [minor] CryptoKeyVersion responses consistently missing ProtectionLevel and GenerateTime
Every method that returns a CryptoKeyVersion proto only populates Name, State, CreateTime, and Algorithm. The ProtectionLevel field (should be SOFTWARE for all emulator keys) and GenerateTime field (should equal CreateTime for instantly generated keys) are always zero-valued.

**Affects**: All methods returning CryptoKeyVersion: CreateCryptoKey, GetCryptoKey, ListCryptoKeys, CreateCryptoKeyVersion, GetCryptoKeyVersion, ListCryptoKeyVersions, UpdateCryptoKeyVersion, UpdateCryptoKeyPrimaryVersion, DestroyCryptoKeyVersion, RestoreCryptoKeyVersion, ImportCryptoKeyVersion (11 methods)

**Fix**: Add `ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE` and `GenerateTime: timestamppb.New(version.CreateTime)` to every CryptoKeyVersion proto construction.

### 4. [minor] Pagination not implemented on any List method
ListKeyRings, ListCryptoKeys, ListCryptoKeyVersions, and ListImportJobs all ignore page_size and page_token. TotalSize is set but NextPageToken is always empty.

**Affects**: ListKeyRings, ListCryptoKeys, ListCryptoKeyVersions, ListImportJobs (4 methods)

### 5. [minor] ListKeyRings does not filter by parent
ListKeyRings returns all keyrings in storage regardless of the parent location. In the real API, only keyrings within the specified project/location are returned.

### 6. [minor] Algorithm support gaps
The following algorithms can be specified but will fail at key generation time:
- RSA_SIGN_PSS_* (4 algorithms) - key generates fine since RSA, but signing uses PKCS1v15 instead of PSS
- RSA_SIGN_RAW_PKCS1_* (3 algorithms) - not in generateKeyMaterial
- EC_SIGN_SECP256K1_SHA256 - not in generateKeyMaterial
- EC_SIGN_ED25519 - not in generateKeyMaterial
- HMAC_SHA1, HMAC_SHA224, HMAC_SHA384, HMAC_SHA512 - not in generateKeyMaterial
- AES_128_GCM, AES_128_CBC, AES_256_CBC, AES_128_CTR, AES_256_CTR - not in generateKeyMaterial
- All PQ_* and ML_KEM_*/KEM_XWING algorithms - not in generateKeyMaterial

### 7. [minor] AsymmetricDecrypt always uses SHA-256 for OAEP
The `AsymmetricDecrypt` storage function hardcodes `sha256.New()` for OAEP, but SHA-512 and SHA-1 variants exist (RSA_DECRYPT_OAEP_*_SHA512, RSA_DECRYPT_OAEP_*_SHA1). Data encrypted with the correct hash on a real KMS would fail to decrypt here.

### 8. [minor] Encrypt/Decrypt ignores AdditionalAuthenticatedData
Both `storage.Encrypt()` and `storage.Decrypt()` pass `nil` as the AAD parameter to AES-GCM. This means:
- Data encrypted with AAD on a real KMS cannot be decrypted by the emulator
- Data encrypted with the emulator cannot be decrypted if AAD is later provided

---

## Recommended Fix Priority

1. **[critical]** Encrypt/Decrypt: Pass AdditionalAuthenticatedData through to AES-GCM operations - data loss/corruption risk
2. **[critical]** All crypto ops: Add key purpose validation - wrong key type produces unexpected behavior
3. **[critical]** All crypto ops: Implement CRC32C input verification - data corruption goes undetected
4. **[critical]** Encrypt response: Return CryptoKeyVersion name, not CryptoKey name
5. **[critical]** AsymmetricDecrypt: Use correct OAEP hash based on algorithm - decryption failures for SHA-512/SHA-1 keys
6. **[critical]** UpdateCryptoKeyVersion: Add state transition validation - allows invalid states
7. **[critical]** UpdateCryptoKey: Respect update_mask field - applies all changes regardless of mask
8. **[critical]** DestroyCryptoKeyVersion: Set destroy_time on response; make idempotent for DESTROY_SCHEDULED
9. **[critical]** CreateCryptoKey: Reject UNSPECIFIED purpose instead of defaulting
10. **[critical]** CreateCryptoKeyVersion: Read crypto_key_version field from request
11. **[critical]** MacSign/MacVerify: Select hash function based on algorithm, not hardcoded SHA-256
12. **[critical]** ImportCryptoKeyVersion: Validate algorithm is not UNSPECIFIED
13. **[critical]** DeleteCryptoKey / DeleteCryptoKeyVersion: Implement methods
14. **[minor]** All CryptoKeyVersion responses: Add ProtectionLevel=SOFTWARE and GenerateTime fields
15. **[minor]** AsymmetricSign: Support `data` field (direct data signing)
16. **[minor]** AsymmetricSign: Add RSA-PSS signing support
17. **[minor]** All List methods: Implement pagination
18. **[minor]** ListKeyRings: Filter by parent prefix
19. **[minor]** Algorithm support: Add missing HMAC variants, raw encryption modes, EC curves
20. **[minor]** GenerateRandomBytes: Change minimum from 1 to 8 bytes per spec
21. **[minor]** CreateImportJob: Match wrapping key size to ImportMethod
22. **[minor]** CreateCryptoKey: Honor skip_initial_version_creation
23. **[minor]** CreateCryptoKey: Validate algorithm-purpose compatibility
24. **[minor]** Decrypt: Track which version decrypted and set UsedPrimary correctly
25. **[minor]** GetPublicKey: Allow DISABLED versions to return public key
26. **[minor]** ImportCryptoKeyVersion: Populate ImportJob/ImportTime in response
27. **[minor]** RawEncrypt: Support customer-provided initialization vector
28. **[minor]** RawDecrypt: Respect TagLength field
