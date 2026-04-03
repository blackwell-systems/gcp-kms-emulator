---
saw_name: [SAW:wave2:agent-E] ## Agent E -- Wire Everything: Shared File Modifications
---

# Agent E Brief - Wave 2

**IMPL Doc:** /Users/dayna.blackwell/code/gcp-kms-emulator/docs/IMPL/IMPL-kms-full-rpc-coverage.yaml

## Files Owned

- `internal/storage/storage.go`
- `internal/server/server.go`
- `internal/authz/permissions.go`


## Task

## Agent E -- Wire Everything: Shared File Modifications

Modify storage.go, server.go, and permissions.go to connect Wave 1 work.

### 1. `internal/storage/storage.go`

a) Add to StoredCryptoKeyVersion struct (after SymmetricKey line 81):
   AsymmetricKey *AsymmetricKeyMaterial
   HMACKey       []byte

b) Add to StoredKeyRing struct (after CryptoKeys line 60):
   ImportJobs map[string]*StoredImportJob

c) In CreateKeyRing (~line 104), add to StoredKeyRing literal:
   ImportJobs: make(map[string]*StoredImportJob),

d) In CreateCryptoKey (~line 172), replace symmetric key generation with:
   symKey, asymKey, hmacKey, err := generateKeyMaterial(algorithm)
   Then set all three fields on StoredCryptoKeyVersion.

e) Same in CreateCryptoKeyVersion (~line 394).

f) Add RestoreCryptoKeyVersion:
   func (s *Storage) RestoreCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error)
   Find version, validate DESTROY_SCHEDULED, set DISABLED, return proto.

### 2. `internal/server/server.go`

a) DELETE all 14 stub methods (lines ~414-468) returning Unimplemented.

b) ADD RestoreCryptoKeyVersion server method:
   requireField, checkPermission("RestoreCryptoKeyVersion"), s.storage.RestoreCryptoKeyVersion

c) ADD Decapsulate minimal stub:
   requireField, return Unimplemented("KEM not yet supported")

### 3. `internal/authz/permissions.go`

Add to OperationPermissions:
- GenerateRandomBytes: cloudkms.locations.generateRandomBytes, Self
- RawEncrypt: cloudkms.cryptoKeyVersions.useToEncrypt, Self
- RawDecrypt: cloudkms.cryptoKeyVersions.useToDecrypt, Self
- CreateImportJob: cloudkms.importJobs.create, Parent
- GetImportJob: cloudkms.importJobs.get, Self
- ListImportJobs: cloudkms.importJobs.list, Parent
- ImportCryptoKeyVersion: cloudkms.cryptoKeyVersions.create, Parent
- Decapsulate: cloudkms.cryptoKeyVersions.useToDecapsulate, Self

### Verification gate
go build ./... && go vet ./... && go test -v ./...

### Constraints
- Do NOT modify Wave 1 files
- Existing tests must continue to pass
- RestoreCryptoKeyVersion sets state to DISABLED (not ENABLED)
- Decapsulate remains a stub with TODO
- Remove unused io import from storage.go if needed



## Interface Contracts

### StoredCryptoKeyVersion new fields

Add AsymmetricKey and HMACKey fields to StoredCryptoKeyVersion in storage.go.
Populated during key creation based on algorithm.


```
AsymmetricKey *AsymmetricKeyMaterial
HMACKey       []byte

```

### StoredKeyRing.ImportJobs field

Add ImportJobs map to StoredKeyRing for import job storage.

```
ImportJobs map[string]*StoredImportJob

```

### Storage.AsymmetricSign

Sign digest using asymmetric key version private key.

```
func (s *Storage) AsymmetricSign(versionName string, digest []byte, digestType string) ([]byte, error)

```

### Storage.AsymmetricDecrypt

Decrypt ciphertext using asymmetric RSA key version.

```
func (s *Storage) AsymmetricDecrypt(versionName string, ciphertext []byte) ([]byte, error)

```

### Storage.GetPublicKey

Return PEM-encoded public key for asymmetric key version.

```
func (s *Storage) GetPublicKey(versionName string) (string, int32, error)

```

### Storage.MacSign

Create HMAC tag for data using MAC key version.

```
func (s *Storage) MacSign(versionName string, data []byte) ([]byte, error)

```

### Storage.MacVerify

Verify HMAC tag against data using MAC key version.

```
func (s *Storage) MacVerify(versionName string, data []byte, mac []byte) (bool, error)

```

### Storage.RawEncrypt

AES-GCM encrypt without envelope wrapping.

```
func (s *Storage) RawEncrypt(versionName string, plaintext []byte, aad []byte) (ciphertext []byte, iv []byte, tagLen int32, err error)

```

### Storage.RawDecrypt

AES-GCM decrypt without envelope wrapping.

```
func (s *Storage) RawDecrypt(versionName string, ciphertext []byte, iv []byte, aad []byte) ([]byte, error)

```

### Storage.CreateImportJob

Create import job with RSA wrapping key.

```
func (s *Storage) CreateImportJob(keyringName, importJobID string, importMethod int32, protectionLevel int32) (*StoredImportJob, error)

```

### Storage.GetImportJob

Retrieve import job by name.

```
func (s *Storage) GetImportJob(name string) (*StoredImportJob, error)

```

### Storage.ListImportJobs

List import jobs in a keyring.

```
func (s *Storage) ListImportJobs(keyringName string) ([]*StoredImportJob, error)

```

### Storage.ImportCryptoKeyVersion

Import wrapped key material into a crypto key version.

```
func (s *Storage) ImportCryptoKeyVersion(keyName string, algorithm int32, importJobName string, wrappedKey []byte) (*StoredCryptoKeyVersion, error)

```

### Storage.GenerateRandomBytes

Generate cryptographically random bytes.

```
func (s *Storage) GenerateRandomBytes(length int32) ([]byte, error)

```

### Storage.RestoreCryptoKeyVersion

Restore DESTROY_SCHEDULED version to DISABLED.

```
func (s *Storage) RestoreCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error)

```

### generateKeyMaterial

Generate key material based on algorithm. Returns symmetric key, asymmetric
key material, and HMAC key (only one non-nil based on algorithm).
Lives in scaffold file internal/storage/keymaterial.go.


```
func generateKeyMaterial(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (symmetricKey []byte, asymKey *AsymmetricKeyMaterial, hmacKey []byte, err error)

```



## Quality Gates

Level: standard

- **build**: `go build ./...` (required: true)
- **lint**: `go vet ./...` (required: true)
- **test**: `go test -v ./...` (required: true)

