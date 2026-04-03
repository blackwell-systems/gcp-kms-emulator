// Package storage provides thread-safe in-memory storage for KMS resources.
//
// This package implements the storage layer for the GCP KMS emulator, providing
// a complete in-memory representation of keyrings, crypto keys, and key versions
// with real AES-256-GCM encryption.
//
// All storage operations are thread-safe using sync.RWMutex, allowing concurrent
// access from multiple gRPC or REST API handlers.
//
// # Key Features
//
// Real cryptographic operations using Go's crypto/aes and crypto/cipher packages.
// Automatic key version management with auto-incrementing version IDs. Version-aware
// decryption that tries all enabled versions. State management for version lifecycle
// (ENABLED, DISABLED, DESTROY_SCHEDULED, DESTROYED).
//
// # Storage Structure
//
// Storage maintains a hierarchical structure:
//   - KeyRings: Top-level containers identified by name
//   - CryptoKeys: Keys within keyrings with purpose and metadata
//   - CryptoKeyVersions: Individual versions with symmetric keys and state
//
// # Thread Safety
//
// All public methods use appropriate read or write locks. Read operations
// (Get, List) use RLock for concurrent reads. Write operations (Create, Update,
// Delete) use Lock for exclusive access.
//
// # Encryption
//
// Encrypt operations use the primary version's symmetric key. Decrypt operations
// try all enabled versions to support data encrypted with older keys. Each version
// has a unique 256-bit AES key generated with crypto/rand.
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Storage manages in-memory KMS resources
type Storage struct {
	mu       sync.RWMutex
	keyrings map[string]*StoredKeyRing
}

// StoredKeyRing represents a keyring and its crypto keys
type StoredKeyRing struct {
	Name       string
	CreateTime time.Time
	CryptoKeys map[string]*StoredCryptoKey
	ImportJobs map[string]*StoredImportJob
}

// StoredCryptoKey represents a crypto key and its versions
type StoredCryptoKey struct {
	Name                            string
	CreateTime                      time.Time
	Purpose                         kmspb.CryptoKey_CryptoKeyPurpose
	PrimaryVersion                  string
	Versions                        map[string]*StoredCryptoKeyVersion
	NextVersionID                   int64
	VersionTemplate                 *kmspb.CryptoKeyVersionTemplate
	Labels                          map[string]string
	RotationPeriod                  *durationpb.Duration
	NextRotationTime                *timestamppb.Timestamp
	DestroyScheduledDuration        *durationpb.Duration
	DestroyScheduledDurationDefault *durationpb.Duration
}

// StoredCryptoKeyVersion represents a single version of a crypto key
type StoredCryptoKeyVersion struct {
	Name          string
	State         kmspb.CryptoKeyVersion_CryptoKeyVersionState
	CreateTime    time.Time
	Algorithm     kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	SymmetricKey  []byte                 // AES key for symmetric encryption
	AsymmetricKey *AsymmetricKeyMaterial // RSA/EC key material for asymmetric operations
	HMACKey       []byte                 // HMAC key for MAC operations
	DestroyTime   time.Time              // Time when version will be destroyed (DESTROY_SCHEDULED state)
}

// NewStorage creates a new storage instance
func NewStorage() *Storage {
	return &Storage{
		keyrings: make(map[string]*StoredKeyRing),
	}
}

// CreateKeyRing creates a new keyring
func (s *Storage) CreateKeyRing(name string) (*kmspb.KeyRing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keyrings[name]; exists {
		return nil, &ErrAlreadyExists{Resource: name}
	}

	now := time.Now()
	keyring := &StoredKeyRing{
		Name:       name,
		CreateTime: now,
		CryptoKeys: make(map[string]*StoredCryptoKey),
		ImportJobs: make(map[string]*StoredImportJob),
	}

	s.keyrings[name] = keyring

	return &kmspb.KeyRing{
		Name:       name,
		CreateTime: timestamppb.New(now),
	}, nil
}

// GetKeyRing retrieves a keyring
func (s *Storage) GetKeyRing(name string) (*kmspb.KeyRing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyring, exists := s.keyrings[name]
	if !exists {
		return nil, &ErrNotFound{Resource: name}
	}

	return &kmspb.KeyRing{
		Name:       keyring.Name,
		CreateTime: timestamppb.New(keyring.CreateTime),
	}, nil
}

// ListKeyRings lists all keyrings under a given parent location
func (s *Storage) ListKeyRings(parent string) ([]*kmspb.KeyRing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prefix := parent + "/keyRings/"
	var keyrings []*kmspb.KeyRing
	for _, kr := range s.keyrings {
		if strings.HasPrefix(kr.Name, prefix) {
			keyrings = append(keyrings, &kmspb.KeyRing{
				Name:       kr.Name,
				CreateTime: timestamppb.New(kr.CreateTime),
			})
		}
	}

	return keyrings, nil
}

// CreateCryptoKey creates a new crypto key
func (s *Storage) CreateCryptoKey(keyringName, keyID string, purpose kmspb.CryptoKey_CryptoKeyPurpose, versionTemplate *kmspb.CryptoKeyVersionTemplate, labels map[string]string) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject unspecified purpose
	if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
		return nil, &ErrFailedPrecondition{Message: "crypto_key.purpose is required"}
	}

	keyring, exists := s.keyrings[keyringName]
	if !exists {
		return nil, &ErrNotFound{Resource: keyringName}
	}

	keyName := fmt.Sprintf("%s/cryptoKeys/%s", keyringName, keyID)
	if _, exists := keyring.CryptoKeys[keyName]; exists {
		return nil, &ErrAlreadyExists{Resource: keyName}
	}

	now := time.Now()

	// Create first version automatically
	versionName := fmt.Sprintf("%s/cryptoKeyVersions/1", keyName)
	algorithm := kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	if versionTemplate != nil && versionTemplate.Algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		algorithm = versionTemplate.Algorithm
	}

	// Generate key material based on algorithm
	symmetricKey, asymKey, hmacKey, err := generateKeyMaterial(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key material: %w", err)
	}

	version := &StoredCryptoKeyVersion{
		Name:          versionName,
		State:         kmspb.CryptoKeyVersion_ENABLED,
		CreateTime:    now,
		Algorithm:     algorithm,
		SymmetricKey:  symmetricKey,
		AsymmetricKey: asymKey,
		HMACKey:       hmacKey,
	}

	defaultDestroyDuration := durationpb.New(30 * 24 * time.Hour)
	cryptoKey := &StoredCryptoKey{
		Name:                            keyName,
		CreateTime:                      now,
		Purpose:                         purpose,
		PrimaryVersion:                  versionName,
		Versions:                        map[string]*StoredCryptoKeyVersion{versionName: version},
		NextVersionID:                   2,
		VersionTemplate:                 versionTemplate,
		Labels:                          labels,
		DestroyScheduledDuration:        defaultDestroyDuration,
		DestroyScheduledDurationDefault: defaultDestroyDuration,
	}

	keyring.CryptoKeys[keyName] = cryptoKey

	return &kmspb.CryptoKey{
		Name:       keyName,
		CreateTime: timestamppb.New(now),
		Purpose:    purpose,
		Primary: &kmspb.CryptoKeyVersion{
			Name:            versionName,
			State:           kmspb.CryptoKeyVersion_ENABLED,
			CreateTime:      timestamppb.New(now),
			Algorithm:       algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			GenerateTime:    timestamppb.New(now),
		},
		VersionTemplate:          versionTemplate,
		Labels:                   labels,
		DestroyScheduledDuration: defaultDestroyDuration,
	}, nil
}

// GetCryptoKey retrieves a crypto key
func (s *Storage) GetCryptoKey(name string) (*kmspb.CryptoKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, keyring := range s.keyrings {
		if cryptoKey, exists := keyring.CryptoKeys[name]; exists {
			primary := cryptoKey.Versions[cryptoKey.PrimaryVersion]
			return storedKeyToProto(cryptoKey, primary), nil
		}
	}

	return nil, &ErrNotFound{Resource: name}
}

// Encrypt encrypts plaintext using a crypto key
func (s *Storage) Encrypt(keyName string, plaintext []byte, aad []byte) (ciphertext []byte, versionName string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, "", &ErrNotFound{Resource: keyName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, "", &ErrFailedPrecondition{Message: "key purpose must be ENCRYPT_DECRYPT"}
	}

	primaryVersion := cryptoKey.Versions[cryptoKey.PrimaryVersion]
	if primaryVersion == nil {
		return nil, "", fmt.Errorf("primary version not found")
	}

	if primaryVersion.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, "", fmt.Errorf("primary version is not enabled")
	}

	// AES-GCM encryption
	block, err := aes.NewCipher(primaryVersion.SymmetricKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return ct, cryptoKey.PrimaryVersion, nil
}

// Decrypt decrypts ciphertext using a crypto key
func (s *Storage) Decrypt(keyName string, ciphertext []byte, aad []byte) (plaintext []byte, usedVersionName string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, "", &ErrNotFound{Resource: keyName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, "", &ErrFailedPrecondition{Message: "key purpose must be ENCRYPT_DECRYPT"}
	}

	// Try all versions (in case it was encrypted with a non-primary version)
	for _, version := range cryptoKey.Versions {
		if version.State != kmspb.CryptoKeyVersion_ENABLED {
			continue
		}

		pt, decErr := s.decryptWithVersion(version, ciphertext, aad)
		if decErr == nil {
			return pt, version.Name, nil
		}
	}

	return nil, "", fmt.Errorf("failed to decrypt with any key version")
}

func (s *Storage) decryptWithVersion(version *StoredCryptoKeyVersion, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(version.SymmetricKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// ListCryptoKeys lists all crypto keys in a keyring
func (s *Storage) ListCryptoKeys(keyringName string) ([]*kmspb.CryptoKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyring, exists := s.keyrings[keyringName]
	if !exists {
		return nil, &ErrNotFound{Resource: keyringName}
	}

	var cryptoKeys []*kmspb.CryptoKey
	for _, ck := range keyring.CryptoKeys {
		primary := ck.Versions[ck.PrimaryVersion]
		cryptoKeys = append(cryptoKeys, storedKeyToProto(ck, primary))
	}

	return cryptoKeys, nil
}

// CreateCryptoKeyVersion creates a new version for an existing crypto key
func (s *Storage) CreateCryptoKeyVersion(keyName string, req *kmspb.CryptoKeyVersion) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, &ErrNotFound{Resource: keyName}
	}

	now := time.Now()
	versionID := cryptoKey.NextVersionID
	versionName := fmt.Sprintf("%s/cryptoKeyVersions/%d", keyName, versionID)

	algorithm := kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	if cryptoKey.VersionTemplate != nil && cryptoKey.VersionTemplate.Algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		algorithm = cryptoKey.VersionTemplate.Algorithm
	}
	// If req specifies an algorithm, override the template algorithm
	if req != nil && req.Algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		algorithm = req.Algorithm
	}

	symmetricKey, asymKey, hmacKey, err := generateKeyMaterial(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key material: %w", err)
	}

	version := &StoredCryptoKeyVersion{
		Name:          versionName,
		State:         kmspb.CryptoKeyVersion_ENABLED,
		CreateTime:    now,
		Algorithm:     algorithm,
		SymmetricKey:  symmetricKey,
		AsymmetricKey: asymKey,
		HMACKey:       hmacKey,
	}

	cryptoKey.Versions[versionName] = version
	cryptoKey.NextVersionID++

	return &kmspb.CryptoKeyVersion{
		Name:            versionName,
		State:           kmspb.CryptoKeyVersion_ENABLED,
		CreateTime:      timestamppb.New(now),
		Algorithm:       algorithm,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		GenerateTime:    timestamppb.New(now),
	}, nil
}

// UpdateCryptoKeyPrimaryVersion sets a new primary version for a crypto key
func (s *Storage) UpdateCryptoKeyPrimaryVersion(keyName, versionName string) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, &ErrNotFound{Resource: keyName}
	}

	version, exists := cryptoKey.Versions[versionName]
	if !exists {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	cryptoKey.PrimaryVersion = versionName

	primary := cryptoKey.Versions[cryptoKey.PrimaryVersion]
	return storedKeyToProto(cryptoKey, primary), nil
}

// GetCryptoKeyVersion retrieves a specific crypto key version
func (s *Storage) GetCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				return &kmspb.CryptoKeyVersion{
					Name:            version.Name,
					State:           version.State,
					CreateTime:      timestamppb.New(version.CreateTime),
					Algorithm:       version.Algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
					GenerateTime:    timestamppb.New(version.CreateTime),
				}, nil
			}
		}
	}

	return nil, &ErrNotFound{Resource: versionName}
}

// ListCryptoKeyVersions lists all versions of a crypto key
func (s *Storage) ListCryptoKeyVersions(keyName string) ([]*kmspb.CryptoKeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, &ErrNotFound{Resource: keyName}
	}

	var versions []*kmspb.CryptoKeyVersion
	for _, version := range cryptoKey.Versions {
		versions = append(versions, &kmspb.CryptoKeyVersion{
			Name:            version.Name,
			State:           version.State,
			CreateTime:      timestamppb.New(version.CreateTime),
			Algorithm:       version.Algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			GenerateTime:    timestamppb.New(version.CreateTime),
		})
	}

	return versions, nil
}

// UpdateCryptoKeyVersion updates the state of a crypto key version
func (s *Storage) UpdateCryptoKeyVersion(versionName string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate mask contains "state"
	if mask != nil {
		hasState := false
		for _, p := range mask.Paths {
			if p == "state" {
				hasState = true
				break
			}
		}
		if !hasState {
			return nil, &ErrFailedPrecondition{Message: "update_mask must contain state"}
		}
	}

	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				// Validate current state: must be ENABLED or DISABLED
				if version.State != kmspb.CryptoKeyVersion_ENABLED && version.State != kmspb.CryptoKeyVersion_DISABLED {
					return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("cannot update version in state %v; must be ENABLED or DISABLED", version.State)}
				}
				// Validate target state: must be ENABLED or DISABLED
				if state != kmspb.CryptoKeyVersion_ENABLED && state != kmspb.CryptoKeyVersion_DISABLED {
					return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("target state %v is not permitted; must be ENABLED or DISABLED", state)}
				}
				version.State = state
				return &kmspb.CryptoKeyVersion{
					Name:            version.Name,
					State:           version.State,
					CreateTime:      timestamppb.New(version.CreateTime),
					Algorithm:       version.Algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
					GenerateTime:    timestamppb.New(version.CreateTime),
				}, nil
			}
		}
	}

	return nil, &ErrNotFound{Resource: versionName}
}

// DestroyCryptoKeyVersion schedules a crypto key version for destruction
func (s *Storage) DestroyCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				if version.State == kmspb.CryptoKeyVersion_DESTROYED {
					return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version already destroyed: %s", versionName)}
				}

				// Idempotent: if already DESTROY_SCHEDULED, return as-is
				if version.State == kmspb.CryptoKeyVersion_DESTROY_SCHEDULED {
					return &kmspb.CryptoKeyVersion{
						Name:            version.Name,
						State:           version.State,
						CreateTime:      timestamppb.New(version.CreateTime),
						Algorithm:       version.Algorithm,
						ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
						GenerateTime:    timestamppb.New(version.CreateTime),
						DestroyTime:     timestamppb.New(version.DestroyTime),
					}, nil
				}

				// Schedule destruction
				version.DestroyTime = time.Now().Add(30 * 24 * time.Hour)
				version.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
				return &kmspb.CryptoKeyVersion{
					Name:            version.Name,
					State:           version.State,
					CreateTime:      timestamppb.New(version.CreateTime),
					Algorithm:       version.Algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
					GenerateTime:    timestamppb.New(version.CreateTime),
					DestroyTime:     timestamppb.New(version.DestroyTime),
				}, nil
			}
		}
	}

	return nil, &ErrNotFound{Resource: versionName}
}

// RestoreCryptoKeyVersion restores a DESTROY_SCHEDULED version to DISABLED state
func (s *Storage) RestoreCryptoKeyVersion(versionName string) (*kmspb.CryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				if version.State != kmspb.CryptoKeyVersion_DESTROY_SCHEDULED {
					return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not scheduled for destruction: %s", versionName)}
				}

				version.State = kmspb.CryptoKeyVersion_DISABLED
				return &kmspb.CryptoKeyVersion{
					Name:            version.Name,
					State:           version.State,
					CreateTime:      timestamppb.New(version.CreateTime),
					Algorithm:       version.Algorithm,
					ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
					GenerateTime:    timestamppb.New(version.CreateTime),
				}, nil
			}
		}
	}

	return nil, &ErrNotFound{Resource: versionName}
}

// UpdateCryptoKey updates metadata of a crypto key using a field mask
func (s *Storage) UpdateCryptoKey(keyName string, key *kmspb.CryptoKey, mask *fieldmaskpb.FieldMask) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cryptoKey *StoredCryptoKey
	for _, keyring := range s.keyrings {
		if ck, exists := keyring.CryptoKeys[keyName]; exists {
			cryptoKey = ck
			break
		}
	}

	if cryptoKey == nil {
		return nil, &ErrNotFound{Resource: keyName}
	}

	if mask != nil {
		for _, path := range mask.Paths {
			switch path {
			case "labels":
				cryptoKey.Labels = key.Labels
			case "rotation_period":
				cryptoKey.RotationPeriod = key.GetRotationPeriod()
			case "next_rotation_time":
				cryptoKey.NextRotationTime = key.NextRotationTime
			case "version_template":
				cryptoKey.VersionTemplate = key.VersionTemplate
			case "destroy_scheduled_duration":
				cryptoKey.DestroyScheduledDuration = key.DestroyScheduledDuration
			// Unrecognised paths are silently ignored
			}
		}
	}

	primary := cryptoKey.Versions[cryptoKey.PrimaryVersion]
	return storedKeyToProto(cryptoKey, primary), nil
}

// findKeyAndVersion returns both the parent StoredCryptoKey and the
// StoredCryptoKeyVersion for a version resource name.
// Caller must hold at least s.mu.RLock.
// Returns (nil, nil) if not found.
func (s *Storage) findKeyAndVersion(versionName string) (*StoredCryptoKey, *StoredCryptoKeyVersion) {
	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				return cryptoKey, version
			}
		}
	}
	return nil, nil
}

// storedKeyToProto converts a StoredCryptoKey to its proto representation.
// primary is the primary StoredCryptoKeyVersion to embed.
func storedKeyToProto(ck *StoredCryptoKey, primary *StoredCryptoKeyVersion) *kmspb.CryptoKey {
	proto := &kmspb.CryptoKey{
		Name:       ck.Name,
		CreateTime: timestamppb.New(ck.CreateTime),
		Purpose:    ck.Purpose,
		Primary: &kmspb.CryptoKeyVersion{
			Name:            primary.Name,
			State:           primary.State,
			CreateTime:      timestamppb.New(primary.CreateTime),
			Algorithm:       primary.Algorithm,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			GenerateTime:    timestamppb.New(primary.CreateTime),
		},
		VersionTemplate:          ck.VersionTemplate,
		Labels:                   ck.Labels,
		NextRotationTime:         ck.NextRotationTime,
		DestroyScheduledDuration: ck.DestroyScheduledDuration,
	}
	if ck.RotationPeriod != nil {
		proto.RotationSchedule = &kmspb.CryptoKey_RotationPeriod{
			RotationPeriod: ck.RotationPeriod,
		}
	}
	return proto
}

// Clear removes all stored data (for testing)
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyrings = make(map[string]*StoredKeyRing)
}
