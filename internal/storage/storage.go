// Package storage provides in-memory storage for KMS resources
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
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
}

// StoredCryptoKey represents a crypto key and its versions
type StoredCryptoKey struct {
	Name            string
	CreateTime      time.Time
	Purpose         kmspb.CryptoKey_CryptoKeyPurpose
	PrimaryVersion  string
	Versions        map[string]*StoredCryptoKeyVersion
	NextVersionID   int64
	VersionTemplate *kmspb.CryptoKeyVersionTemplate
	Labels          map[string]string
}

// StoredCryptoKeyVersion represents a single version of a crypto key
type StoredCryptoKeyVersion struct {
	Name         string
	State        kmspb.CryptoKeyVersion_CryptoKeyVersionState
	CreateTime   time.Time
	Algorithm    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	SymmetricKey []byte // AES key for symmetric encryption
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
		return nil, fmt.Errorf("keyring already exists: %s", name)
	}

	now := time.Now()
	keyring := &StoredKeyRing{
		Name:       name,
		CreateTime: now,
		CryptoKeys: make(map[string]*StoredCryptoKey),
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
		return nil, fmt.Errorf("keyring not found: %s", name)
	}

	return &kmspb.KeyRing{
		Name:       keyring.Name,
		CreateTime: timestamppb.New(keyring.CreateTime),
	}, nil
}

// ListKeyRings lists all keyrings in a location
func (s *Storage) ListKeyRings(parent string) ([]*kmspb.KeyRing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keyrings []*kmspb.KeyRing
	for _, kr := range s.keyrings {
		keyrings = append(keyrings, &kmspb.KeyRing{
			Name:       kr.Name,
			CreateTime: timestamppb.New(kr.CreateTime),
		})
	}

	return keyrings, nil
}

// CreateCryptoKey creates a new crypto key
func (s *Storage) CreateCryptoKey(keyringName, keyID string, purpose kmspb.CryptoKey_CryptoKeyPurpose, versionTemplate *kmspb.CryptoKeyVersionTemplate, labels map[string]string) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyring, exists := s.keyrings[keyringName]
	if !exists {
		return nil, fmt.Errorf("keyring not found: %s", keyringName)
	}

	keyName := fmt.Sprintf("%s/cryptoKeys/%s", keyringName, keyID)
	if _, exists := keyring.CryptoKeys[keyName]; exists {
		return nil, fmt.Errorf("crypto key already exists: %s", keyName)
	}

	now := time.Now()

	// Create first version automatically
	versionName := fmt.Sprintf("%s/cryptoKeyVersions/1", keyName)
	algorithm := kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	if versionTemplate != nil && versionTemplate.Algorithm != kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		algorithm = versionTemplate.Algorithm
	}

	// Generate symmetric key for encryption
	symmetricKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	version := &StoredCryptoKeyVersion{
		Name:         versionName,
		State:        kmspb.CryptoKeyVersion_ENABLED,
		CreateTime:   now,
		Algorithm:    algorithm,
		SymmetricKey: symmetricKey,
	}

	cryptoKey := &StoredCryptoKey{
		Name:            keyName,
		CreateTime:      now,
		Purpose:         purpose,
		PrimaryVersion:  versionName,
		Versions:        map[string]*StoredCryptoKeyVersion{versionName: version},
		NextVersionID:   2,
		VersionTemplate: versionTemplate,
		Labels:          labels,
	}

	keyring.CryptoKeys[keyName] = cryptoKey

	return &kmspb.CryptoKey{
		Name:       keyName,
		CreateTime: timestamppb.New(now),
		Purpose:    purpose,
		Primary: &kmspb.CryptoKeyVersion{
			Name:       versionName,
			State:      kmspb.CryptoKeyVersion_ENABLED,
			CreateTime: timestamppb.New(now),
			Algorithm:  algorithm,
		},
		VersionTemplate: versionTemplate,
		Labels:          labels,
	}, nil
}

// GetCryptoKey retrieves a crypto key
func (s *Storage) GetCryptoKey(name string) (*kmspb.CryptoKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, keyring := range s.keyrings {
		if cryptoKey, exists := keyring.CryptoKeys[name]; exists {
			primary := cryptoKey.Versions[cryptoKey.PrimaryVersion]
			return &kmspb.CryptoKey{
				Name:       cryptoKey.Name,
				CreateTime: timestamppb.New(cryptoKey.CreateTime),
				Purpose:    cryptoKey.Purpose,
				Primary: &kmspb.CryptoKeyVersion{
					Name:       primary.Name,
					State:      primary.State,
					CreateTime: timestamppb.New(primary.CreateTime),
					Algorithm:  primary.Algorithm,
				},
				VersionTemplate: cryptoKey.VersionTemplate,
				Labels:          cryptoKey.Labels,
			}, nil
		}
	}

	return nil, fmt.Errorf("crypto key not found: %s", name)
}

// Encrypt encrypts plaintext using a crypto key
func (s *Storage) Encrypt(keyName string, plaintext []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("crypto key not found: %s", keyName)
	}

	primaryVersion := cryptoKey.Versions[cryptoKey.PrimaryVersion]
	if primaryVersion == nil {
		return nil, fmt.Errorf("primary version not found")
	}

	if primaryVersion.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("primary version is not enabled")
	}

	// AES-GCM encryption
	block, err := aes.NewCipher(primaryVersion.SymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using a crypto key
func (s *Storage) Decrypt(keyName string, ciphertext []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("crypto key not found: %s", keyName)
	}

	// Try all versions (in case it was encrypted with a non-primary version)
	for _, version := range cryptoKey.Versions {
		if version.State != kmspb.CryptoKeyVersion_ENABLED {
			continue
		}

		plaintext, err := s.decryptWithVersion(version, ciphertext)
		if err == nil {
			return plaintext, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt with any key version")
}

func (s *Storage) decryptWithVersion(version *StoredCryptoKeyVersion, ciphertext []byte) ([]byte, error) {
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

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Clear removes all stored data (for testing)
func (s *Storage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyrings = make(map[string]*StoredKeyRing)
}
