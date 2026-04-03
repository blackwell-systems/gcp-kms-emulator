package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// CreateImportJob creates a new import job with an RSA-2048 wrapping keypair.
func (s *Storage) CreateImportJob(keyringName, importJobID string, importMethod int32, protectionLevel int32) (*StoredImportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyring, exists := s.keyrings[keyringName]
	if !exists {
		return nil, &ErrNotFound{Resource: keyringName}
	}

	name := fmt.Sprintf("%s/importJobs/%s", keyringName, importJobID)

	// Lazy-init the ImportJobs map
	if keyring.ImportJobs == nil {
		keyring.ImportJobs = make(map[string]*StoredImportJob)
	}

	if _, exists := keyring.ImportJobs[name]; exists {
		return nil, &ErrAlreadyExists{Resource: name}
	}

	// Generate RSA-2048 wrapping keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrapping key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	now := time.Now()
	importJob := &StoredImportJob{
		Name:            name,
		State:           kmspb.ImportJob_ACTIVE,
		ImportMethod:    kmspb.ImportJob_ImportMethod(importMethod),
		ProtectionLevel: kmspb.ProtectionLevel(protectionLevel),
		CreateTime:      now,
		ExpireTime:      now.Add(72 * time.Hour),
		PublicKeyPEM:    pubPEM,
		PrivateKey:      privateKey,
	}

	keyring.ImportJobs[name] = importJob
	return importJob, nil
}

// GetImportJob retrieves an import job by its full resource name.
func (s *Storage) GetImportJob(name string) (*StoredImportJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, keyring := range s.keyrings {
		if keyring.ImportJobs != nil {
			if ij, exists := keyring.ImportJobs[name]; exists {
				return ij, nil
			}
		}
	}

	return nil, &ErrNotFound{Resource: name}
}

// ListImportJobs lists all import jobs in a keyring with pagination.
func (s *Storage) ListImportJobs(keyringName string, pageSize int32, pageToken string) ([]*StoredImportJob, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyring, exists := s.keyrings[keyringName]
	if !exists {
		return nil, "", &ErrNotFound{Resource: keyringName}
	}

	var all []*StoredImportJob
	for _, ij := range keyring.ImportJobs {
		all = append(all, ij)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	page, next, err := paginatePage(all, pageToken, pageSize)
	return page, next, err
}

// ImportCryptoKeyVersion imports a wrapped key into a new crypto key version.
// The wrappedKey is decrypted using the import job's RSA-OAEP private key.
func (s *Storage) ImportCryptoKeyVersion(keyName string, algorithm int32, importJobName string, wrappedKey []byte) (*StoredCryptoKeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the crypto key
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

	// Find the import job
	var importJob *StoredImportJob
	for _, keyring := range s.keyrings {
		if keyring.ImportJobs != nil {
			if ij, exists := keyring.ImportJobs[importJobName]; exists {
				importJob = ij
				break
			}
		}
	}
	if importJob == nil {
		return nil, &ErrNotFound{Resource: importJobName}
	}

	// Validate import job is active
	if importJob.State != kmspb.ImportJob_ACTIVE {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("import job %s is not active", importJobName)}
	}

	// Validate algorithm is specified
	if kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(algorithm) == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		return nil, &ErrFailedPrecondition{Message: "algorithm is required"}
	}

	// Unwrap the key using RSA-OAEP with SHA-256
	unwrappedKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, importJob.PrivateKey, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	// Create a new version with the unwrapped key
	now := time.Now()
	versionID := cryptoKey.NextVersionID
	versionName := fmt.Sprintf("%s/cryptoKeyVersions/%d", keyName, versionID)

	version := &StoredCryptoKeyVersion{
		Name:         versionName,
		State:        kmspb.CryptoKeyVersion_ENABLED,
		CreateTime:   now,
		Algorithm:    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(algorithm),
		SymmetricKey: unwrappedKey,
	}

	cryptoKey.Versions[versionName] = version
	cryptoKey.NextVersionID++

	return version, nil
}
