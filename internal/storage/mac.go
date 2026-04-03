package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// MacSign computes an HMAC-SHA256 tag for the given data using the specified
// key version's HMAC key material.
func (s *Storage) MacSign(versionName string, data []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version, err := s.findVersion(versionName)
	if err != nil {
		return nil, err
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.HMACKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version does not contain HMAC key material: %s", versionName)}
	}

	h := hmac.New(sha256.New, version.HMACKey)
	h.Write(data)
	return h.Sum(nil), nil
}

// MacVerify verifies an HMAC-SHA256 tag against data using the specified
// key version's HMAC key material. Uses constant-time comparison.
func (s *Storage) MacVerify(versionName string, data []byte, mac []byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version, err := s.findVersion(versionName)
	if err != nil {
		return false, err
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return false, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.HMACKey == nil {
		return false, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version does not contain HMAC key material: %s", versionName)}
	}

	h := hmac.New(sha256.New, version.HMACKey)
	h.Write(data)
	expected := h.Sum(nil)
	return hmac.Equal(expected, mac), nil
}

// findVersion locates a StoredCryptoKeyVersion by its full resource name.
// Caller must hold s.mu (read or write lock).
func (s *Storage) findVersion(versionName string) (*StoredCryptoKeyVersion, error) {
	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				return version, nil
			}
		}
	}
	return nil, &ErrNotFound{Resource: versionName}
}
