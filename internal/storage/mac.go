package storage

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// hmacHashFuncFromAlgorithm returns the hash constructor for the given HMAC algorithm.
// Falls back to sha256.New for unrecognised algorithms (should not be reached in practice).
func hmacHashFuncFromAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) func() hash.Hash {
	switch alg {
	case kmspb.CryptoKeyVersion_HMAC_SHA1:
		return sha1.New
	case kmspb.CryptoKeyVersion_HMAC_SHA224:
		return sha256.New224
	case kmspb.CryptoKeyVersion_HMAC_SHA256:
		return sha256.New
	case kmspb.CryptoKeyVersion_HMAC_SHA384:
		return sha512.New384
	case kmspb.CryptoKeyVersion_HMAC_SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

// MacSign computes an HMAC tag for the given data using the specified
// key version's HMAC key material. The hash function is selected based
// on the key version's algorithm.
func (s *Storage) MacSign(versionName string, data []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cryptoKey, version := s.findKeyAndVersion(versionName)
	if cryptoKey == nil {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_MAC {
		return nil, &ErrFailedPrecondition{Message: "key purpose must be MAC"}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.HMACKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version does not contain HMAC key material: %s", versionName)}
	}

	h := hmac.New(hmacHashFuncFromAlgorithm(version.Algorithm), version.HMACKey)
	h.Write(data)
	return h.Sum(nil), nil
}

// MacVerify verifies an HMAC tag against data using the specified
// key version's HMAC key material. Uses constant-time comparison.
// The hash function is selected based on the key version's algorithm.
func (s *Storage) MacVerify(versionName string, data []byte, mac []byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cryptoKey, version := s.findKeyAndVersion(versionName)
	if cryptoKey == nil {
		return false, &ErrNotFound{Resource: versionName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_MAC {
		return false, &ErrFailedPrecondition{Message: "key purpose must be MAC"}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return false, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.HMACKey == nil {
		return false, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version does not contain HMAC key material: %s", versionName)}
	}

	h := hmac.New(hmacHashFuncFromAlgorithm(version.Algorithm), version.HMACKey)
	h.Write(data)
	expected := h.Sum(nil)
	return hmac.Equal(expected, mac), nil
}
