// asymmetric.go provides asymmetric crypto operations (sign, decrypt, get public key)
// on key versions stored in the emulator's in-memory storage.
package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// findVersion locates a StoredCryptoKeyVersion by its full resource name.
// Caller must hold at least s.mu.RLock.
func (s *Storage) findVersion(versionName string) *StoredCryptoKeyVersion {
	for _, keyring := range s.keyrings {
		for _, cryptoKey := range keyring.CryptoKeys {
			if version, exists := cryptoKey.Versions[versionName]; exists {
				return version
			}
		}
	}
	return nil
}

// findKeyAndVersion locates both the parent StoredCryptoKey and the
// StoredCryptoKeyVersion for a given version resource name.
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

// hashFromDigestType maps a digest type string to a crypto.Hash constant.
func hashFromDigestType(digestType string) (crypto.Hash, error) {
	switch digestType {
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported digest type: %s", digestType)
	}
}

// isRSASignAlgorithm returns true if the algorithm is an RSA signing algorithm.
func isRSASignAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch alg {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return true
	default:
		return false
	}
}

// isECSignAlgorithm returns true if the algorithm is an EC signing algorithm.
func isECSignAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch alg {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return true
	default:
		return false
	}
}

// isRSADecryptAlgorithm returns true if the algorithm is an RSA decryption algorithm.
func isRSADecryptAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch alg {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		return true
	default:
		return false
	}
}

// hashForSignAlgorithm returns the crypto.Hash and digest type string for a
// signing algorithm. Used to hash rawData when the data field is provided.
func hashForSignAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.Hash, string, error) {
	switch alg {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return crypto.SHA256, "SHA256", nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384, "SHA384", nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return crypto.SHA512, "SHA512", nil
	default:
		return 0, "", fmt.Errorf("no hash defined for sign algorithm %v", alg)
	}
}

// oaepHashFromAlgorithm returns the hash.Hash to use for RSA OAEP operations
// based on the key version algorithm.
func oaepHashFromAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) hash.Hash {
	name := alg.String()
	switch {
	case containsSubstring(name, "SHA1"):
		return sha1.New()
	case containsSubstring(name, "SHA512"):
		return sha512.New()
	default:
		// SHA256 is the default for OAEP algorithms
		return sha256.New()
	}
}

// AsymmetricSign signs a digest (or raw data) using the asymmetric private key of
// the specified key version. It supports RSA PKCS1v15 and ECDSA signing depending
// on the key version's algorithm.
//
// If rawData is non-nil, the data is hashed internally using the algorithm's hash
// function and used as the digest. Otherwise, digest and digestType are used directly.
func (s *Storage) AsymmetricSign(versionName string, digest []byte, digestType string, rawData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cryptoKey, version := s.findKeyAndVersion(versionName)
	if version == nil {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, &ErrFailedPrecondition{Message: "key purpose must be ASYMMETRIC_SIGN"}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.AsymmetricKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no asymmetric key material: %s", versionName)}
	}

	// If rawData is provided, hash it internally and derive digest/digestType.
	if rawData != nil {
		h, dt, err := hashForSignAlgorithm(version.Algorithm)
		if err != nil {
			return nil, &ErrFailedPrecondition{Message: err.Error()}
		}
		hasher := h.New()
		hasher.Write(rawData)
		digest = hasher.Sum(nil)
		digestType = dt
	}

	switch version.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		sig, err := signSecp256k1(version.AsymmetricKey.PrivateKeyDER, digest)
		if err != nil {
			return nil, &ErrFailedPrecondition{Message: err.Error()}
		}
		return sig, nil
	default:
		// For RSA and stdlib EC signing, convert digestType to crypto.Hash.
		hashType, err := hashFromDigestType(digestType)
		if err != nil {
			return nil, &ErrFailedPrecondition{Message: err.Error()}
		}

		key, err := x509.ParsePKCS8PrivateKey(version.AsymmetricKey.PrivateKeyDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		switch typedKey := key.(type) {
		case *rsa.PrivateKey:
			if !isRSASignAlgorithm(version.Algorithm) {
				return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("algorithm %s is not an RSA signing algorithm", version.Algorithm)}
			}
			return rsa.SignPKCS1v15(rand.Reader, typedKey, hashType, digest)
		case *ecdsa.PrivateKey:
			if !isECSignAlgorithm(version.Algorithm) {
				return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("algorithm %s is not an EC signing algorithm", version.Algorithm)}
			}
			return ecdsa.SignASN1(rand.Reader, typedKey, digest)
		default:
			return nil, &ErrFailedPrecondition{Message: "unsupported key type for signing"}
		}
	}
}

// AsymmetricDecrypt decrypts ciphertext using the RSA private key of the specified
// key version. Only RSA OAEP decryption algorithms are supported. The hash function
// is selected based on the version's algorithm.
func (s *Storage) AsymmetricDecrypt(versionName string, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cryptoKey, version := s.findKeyAndVersion(versionName)
	if version == nil {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		return nil, &ErrFailedPrecondition{Message: "key purpose must be ASYMMETRIC_DECRYPT"}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.AsymmetricKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no asymmetric key material: %s", versionName)}
	}

	if !isRSADecryptAlgorithm(version.Algorithm) {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("algorithm %s is not an RSA decryption algorithm", version.Algorithm)}
	}

	key, err := x509.ParsePKCS8PrivateKey(version.AsymmetricKey.PrivateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, &ErrFailedPrecondition{Message: "key is not an RSA private key"}
	}

	return rsa.DecryptOAEP(oaepHashFromAlgorithm(version.Algorithm), rand.Reader, rsaKey, ciphertext, nil)
}

// GetPublicKey returns the PEM-encoded public key and algorithm for the specified
// asymmetric key version. DISABLED versions are allowed to return their public key.
func (s *Storage) GetPublicKey(versionName string) (string, int32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cryptoKey, version := s.findKeyAndVersion(versionName)
	if version == nil {
		return "", 0, &ErrNotFound{Resource: versionName}
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN && cryptoKey.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		return "", 0, &ErrFailedPrecondition{Message: "key purpose must be ASYMMETRIC_SIGN or ASYMMETRIC_DECRYPT"}
	}

	if version.AsymmetricKey == nil {
		return "", 0, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no asymmetric key material: %s", versionName)}
	}

	return version.AsymmetricKey.PublicKeyPEM, int32(version.Algorithm), nil
}
