// asymmetric.go provides asymmetric crypto operations (sign, decrypt, get public key)
// on key versions stored in the emulator's in-memory storage.
package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

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

// AsymmetricSign signs a digest using the asymmetric private key of the specified
// key version. It supports RSA PKCS1v15 and ECDSA signing depending on the
// key version's algorithm.
func (s *Storage) AsymmetricSign(versionName string, digest []byte, digestType string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version := s.findVersion(versionName)
	if version == nil {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.AsymmetricKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no asymmetric key material: %s", versionName)}
	}

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

// AsymmetricDecrypt decrypts ciphertext using the RSA private key of the specified
// key version. Only RSA OAEP decryption algorithms are supported.
func (s *Storage) AsymmetricDecrypt(versionName string, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version := s.findVersion(versionName)
	if version == nil {
		return nil, &ErrNotFound{Resource: versionName}
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

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
}

// GetPublicKey returns the PEM-encoded public key and algorithm for the specified
// asymmetric key version.
func (s *Storage) GetPublicKey(versionName string) (string, int32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version := s.findVersion(versionName)
	if version == nil {
		return "", 0, &ErrNotFound{Resource: versionName}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return "", 0, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.AsymmetricKey == nil {
		return "", 0, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no asymmetric key material: %s", versionName)}
	}

	return version.AsymmetricKey.PublicKeyPEM, int32(version.Algorithm), nil
}
