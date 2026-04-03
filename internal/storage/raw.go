package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// RawEncrypt performs AES-GCM encryption using a specific key version's symmetric key,
// without envelope wrapping. Returns the sealed ciphertext, the initialization vector (nonce),
// the GCM authentication tag length, and any error.
func (s *Storage) RawEncrypt(versionName string, plaintext []byte, aad []byte) (ciphertext []byte, iv []byte, tagLen int32, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version := s.findVersion(versionName)
	if version == nil {
		return nil, nil, 0, &ErrNotFound{Resource: versionName}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, nil, 0, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.SymmetricKey == nil {
		return nil, nil, 0, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no symmetric key: %s", versionName)}
	}

	block, err := aes.NewCipher(version.SymmetricKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return sealed, nonce, int32(gcm.Overhead()), nil
}

// RawDecrypt performs AES-GCM decryption using a specific key version's symmetric key,
// without envelope wrapping.
func (s *Storage) RawDecrypt(versionName string, ciphertext []byte, iv []byte, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version := s.findVersion(versionName)
	if version == nil {
		return nil, &ErrNotFound{Resource: versionName}
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version is not enabled: %s", versionName)}
	}

	if version.SymmetricKey == nil {
		return nil, &ErrFailedPrecondition{Message: fmt.Sprintf("crypto key version has no symmetric key: %s", versionName)}
	}

	block, err := aes.NewCipher(version.SymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
