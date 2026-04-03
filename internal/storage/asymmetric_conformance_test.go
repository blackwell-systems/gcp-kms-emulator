package storage

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

const conformanceKeyRing = "projects/test/locations/global/keyRings/conformance-ring"

// createConformanceKey creates a keyring (idempotent) and a crypto key with the
// given purpose and algorithm. Returns the first version's resource name.
func createConformanceKey(t *testing.T, s *Storage, keyID string, purpose kmspb.CryptoKey_CryptoKeyPurpose, alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) string {
	t.Helper()

	if _, err := s.CreateKeyRing(conformanceKeyRing); err != nil {
		if _, ok := err.(*ErrAlreadyExists); !ok {
			t.Fatalf("CreateKeyRing: %v", err)
		}
	}

	tmpl := &kmspb.CryptoKeyVersionTemplate{Algorithm: alg}
	ck, err := s.CreateCryptoKey(conformanceKeyRing, keyID, purpose, tmpl, nil)
	if err != nil {
		t.Fatalf("CreateCryptoKey(%q): %v", keyID, err)
	}
	return ck.Primary.Name
}

// decodePublicKey decodes a PEM-encoded public key and returns it as an interface{}.
func decodePublicKey(t *testing.T, pemStr string) interface{} {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("failed to PEM-decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	return pub
}

// TestAsymmetricSign_PurposeCheck ensures AsymmetricSign rejects keys whose purpose
// is not ASYMMETRIC_SIGN.
func TestAsymmetricSign_PurposeCheck(t *testing.T) {
	s := NewStorage()
	// ENCRYPT_DECRYPT key with a symmetric algorithm — no asymmetric material,
	// and wrong purpose.
	versionName := createConformanceKey(t, s, "enc-key",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION)

	_, err := s.AsymmetricSign(versionName, []byte("fakedigest"), "SHA256", nil)
	if err == nil {
		t.Fatal("expected ErrFailedPrecondition for wrong purpose, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Fatalf("expected *ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestAsymmetricSign_DataField verifies that passing rawData causes AsymmetricSign
// to hash the data internally and produce a valid EC signature.
func TestAsymmetricSign_DataField(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "sign-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)

	rawData := []byte("hello, world — raw payload")
	sig, err := s.AsymmetricSign(versionName, nil, "", rawData)
	if err != nil {
		t.Fatalf("AsymmetricSign(rawData): %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// Retrieve the public key and verify.
	pemStr, _, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	pub := decodePublicKey(t, pemStr)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	// The implementation hashes with SHA-256 for EC_SIGN_P256_SHA256.
	digest := sha256.Sum256(rawData)
	if !ecdsa.VerifyASN1(ecPub, digest[:], sig) {
		t.Error("signature verification failed")
	}
}

// TestAsymmetricDecrypt_PurposeCheck ensures AsymmetricDecrypt rejects keys whose
// purpose is not ASYMMETRIC_DECRYPT.
func TestAsymmetricDecrypt_PurposeCheck(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "sign-only-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256)

	_, err := s.AsymmetricDecrypt(versionName, []byte("fakeciphertext"))
	if err == nil {
		t.Fatal("expected ErrFailedPrecondition for wrong purpose, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Fatalf("expected *ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestAsymmetricDecrypt_SHA1Hash verifies that a key using RSA_DECRYPT_OAEP_2048_SHA1
// correctly decrypts data that was encrypted with SHA-1 OAEP.
func TestAsymmetricDecrypt_SHA1Hash(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "rsa-sha1-key",
		kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1)

	// Retrieve public key for external encryption.
	pemStr, _, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	pub := decodePublicKey(t, pemStr)
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	plaintext := []byte("secret message for SHA1 OAEP")
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP(sha1): %v", err)
	}

	decrypted, err := s.AsymmetricDecrypt(versionName, ciphertext)
	if err != nil {
		t.Fatalf("AsymmetricDecrypt(SHA1): %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestAsymmetricDecrypt_SHA512Hash verifies that a key using RSA_DECRYPT_OAEP_4096_SHA512
// correctly decrypts data that was encrypted with SHA-512 OAEP.
func TestAsymmetricDecrypt_SHA512Hash(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "rsa-sha512-key",
		kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512)

	pemStr, _, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	pub := decodePublicKey(t, pemStr)
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	plaintext := []byte("secret message for SHA512 OAEP")
	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, rsaPub, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP(sha512): %v", err)
	}

	decrypted, err := s.AsymmetricDecrypt(versionName, ciphertext)
	if err != nil {
		t.Fatalf("AsymmetricDecrypt(SHA512): %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestGetPublicKey_AllowDisabled verifies that GetPublicKey succeeds even when
// the key version is DISABLED.
func TestGetPublicKey_AllowDisabled(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "disabled-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)

	// Directly set the version state to DISABLED via the internal map.
	s.mu.Lock()
	for _, keyring := range s.keyrings {
		for _, ck := range keyring.CryptoKeys {
			if v, ok := ck.Versions[versionName]; ok {
				v.State = kmspb.CryptoKeyVersion_DISABLED
			}
		}
	}
	s.mu.Unlock()

	pemStr, alg, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey on DISABLED version: %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string")
	}
	if alg == 0 {
		t.Error("expected non-zero algorithm")
	}
}

// TestGetPublicKey_PurposeCheck verifies that GetPublicKey rejects keys whose
// purpose is neither ASYMMETRIC_SIGN nor ASYMMETRIC_DECRYPT.
func TestGetPublicKey_PurposeCheck(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "enc-dec-key",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION)

	_, _, err := s.GetPublicKey(versionName)
	if err == nil {
		t.Fatal("expected ErrFailedPrecondition for wrong purpose, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Fatalf("expected *ErrFailedPrecondition, got %T: %v", err, err)
	}
}
