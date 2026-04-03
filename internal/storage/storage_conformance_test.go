package storage

import (
	"strings"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// testSetup creates a storage instance, a keyring, and returns helpers.
func testSetupStorage(t *testing.T) *Storage {
	t.Helper()
	s := NewStorage()
	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}
	return s
}

func createEncryptDecryptKey(t *testing.T, s *Storage) string {
	t.Helper()
	const keyName = "projects/test/locations/global/keyRings/ring1/cryptoKeys/edkey"
	_, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"edkey",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey (ENCRYPT_DECRYPT) failed: %v", err)
	}
	return keyName
}

func createMACKey(t *testing.T, s *Storage) string {
	t.Helper()
	_, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"mackey",
		kmspb.CryptoKey_MAC,
		&kmspb.CryptoKeyVersionTemplate{
			Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey (MAC) failed: %v", err)
	}
	return "projects/test/locations/global/keyRings/ring1/cryptoKeys/mackey"
}

// TestEncrypt_AAD verifies that encrypt/decrypt round-trips with matching AAD
// and that mismatched AAD causes decryption failure.
func TestEncrypt_AAD(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)

	plaintext := []byte("hello world")
	aad := []byte("my-aad")

	ciphertext, _, err := s.Encrypt(keyName, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt with AAD failed: %v", err)
	}

	// Decrypt with same AAD should succeed
	decrypted, _, err := s.Decrypt(keyName, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt with matching AAD failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Decrypt with different AAD should fail
	_, _, err = s.Decrypt(keyName, ciphertext, []byte("wrong-aad"))
	if err == nil {
		t.Error("Expected error decrypting with wrong AAD, got nil")
	}
}

// TestEncrypt_PurposeCheck verifies that encrypting with a non-ENCRYPT_DECRYPT key returns ErrFailedPrecondition.
func TestEncrypt_PurposeCheck(t *testing.T) {
	s := testSetupStorage(t)
	macKeyName := createMACKey(t, s)

	_, _, err := s.Encrypt(macKeyName, []byte("data"), nil)
	if err == nil {
		t.Fatal("Expected error encrypting with MAC key, got nil")
	}
	var fpErr *ErrFailedPrecondition
	if !asError(err, &fpErr) {
		t.Errorf("Expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestEncrypt_ReturnsVersionName checks that the second return value is a valid version name.
func TestEncrypt_ReturnsVersionName(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)

	_, versionName, err := s.Encrypt(keyName, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.Contains(versionName, "cryptoKeyVersions/") {
		t.Errorf("Expected version name to contain 'cryptoKeyVersions/', got %q", versionName)
	}
}

// TestDecrypt_PurposeCheck verifies that decrypting with a non-ENCRYPT_DECRYPT key returns ErrFailedPrecondition.
func TestDecrypt_PurposeCheck(t *testing.T) {
	s := testSetupStorage(t)
	macKeyName := createMACKey(t, s)

	_, _, err := s.Decrypt(macKeyName, []byte("fakeciphertext"), nil)
	if err == nil {
		t.Fatal("Expected error decrypting with MAC key, got nil")
	}
	var fpErr *ErrFailedPrecondition
	if !asError(err, &fpErr) {
		t.Errorf("Expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestUpdateCryptoKey_Mask verifies that only the fields listed in the mask are updated.
func TestUpdateCryptoKey_Mask(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)

	originalKey, err := s.GetCryptoKey(keyName)
	if err != nil {
		t.Fatalf("GetCryptoKey failed: %v", err)
	}
	originalPurpose := originalKey.Purpose
	originalVersionTemplate := originalKey.VersionTemplate

	// Update only labels
	mask := &fieldmaskpb.FieldMask{Paths: []string{"labels"}}
	updated := &kmspb.CryptoKey{
		Labels:          map[string]string{"env": "test"},
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256},
	}

	result, err := s.UpdateCryptoKey(keyName, updated, mask)
	if err != nil {
		t.Fatalf("UpdateCryptoKey failed: %v", err)
	}

	if result.Labels["env"] != "test" {
		t.Errorf("Expected label env=test, got %v", result.Labels)
	}
	if result.Purpose != originalPurpose {
		t.Errorf("Purpose should not have changed: got %v, want %v", result.Purpose, originalPurpose)
	}
	// VersionTemplate should not have changed (not in mask)
	if result.VersionTemplate != originalVersionTemplate {
		t.Errorf("VersionTemplate should not have changed when not in mask")
	}
}

// TestUpdateCryptoKeyVersion_StateTransition tests valid and invalid state transitions.
func TestUpdateCryptoKeyVersion_StateTransition(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)

	versionName := keyName + "/cryptoKeyVersions/1"
	mask := &fieldmaskpb.FieldMask{Paths: []string{"state"}}

	// ENABLED -> DISABLED: should succeed
	v, err := s.UpdateCryptoKeyVersion(versionName, kmspb.CryptoKeyVersion_DISABLED, mask)
	if err != nil {
		t.Fatalf("ENABLED->DISABLED failed: %v", err)
	}
	if v.State != kmspb.CryptoKeyVersion_DISABLED {
		t.Errorf("Expected DISABLED state, got %v", v.State)
	}

	// DISABLED -> ENABLED: should succeed
	_, err = s.UpdateCryptoKeyVersion(versionName, kmspb.CryptoKeyVersion_ENABLED, mask)
	if err != nil {
		t.Fatalf("DISABLED->ENABLED failed: %v", err)
	}

	// ENABLED -> DESTROY_SCHEDULED: should fail (invalid target)
	_, err = s.UpdateCryptoKeyVersion(versionName, kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, mask)
	if err == nil {
		t.Error("Expected error for ENABLED->DESTROY_SCHEDULED, got nil")
	}
	var fpErr *ErrFailedPrecondition
	if !asError(err, &fpErr) {
		t.Errorf("Expected ErrFailedPrecondition, got %T: %v", err, err)
	}

	// Schedule destruction so we can test DESTROY_SCHEDULED -> ENABLED
	_, err = s.DestroyCryptoKeyVersion(versionName)
	if err != nil {
		t.Fatalf("DestroyCryptoKeyVersion failed: %v", err)
	}

	// DESTROY_SCHEDULED -> ENABLED: should fail (invalid source)
	_, err = s.UpdateCryptoKeyVersion(versionName, kmspb.CryptoKeyVersion_ENABLED, mask)
	if err == nil {
		t.Error("Expected error for DESTROY_SCHEDULED->ENABLED, got nil")
	}
	if !asError(err, &fpErr) {
		t.Errorf("Expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestDestroyCryptoKeyVersion_Idempotent verifies that calling destroy twice returns no error.
func TestDestroyCryptoKeyVersion_Idempotent(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)
	versionName := keyName + "/cryptoKeyVersions/1"

	_, err := s.DestroyCryptoKeyVersion(versionName)
	if err != nil {
		t.Fatalf("First DestroyCryptoKeyVersion failed: %v", err)
	}

	// Second call should also succeed (idempotent)
	_, err = s.DestroyCryptoKeyVersion(versionName)
	if err != nil {
		t.Errorf("Second DestroyCryptoKeyVersion (idempotent) failed: %v", err)
	}
}

// TestDestroyCryptoKeyVersion_DestroyTime verifies that DestroyTime is non-zero on the response.
func TestDestroyCryptoKeyVersion_DestroyTime(t *testing.T) {
	s := testSetupStorage(t)
	keyName := createEncryptDecryptKey(t, s)
	versionName := keyName + "/cryptoKeyVersions/1"

	result, err := s.DestroyCryptoKeyVersion(versionName)
	if err != nil {
		t.Fatalf("DestroyCryptoKeyVersion failed: %v", err)
	}

	if result.DestroyTime == nil || result.DestroyTime.AsTime().IsZero() {
		t.Error("Expected non-zero DestroyTime on DestroyCryptoKeyVersion response")
	}
}

// TestCreateCryptoKey_UnspecifiedPurpose verifies that creating a key with unspecified purpose returns an error.
func TestCreateCryptoKey_UnspecifiedPurpose(t *testing.T) {
	s := testSetupStorage(t)

	_, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"badkey",
		kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED,
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("Expected error for unspecified purpose, got nil")
	}
	var fpErr *ErrFailedPrecondition
	if !asError(err, &fpErr) {
		t.Errorf("Expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestCreateCryptoKeyVersion_AlgorithmOverride verifies that passing a req with a specific
// algorithm overrides the template.
func TestCreateCryptoKeyVersion_AlgorithmOverride(t *testing.T) {
	s := testSetupStorage(t)
	// Create a MAC key with HMAC_SHA256 template
	_, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"mackey2",
		kmspb.CryptoKey_MAC,
		&kmspb.CryptoKeyVersionTemplate{
			Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}
	keyName := "projects/test/locations/global/keyRings/ring1/cryptoKeys/mackey2"

	// Create a new version with HMAC_SHA384 override
	req := &kmspb.CryptoKeyVersion{
		Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA384,
	}
	version, err := s.CreateCryptoKeyVersion(keyName, req)
	if err != nil {
		t.Fatalf("CreateCryptoKeyVersion with algorithm override failed: %v", err)
	}

	if version.Algorithm != kmspb.CryptoKeyVersion_HMAC_SHA384 {
		t.Errorf("Expected algorithm HMAC_SHA384, got %v", version.Algorithm)
	}
}

// asError is a helper that checks if err can be assigned to target (like errors.As but without import).
func asError[T error](err error, target *T) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(T); ok {
		*target = e
		return true
	}
	return false
}
