package storage

import (
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

func TestCreateKeyRing(t *testing.T) {
	s := NewStorage()

	keyRing, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	if keyRing.Name != "projects/test/locations/global/keyRings/ring1" {
		t.Errorf("Expected name 'projects/test/locations/global/keyRings/ring1', got '%s'", keyRing.Name)
	}

	if keyRing.CreateTime == nil {
		t.Error("CreateTime should not be nil")
	}
}

func TestCreateKeyRingDuplicate(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("First CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err == nil {
		t.Error("Expected error for duplicate keyring, got nil")
	}
}

func TestGetKeyRing(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	keyRing, err := s.GetKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("GetKeyRing failed: %v", err)
	}

	if keyRing.Name != "projects/test/locations/global/keyRings/ring1" {
		t.Errorf("Expected name 'projects/test/locations/global/keyRings/ring1', got '%s'", keyRing.Name)
	}
}

func TestGetKeyRingNotFound(t *testing.T) {
	s := NewStorage()

	_, err := s.GetKeyRing("projects/test/locations/global/keyRings/nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent keyring, got nil")
	}
}

func TestListKeyRings(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing ring1 failed: %v", err)
	}

	_, err = s.CreateKeyRing("projects/test/locations/global/keyRings/ring2")
	if err != nil {
		t.Fatalf("CreateKeyRing ring2 failed: %v", err)
	}

	keyRings, err := s.ListKeyRings("projects/test/locations/global")
	if err != nil {
		t.Fatalf("ListKeyRings failed: %v", err)
	}

	if len(keyRings) != 2 {
		t.Errorf("Expected 2 keyrings, got %d", len(keyRings))
	}
}

func TestCreateCryptoKey(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	cryptoKey, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	if cryptoKey.Name != "projects/test/locations/global/keyRings/ring1/cryptoKeys/key1" {
		t.Errorf("Unexpected crypto key name: %s", cryptoKey.Name)
	}

	if cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		t.Errorf("Expected purpose ENCRYPT_DECRYPT, got %v", cryptoKey.Purpose)
	}

	if cryptoKey.Primary == nil {
		t.Error("Primary version should not be nil")
	}

	if cryptoKey.Primary.Name != "projects/test/locations/global/keyRings/ring1/cryptoKeys/key1/cryptoKeyVersions/1" {
		t.Errorf("Unexpected primary version name: %s", cryptoKey.Primary.Name)
	}

	if cryptoKey.Primary.State != kmspb.CryptoKeyVersion_ENABLED {
		t.Errorf("Expected primary state ENABLED, got %v", cryptoKey.Primary.State)
	}
}

func TestCreateCryptoKeyInvalidKeyRing(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/nonexistent",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err == nil {
		t.Error("Expected error for nonexistent keyring, got nil")
	}
}

func TestGetCryptoKey(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	cryptoKey, err := s.GetCryptoKey("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1")
	if err != nil {
		t.Fatalf("GetCryptoKey failed: %v", err)
	}

	if cryptoKey.Name != "projects/test/locations/global/keyRings/ring1/cryptoKeys/key1" {
		t.Errorf("Unexpected crypto key name: %s", cryptoKey.Name)
	}
}

func TestListCryptoKeys(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey key1 failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key2",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey key2 failed: %v", err)
	}

	cryptoKeys, err := s.ListCryptoKeys("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("ListCryptoKeys failed: %v", err)
	}

	if len(cryptoKeys) != 2 {
		t.Errorf("Expected 2 crypto keys, got %d", len(cryptoKeys))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	plaintext := []byte("Hello, KMS!")
	ciphertext, err := s.Encrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	decrypted, err := s.Decrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Expected plaintext '%s', got '%s'", string(plaintext), string(decrypted))
	}
}

func TestCreateCryptoKeyVersion(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	version, err := s.CreateCryptoKeyVersion("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1")
	if err != nil {
		t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
	}

	if version.Name != "projects/test/locations/global/keyRings/ring1/cryptoKeys/key1/cryptoKeyVersions/2" {
		t.Errorf("Expected version name ending in /2, got %s", version.Name)
	}

	if version.State != kmspb.CryptoKeyVersion_ENABLED {
		t.Errorf("Expected state ENABLED, got %v", version.State)
	}
}

func TestUpdateCryptoKeyPrimaryVersion(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	_, err = s.CreateCryptoKeyVersion("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1")
	if err != nil {
		t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
	}

	cryptoKey, err := s.UpdateCryptoKeyPrimaryVersion(
		"projects/test/locations/global/keyRings/ring1/cryptoKeys/key1",
		"projects/test/locations/global/keyRings/ring1/cryptoKeys/key1/cryptoKeyVersions/2",
	)
	if err != nil {
		t.Fatalf("UpdateCryptoKeyPrimaryVersion failed: %v", err)
	}

	if cryptoKey.Primary.Name != "projects/test/locations/global/keyRings/ring1/cryptoKeys/key1/cryptoKeyVersions/2" {
		t.Errorf("Expected primary version /2, got %s", cryptoKey.Primary.Name)
	}
}

func TestDecryptWithMultipleVersions(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	plaintext := []byte("Test versioning")
	ciphertext1, err := s.Encrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt with v1 failed: %v", err)
	}

	_, err = s.CreateCryptoKeyVersion("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1")
	if err != nil {
		t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
	}

	_, err = s.UpdateCryptoKeyPrimaryVersion(
		"projects/test/locations/global/keyRings/ring1/cryptoKeys/key1",
		"projects/test/locations/global/keyRings/ring1/cryptoKeys/key1/cryptoKeyVersions/2",
	)
	if err != nil {
		t.Fatalf("UpdateCryptoKeyPrimaryVersion failed: %v", err)
	}

	ciphertext2, err := s.Encrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt with v2 failed: %v", err)
	}

	decrypted1, err := s.Decrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", ciphertext1)
	if err != nil {
		t.Fatalf("Decrypt v1 ciphertext failed: %v", err)
	}

	if string(decrypted1) != string(plaintext) {
		t.Errorf("Expected plaintext '%s', got '%s'", string(plaintext), string(decrypted1))
	}

	decrypted2, err := s.Decrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt v2 ciphertext failed: %v", err)
	}

	if string(decrypted2) != string(plaintext) {
		t.Errorf("Expected plaintext '%s', got '%s'", string(plaintext), string(decrypted2))
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := NewStorage()

	_, err := s.CreateKeyRing("projects/test/locations/global/keyRings/ring1")
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	_, err = s.CreateCryptoKey(
		"projects/test/locations/global/keyRings/ring1",
		"key1",
		kmspb.CryptoKey_ENCRYPT_DECRYPT,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			plaintext := []byte("Concurrent test")
			ciphertext, err := s.Encrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", plaintext)
			if err != nil {
				t.Errorf("Concurrent Encrypt failed: %v", err)
			}
			_, err = s.Decrypt("projects/test/locations/global/keyRings/ring1/cryptoKeys/key1", ciphertext)
			if err != nil {
				t.Errorf("Concurrent Decrypt failed: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
