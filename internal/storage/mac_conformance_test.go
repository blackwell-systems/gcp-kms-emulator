package storage

import (
	"fmt"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

const (
	testProject  = "projects/test"
	testLocation = "locations/global"
	testKeyRing  = "keyRings/test-ring"
)

// setupMACKey creates a keyring and a MAC-purpose crypto key with the given algorithm,
// then directly sets HMACKey on the stored version to the provided key bytes.
// This bypasses generateKeyMaterial so tests don't depend on Agent A's keymaterial changes.
func setupMACKey(t *testing.T, s *Storage, keyID string, alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, rawHMACKey []byte) string {
	t.Helper()

	keyringName := fmt.Sprintf("%s/%s/%s", testProject, testLocation, testKeyRing)
	_, err := s.CreateKeyRing(keyringName)
	if err != nil {
		// keyring may already exist; ignore AlreadyExists
		if _, ok := err.(*ErrAlreadyExists); !ok {
			t.Fatalf("CreateKeyRing failed: %v", err)
		}
	}

	versionTemplate := &kmspb.CryptoKeyVersionTemplate{
		Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256, // use SHA256 so generateKeyMaterial works
	}
	keyName := fmt.Sprintf("%s/cryptoKeys/%s", keyringName, keyID)
	_, err = s.CreateCryptoKey(keyringName, keyID, kmspb.CryptoKey_MAC, versionTemplate, nil)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	// Override algorithm and HMACKey directly on the stored version
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kr := range s.keyrings {
		if ck, ok := kr.CryptoKeys[keyName]; ok {
			for _, v := range ck.Versions {
				v.Algorithm = alg
				v.HMACKey = rawHMACKey
			}
		}
	}

	return keyName
}

// setupNonMACKey creates a keyring and an ENCRYPT_DECRYPT key, then manually
// attaches HMAC key material to its version so MacSign/MacVerify can be called
// (they will fail purpose check, which is what we want to test).
func setupNonMACKey(t *testing.T, s *Storage, keyID string) string {
	t.Helper()

	keyringName := fmt.Sprintf("%s/%s/%s", testProject, testLocation, testKeyRing)
	_, err := s.CreateKeyRing(keyringName)
	if err != nil {
		if _, ok := err.(*ErrAlreadyExists); !ok {
			t.Fatalf("CreateKeyRing failed: %v", err)
		}
	}

	keyName := fmt.Sprintf("%s/cryptoKeys/%s", keyringName, keyID)
	_, err = s.CreateCryptoKey(keyringName, keyID, kmspb.CryptoKey_ENCRYPT_DECRYPT, nil, nil)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	// Manually attach HMAC key material so version lookup doesn't fail before purpose check
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kr := range s.keyrings {
		if ck, ok := kr.CryptoKeys[keyName]; ok {
			for _, v := range ck.Versions {
				v.HMACKey = make([]byte, 32)
			}
		}
	}

	return keyName
}

// primaryVersionName returns the primary version name for the given key.
func primaryVersionName(t *testing.T, s *Storage, keyName string) string {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, kr := range s.keyrings {
		if ck, ok := kr.CryptoKeys[keyName]; ok {
			return ck.PrimaryVersion
		}
	}
	t.Fatalf("key not found: %s", keyName)
	return ""
}

// TestMacSign_PurposeCheck verifies that MacSign returns ErrFailedPrecondition
// when the key's purpose is not MAC.
func TestMacSign_PurposeCheck(t *testing.T) {
	s := NewStorage()
	keyName := setupNonMACKey(t, s, "enc-key")
	versionName := primaryVersionName(t, s, keyName)

	_, err := s.MacSign(versionName, []byte("hello"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Errorf("expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestMacVerify_PurposeCheck verifies that MacVerify returns ErrFailedPrecondition
// when the key's purpose is not MAC.
func TestMacVerify_PurposeCheck(t *testing.T) {
	s := NewStorage()
	keyName := setupNonMACKey(t, s, "enc-key-verify")
	versionName := primaryVersionName(t, s, keyName)

	_, err := s.MacVerify(versionName, []byte("hello"), []byte("fakemac"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Errorf("expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}

// TestMacSign_SHA1Algorithm verifies that HMAC_SHA1 produces a 20-byte tag.
func TestMacSign_SHA1Algorithm(t *testing.T) {
	s := NewStorage()
	// 20-byte raw key for SHA-1 HMAC
	rawKey := make([]byte, 20)
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	keyName := setupMACKey(t, s, "mac-sha1", kmspb.CryptoKeyVersion_HMAC_SHA1, rawKey)
	versionName := primaryVersionName(t, s, keyName)

	tag, err := s.MacSign(versionName, []byte("test data"))
	if err != nil {
		t.Fatalf("MacSign failed: %v", err)
	}
	if len(tag) != 20 {
		t.Errorf("expected 20-byte HMAC-SHA1 tag, got %d bytes", len(tag))
	}

	// Round-trip: MacVerify should return true
	ok, err := s.MacVerify(versionName, []byte("test data"), tag)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// TestMacSign_SHA384Algorithm verifies that HMAC_SHA384 produces a 48-byte tag.
func TestMacSign_SHA384Algorithm(t *testing.T) {
	s := NewStorage()
	rawKey := make([]byte, 48)
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	keyName := setupMACKey(t, s, "mac-sha384", kmspb.CryptoKeyVersion_HMAC_SHA384, rawKey)
	versionName := primaryVersionName(t, s, keyName)

	tag, err := s.MacSign(versionName, []byte("test data"))
	if err != nil {
		t.Fatalf("MacSign failed: %v", err)
	}
	if len(tag) != 48 {
		t.Errorf("expected 48-byte HMAC-SHA384 tag, got %d bytes", len(tag))
	}

	ok, err := s.MacVerify(versionName, []byte("test data"), tag)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// TestMacSign_SHA512Algorithm verifies that HMAC_SHA512 produces a 64-byte tag.
func TestMacSign_SHA512Algorithm(t *testing.T) {
	s := NewStorage()
	rawKey := make([]byte, 64)
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	keyName := setupMACKey(t, s, "mac-sha512", kmspb.CryptoKeyVersion_HMAC_SHA512, rawKey)
	versionName := primaryVersionName(t, s, keyName)

	tag, err := s.MacSign(versionName, []byte("test data"))
	if err != nil {
		t.Fatalf("MacSign failed: %v", err)
	}
	if len(tag) != 64 {
		t.Errorf("expected 64-byte HMAC-SHA512 tag, got %d bytes", len(tag))
	}

	ok, err := s.MacVerify(versionName, []byte("test data"), tag)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// TestImportCryptoKeyVersion_UnspecifiedAlgorithm verifies that ImportCryptoKeyVersion
// returns an error when algorithm is CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED.
func TestImportCryptoKeyVersion_UnspecifiedAlgorithm(t *testing.T) {
	s := NewStorage()

	keyringName := fmt.Sprintf("%s/%s/%s", testProject, testLocation, testKeyRing)
	_, err := s.CreateKeyRing(keyringName)
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	keyName := fmt.Sprintf("%s/cryptoKeys/import-key", keyringName)
	_, err = s.CreateCryptoKey(keyringName, "import-key", kmspb.CryptoKey_ENCRYPT_DECRYPT, nil, nil)
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	importJobID := "import-job-1"
	_, err = s.CreateImportJob(keyringName, importJobID,
		int32(kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256),
		int32(kmspb.ProtectionLevel_SOFTWARE))
	if err != nil {
		t.Fatalf("CreateImportJob failed: %v", err)
	}
	importJobName := fmt.Sprintf("%s/importJobs/%s", keyringName, importJobID)

	_, err = s.ImportCryptoKeyVersion(
		keyName,
		int32(kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED),
		importJobName,
		[]byte("some-wrapped-key"),
	)
	if err == nil {
		t.Fatal("expected error for UNSPECIFIED algorithm, got nil")
	}
	if _, ok := err.(*ErrFailedPrecondition); !ok {
		t.Errorf("expected ErrFailedPrecondition, got %T: %v", err, err)
	}
}
